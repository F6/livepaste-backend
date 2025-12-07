import asyncio
import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from typing import Dict
import os
import time
import secrets
import jwt
from datetime import datetime, timedelta
from dotenv import load_dotenv

from .models import SessionStore
from .storage import FileStorage
from .auth import UserStore
from fastapi import UploadFile, File
from fastapi.responses import StreamingResponse
import io
import zipfile
import base64

load_dotenv()


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_FILE = os.path.join(ROOT, "sessions.json")
USERS_FILE = os.path.join(ROOT, "users.json")

# Security configuration
JWT_SECRET = os.getenv('JWT_SECRET', 'change-me-in-production-with-strong-secret')
JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION_HOURS = int(os.getenv('JWT_EXPIRATION_HOURS', '24'))

app = FastAPI(title="livepaste - backend")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# mount a simple static folder so frontend can be served if placed here
static_dir = os.path.join(ROOT, "static")
os.makedirs(static_dir, exist_ok=True)
app.mount("/static", StaticFiles(directory=static_dir), name="static")

uploads_dir = os.path.join(static_dir, "uploads")
os.makedirs(uploads_dir, exist_ok=True)
storage = FileStorage(uploads_dir)

store = SessionStore(DATA_FILE)
user_store = UserStore(USERS_FILE)

# websocket connections grouped by passphrase
active_connections: Dict[str, Dict[WebSocket, None]] = {}
active_lock = asyncio.Lock()


def verify_token(authorization: str = Header(None)) -> str:
    """Verify JWT token from Authorization header and return user_id."""
    if authorization is None:
        raise HTTPException(status_code=401, detail="missing authorization")
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise HTTPException(status_code=401, detail="invalid authorization header")
    token = parts[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get('sub')
        if not user_id:
            raise HTTPException(status_code=401, detail="invalid token payload")
        return user_id
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="invalid token")


def create_access_token(username: str) -> str:
    """Create a new JWT token with expiration."""
    expire = datetime.utcnow() + timedelta(hours=JWT_EXPIRATION_HOURS)
    payload = {'sub': username, 'exp': expire}
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


@app.post("/api/login")
async def login(username: str, password: str):
    """Authenticate user with username and password, return JWT token."""
    if not user_store.verify_user(username, password):
        raise HTTPException(status_code=401, detail="invalid username or password")
    access_token = create_access_token(username)
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "expires_in": JWT_EXPIRATION_HOURS * 3600,
        "username": username
    }


@app.post("/api/sessions")
def create_session(passphrase: str = None, user_id: str = Depends(verify_token)):
    if not passphrase:
        # generate a random passphrase
        passphrase = secrets.token_hex(8)
    try:
        s = store.create_session(passphrase, owner=user_id)
        store.save()
        return {"passphrase": s.passphrase}
    except ValueError:
        raise HTTPException(status_code=400, detail="session exists")


@app.post("/api/sessions/{passphrase}/join")
def join_session(passphrase: str):
    s = store.get(passphrase)
    if not s or s.ended:
        raise HTTPException(status_code=404, detail="session not found")
    return {"passphrase": s.passphrase, "content": s.content, "files": s.files}


@app.post("/api/sessions/{passphrase}/upload")
async def upload_file(passphrase: str, file: UploadFile = File(...)):
    s = store.get(passphrase)
    if not s or s.ended:
        raise HTTPException(status_code=404, detail="session not found")
    content = await file.read()
    # save to uploads/<passphrase>/<filename>
    saved_path = storage.save_for_session(passphrase, file.filename, content)
    # construct url relative to static mount
    url = f"/static/uploads/{passphrase}/{file.filename}"
    meta = {"filename": file.filename, "url": url, "size": len(content), "content_type": file.content_type, "uploaded_at": time.time()}
    s.files.append(meta)
    s.last_active = time.time()
    store.save()
    # broadcast file event
    asyncio.create_task(broadcast(passphrase, {"type": "file", "filename": file.filename, "url": url, "size": len(content), "content_type": file.content_type}))
    return meta


@app.get("/api/sessions/{passphrase}/files")
def list_files(passphrase: str):
    s = store.get(passphrase)
    if not s or s.ended:
        raise HTTPException(status_code=404, detail="session not found")
    return {"files": s.files}


@app.get("/api/sessions/{passphrase}/files/download")
def download_files(passphrase: str, files: str = None):
    # files parameter is comma separated list of filenames; if empty, download all
    s = store.get(passphrase)
    if not s or s.ended:
        raise HTTPException(status_code=404, detail="session not found")
    requested = None
    if files:
        requested = [f for f in files.split(',') if f]
    else:
        requested = [f['filename'] for f in s.files]
    # create zip in memory
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as z:
        for name in requested:
            path = os.path.join(uploads_dir, passphrase, name)
            if os.path.exists(path):
                z.write(path, arcname=name)
    buf.seek(0)
    headers = {"Content-Disposition": f"attachment; filename=files_{passphrase}.zip"}
    return StreamingResponse(buf, media_type="application/zip", headers=headers)


@app.get("/api/sessions/{passphrase}")
def get_session(passphrase: str):
    s = store.get(passphrase)
    if not s or s.ended:
        raise HTTPException(status_code=404, detail="session not found")
    return s.to_dict()


@app.post("/api/sessions/{passphrase}/end")
async def end_session(passphrase: str, user_id: str = Depends(verify_token)):
    s = store.get(passphrase)
    if not s:
        raise HTTPException(status_code=404, detail="session not found")
    if s.owner != user_id:
        raise HTTPException(status_code=403, detail="only owner can end session")
    store.end_session(passphrase)
    # notify websockets
    await broadcast(passphrase, {"type": "session_ended"})
    # cleanup temporary files
    storage.delete_session_files(passphrase)
    store.save()
    return {"status": "ended"}


@app.websocket("/ws/{passphrase}")
async def websocket_endpoint(websocket: WebSocket, passphrase: str):
    await websocket.accept()
    async with active_lock:
        conns = active_connections.setdefault(passphrase, {})
        conns[websocket] = None
    # increment connected count
    s = store.get(passphrase)
    if s:
        s.connected += 1
        s.last_active = time.time()
    try:
        while True:
            data = await websocket.receive_text()
            # expect simple JSON messages
            try:
                import json

                msg = json.loads(data)
            except Exception:
                msg = {"type": "raw", "data": data}

            # handle clipboard updates
            if msg.get("type") == "update":
                content = msg.get("content", "")
                store.update_content(passphrase, content)
                store.save()
                await broadcast(passphrase, {"type": "update", "content": content})
            elif msg.get("type") == "ping":
                await websocket.send_text('{"type":"pong"}')
            elif msg.get("type") in ("image", "file"):
                # expect data URL or base64 payload in msg.data
                data = msg.get("data")
                filename = msg.get("filename") or ("pasted-image" if msg.get("type") == "image" else "file")
                content_type = None
                blob = None
                try:
                    if isinstance(data, str) and data.startswith("data:"):
                        # data:<mime>;base64,<payload>
                        header, b64 = data.split(',', 1)
                        # header like data:image/png;base64
                        if ';' in header:
                            content_type = header.split(';', 1)[0].split(':', 1)[1]
                        else:
                            content_type = header.split(':', 1)[1]
                        blob = base64.b64decode(b64)
                    elif isinstance(data, str):
                        # treat as raw base64
                        blob = base64.b64decode(data)
                    else:
                        # unknown format
                        blob = None
                except Exception:
                    blob = None

                if blob is not None:
                    # save file
                    # sanitize filename could be improved
                    saved_path = storage.save_for_session(passphrase, filename, blob)
                    url = f"/static/uploads/{passphrase}/{filename}"
                    meta = {"filename": filename, "url": url, "size": len(blob), "content_type": content_type or "application/octet-stream", "uploaded_at": time.time()}
                    s = store.get(passphrase)
                    if s:
                        s.files.append(meta)
                        s.last_active = time.time()
                        store.save()
                    # broadcast file event (image clients can treat by content_type)
                    await broadcast(passphrase, {"type": msg.get("type"), "filename": filename, "url": url, "size": len(blob), "content_type": content_type})
                else:
                    # just echo if we couldn't process
                    await broadcast(passphrase, msg)
            else:
                # echo other messages to group
                await broadcast(passphrase, msg)
    except WebSocketDisconnect:
        pass
    finally:
        # cleanup
        async with active_lock:
            conns = active_connections.get(passphrase, {})
            conns.pop(websocket, None)
            if not conns:
                active_connections.pop(passphrase, None)
        s = store.get(passphrase)
        if s:
            s.connected = max(0, s.connected - 1)
            s.last_active = time.time()


async def broadcast(passphrase: str, message: dict):
    import json

    text = json.dumps(message)
    async with active_lock:
        conns = list(active_connections.get(passphrase, {}).keys())
    for ws in conns:
        try:
            await ws.send_text(text)
        except Exception:
            # ignore send errors; cleanup will happen on disconnect
            pass


async def periodic_save_and_gc():
    while True:
        await asyncio.sleep(30)
        try:
            store.save()
            store.garbage_collect()
        except Exception:
            pass


@app.on_event("startup")
async def startup_event():
    # start background task
    asyncio.create_task(periodic_save_and_gc())


if __name__ == "__main__":
    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=8000, log_level="info")
