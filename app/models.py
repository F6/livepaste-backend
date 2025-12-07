import time
import json
import threading
import os
from typing import Dict, Optional


class Session:
    def __init__(self, passphrase: str, owner: Optional[str] = None):
        self.passphrase = passphrase
        self.owner = owner
        self.content = ""  # current clipboard content
        self.metadata = {}
        self.files = []  # list of file metadata dicts: {filename, url, size, content_type, uploaded_at}
        self.created_at = time.time()
        self.last_active = self.created_at
        self.connected = 0
        self.ended = False

    def to_dict(self):
        return {
            "passphrase": self.passphrase,
            "owner": self.owner,
            "content": self.content,
            "metadata": self.metadata,
            "files": self.files,
            "created_at": self.created_at,
            "last_active": self.last_active,
            "connected": self.connected,
            "ended": self.ended,
        }

    @staticmethod
    def from_dict(d):
        s = Session(d["passphrase"], d.get("owner"))
        s.content = d.get("content", "")
        s.metadata = d.get("metadata", {})
        s.files = d.get("files", [])
        s.created_at = d.get("created_at", time.time())
        s.last_active = d.get("last_active", s.created_at)
        s.connected = d.get("connected", 0)
        s.ended = d.get("ended", False)
        return s


class SessionStore:
    def __init__(self, data_file: str):
        self.data_file = data_file
        self.sessions: Dict[str, Session] = {}
        self.lock = threading.Lock()
        self._load()

    def _load(self):
        if os.path.exists(self.data_file):
            try:
                with open(self.data_file, "r", encoding="utf-8") as f:
                    raw = json.load(f)
                for k, v in raw.items():
                    self.sessions[k] = Session.from_dict(v)
            except Exception:
                # ignore corrupt file
                self.sessions = {}

    def save(self):
        tmp = self.data_file + ".tmp"
        with self.lock:
            data = {k: s.to_dict() for k, s in self.sessions.items()}
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp, self.data_file)

    def create_session(self, passphrase: str, owner: Optional[str] = None) -> Session:
        with self.lock:
            if passphrase in self.sessions and not self.sessions[passphrase].ended:
                raise ValueError("session exists")
            s = Session(passphrase, owner)
            self.sessions[passphrase] = s
            return s

    def get(self, passphrase: str) -> Optional[Session]:
        with self.lock:
            return self.sessions.get(passphrase)

    def update_content(self, passphrase: str, content: str):
        with self.lock:
            s = self.sessions.get(passphrase)
            if not s:
                raise KeyError("session not found")
            s.content = content
            s.last_active = time.time()
            return s

    def end_session(self, passphrase: str):
        with self.lock:
            s = self.sessions.get(passphrase)
            if s:
                s.ended = True
                s.content = ""

    def garbage_collect(self, expire_seconds: int = 7 * 24 * 3600):
        now = time.time()
        to_delete = []
        with self.lock:
            for k, s in list(self.sessions.items()):
                if s.ended:
                    to_delete.append(k)
                else:
                    if (s.connected == 0) and (now - s.last_active > expire_seconds):
                        to_delete.append(k)
            for k in to_delete:
                del self.sessions[k]
