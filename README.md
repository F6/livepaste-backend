# livepaste backend

Run the FastAPI backend (development):

1. Create a virtualenv and install dependencies:

```powershell
python -m venv .venv; .\.venv\\Scripts\\Activate.ps1; pip install -r requirements.txt
```

2. Start the server:

```powershell
python -m backend.app.main
```

The server listens on port 8000 by default. WebSocket endpoint is `/ws/{passphrase}`.
