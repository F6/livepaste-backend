import os
from typing import Optional


class FileStorage:
    def __init__(self, base_dir: str):
        self.base_dir = base_dir
        os.makedirs(self.base_dir, exist_ok=True)

    def save_for_session(self, passphrase: str, name: str, data: bytes) -> str:
        # ensure session directory exists
        safe_dir = os.path.join(self.base_dir, passphrase)
        os.makedirs(safe_dir, exist_ok=True)
        path = os.path.join(safe_dir, name)
        with open(path, "wb") as f:
            f.write(data)
        # return relative path under base_dir for serving
        # callers should construct a URL to the static mount (e.g. /static/uploads/...)
        return path

    def list_for_session(self, passphrase: str):
        safe_dir = os.path.join(self.base_dir, passphrase)
        if not os.path.isdir(safe_dir):
            return []
        return [f for f in os.listdir(safe_dir) if os.path.isfile(os.path.join(safe_dir, f))]

    def save_bytes(self, name: str, data: bytes) -> str:
        path = os.path.join(self.base_dir, name)
        with open(path, "wb") as f:
            f.write(data)
        return path

    def get_path(self, name: str) -> Optional[str]:
        path = os.path.join(self.base_dir, name)
        if os.path.exists(path):
            return path
        return None

    def delete_session_files(self, passphrase: str) -> bool:
        """Delete all files for a session."""
        safe_dir = os.path.join(self.base_dir, passphrase)
        if not os.path.isdir(safe_dir):
            return False
        try:
            import shutil
            shutil.rmtree(safe_dir)
            return True
        except Exception:
            return False
