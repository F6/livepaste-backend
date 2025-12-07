import json
import os
import bcrypt
from typing import Optional


class UserStore:
    """Manage user credentials with hashed passwords."""

    def __init__(self, data_file: str):
        self.data_file = data_file
        self.users = self._load()

    def _load(self) -> dict:
        """Load users from JSON file."""
        if not os.path.exists(self.data_file):
            return {}
        try:
            with open(self.data_file, 'r') as f:
                return json.load(f)
        except Exception:
            return {}

    def save(self):
        """Save users to JSON file."""
        with open(self.data_file, 'w') as f:
            json.dump(self.users, f, indent=2)

    def add_user(self, username: str, password: str) -> bool:
        """Add a new user with hashed password."""
        if username in self.users:
            return False
        # Hash password with bcrypt
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        self.users[username] = {'password_hash': hashed.decode('utf-8')}
        self.save()
        return True

    def verify_user(self, username: str, password: str) -> bool:
        """Verify username and password."""
        if username not in self.users:
            return False
        user = self.users[username]
        try:
            stored_hash = user['password_hash'].encode('utf-8')
            return bcrypt.checkpw(password.encode('utf-8'), stored_hash)
        except Exception:
            return False

    def user_exists(self, username: str) -> bool:
        """Check if user exists."""
        return username in self.users
