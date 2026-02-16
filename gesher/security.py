import base64
import hashlib
import hmac
import time

from cryptography.fernet import Fernet


class SecurityLayer:
    def __init__(self, secret: str):
        self.secret = secret
        # Derive a 32-byte URL-safe base64 key from the shared secret for AES
        key = hashlib.sha256(secret.encode()).digest()
        self.fernet = Fernet(base64.urlsafe_b64encode(key))

    def encrypt(self, data: str) -> str:
        """Encrypts a string payload into a fernet token (The 'Gibberish')."""
        return self.fernet.encrypt(data.encode()).decode()

    def decrypt(self, token: str) -> str:
        """Decrypts a fernet token back to string."""
        try:
            return self.fernet.decrypt(token.encode()).decode()
        except Exception as exc:
            raise ValueError("Decryption Failed: Invalid Key or Corrupted Data") from exc

    def get_auth_header(self) -> str:
        """Generates a time-based HMAC signature for the Authorization header."""
        timestamp = str(int(time.time()))
        signature = hmac.new(self.secret.encode(), timestamp.encode(), hashlib.sha256).hexdigest()
        return f"{timestamp}:{signature}"

    def verify_signature(self, auth_header: str, window_seconds: int = 30) -> bool:
        """
        Verifies the time-based HMAC signature.
        Returns (True, signature) if valid, (False, None) if invalid.
        """
        if not auth_header or ":" not in auth_header:
            return False, None

        try:
            timestamp_str, signature = auth_header.split(":", 1)
            timestamp = int(timestamp_str)
            current_time = int(time.time())

            # 1. Check Time Window
            if abs(current_time - timestamp) > window_seconds:
                return False, None

            # 2. Verify Cryptographic Match
            expected_sig = hmac.new(self.secret.encode(), timestamp_str.encode(), hashlib.sha256).hexdigest()

            is_valid = hmac.compare_digest(expected_sig, signature)
            return is_valid, signature
        except Exception:
            return False, None
