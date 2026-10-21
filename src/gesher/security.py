import base64
import hashlib
import hmac
import secrets
import time

from cryptography.fernet import Fernet

SIGNATURE_WINDOW_SECONDS = 30


class SecurityLayer:
    def __init__(self, secret: str):
        self.secret = secret

        key = hashlib.sha256(secret.encode()).digest()
        self.fernet = Fernet(base64.urlsafe_b64encode(key))

    def encrypt(self, data: str) -> str:
        return self.fernet.encrypt(data.encode()).decode()

    def decrypt(self, token: str) -> str:
        try:
            return self.fernet.decrypt(token.encode()).decode()
        except Exception as exc:
            raise ValueError(
                "Decryption Failed: Invalid Key or Corrupted Data"
            ) from exc

    def get_auth_header(self) -> str:
        timestamp = str(int(time.time()))
        nonce = secrets.token_hex(8)
        signature = hmac.new(
            self.secret.encode(),
            f"{timestamp}.{nonce}".encode(),
            hashlib.sha256,
        ).hexdigest()
        return f"{timestamp}:{nonce}.{signature}"

    def verify_signature(
        self, auth_header: str, window_seconds: int = SIGNATURE_WINDOW_SECONDS
    ) -> bool:
        if not auth_header or ":" not in auth_header:
            return False, None

        try:
            timestamp_str, signature = auth_header.split(":", 1)
            timestamp = int(timestamp_str)
            current_time = int(time.time())

            if abs(current_time - timestamp) > window_seconds:
                return False, None

            nonce, dot, mac = signature.rpartition(".")
            if dot:
                if not nonce or len(nonce) > 64:
                    return False, None
                signed = f"{timestamp_str}.{nonce}"
            else:
                signed = timestamp_str

            expected_sig = hmac.new(
                self.secret.encode(), signed.encode(), hashlib.sha256
            ).hexdigest()

            is_valid = hmac.compare_digest(expected_sig, mac)
            return is_valid, signature
        except Exception:
            return False, None
