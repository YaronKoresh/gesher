import time
import unittest
from unittest.mock import patch

from gesher.security import SecurityLayer


class TestSecurityLayer(unittest.TestCase):
    def setUp(self):
        self.security = SecurityLayer("test-secret")

    def test_encrypt_decrypt_roundtrip(self):
        original = "Hello, Gesher!"
        encrypted = self.security.encrypt(original)
        self.assertNotEqual(encrypted, original)
        decrypted = self.security.decrypt(encrypted)
        self.assertEqual(decrypted, original)

    def test_decrypt_invalid_token_raises(self):
        with self.assertRaises(ValueError):
            self.security.decrypt("invalid-token-data")

    def test_decrypt_wrong_key_raises(self):
        other = SecurityLayer("different-secret")
        encrypted = self.security.encrypt("secret data")
        with self.assertRaises(ValueError):
            other.decrypt(encrypted)

    def test_get_auth_header_format(self):
        header = self.security.get_auth_header()
        self.assertIn(":", header)
        parts = header.split(":", 1)
        self.assertEqual(len(parts), 2)
        # First part should be a unix timestamp
        int(parts[0])

    def test_verify_signature_valid(self):
        header = self.security.get_auth_header()
        is_valid, signature = self.security.verify_signature(header)
        self.assertTrue(is_valid)
        self.assertIsNotNone(signature)

    def test_verify_signature_invalid_secret(self):
        other = SecurityLayer("wrong-secret")
        header = other.get_auth_header()
        is_valid, signature = self.security.verify_signature(header)
        self.assertFalse(is_valid)

    def test_verify_signature_expired(self):
        header = self.security.get_auth_header()
        with patch("gesher.security.time.time", return_value=time.time() + 60):
            is_valid, signature = self.security.verify_signature(header)
        self.assertFalse(is_valid)

    def test_verify_signature_empty(self):
        is_valid, signature = self.security.verify_signature("")
        self.assertFalse(is_valid)
        self.assertIsNone(signature)

    def test_verify_signature_none(self):
        is_valid, signature = self.security.verify_signature(None)
        self.assertFalse(is_valid)
        self.assertIsNone(signature)

    def test_verify_signature_no_colon(self):
        is_valid, signature = self.security.verify_signature("no-colon-here")
        self.assertFalse(is_valid)
        self.assertIsNone(signature)

    def test_encrypt_json_roundtrip(self):
        import json

        data = {"id": "123", "method": "GET", "url": "/api/test"}
        encrypted = self.security.encrypt(json.dumps(data))
        decrypted = json.loads(self.security.decrypt(encrypted))
        self.assertEqual(decrypted, data)
