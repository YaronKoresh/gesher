import json
import unittest
from unittest.mock import MagicMock, patch

import requests

from gesher import client
from gesher.security import SecurityLayer


class TestClient(unittest.TestCase):
    def setUp(self):
        self.security = SecurityLayer("test-secret")
        client.SECURITY = self.security

    @patch("gesher.client.requests.post")
    @patch("gesher.client.requests.request")
    def test_handle_task_success(self, mock_request, mock_post):
        task_data = {"id": "123", "method": "POST", "url": "/submit", "headers": {"Content-Type": "application/json"}}
        local_target = "http://localhost:8080"
        gateway_url = "http://gateway.com"

        encrypted_payload = self.security.encrypt(json.dumps(task_data))

        mock_local_resp = MagicMock()
        mock_local_resp.status_code = 201
        mock_local_resp.headers = {"X-Custom": "Value"}
        mock_local_resp.content = b"Created"
        mock_request.return_value = mock_local_resp

        client.handle_task(encrypted_payload, local_target, gateway_url)

        mock_request.assert_called_with(
            method="POST",
            url="http://localhost:8080/submit",
            headers=task_data["headers"],
            data=None,
            allow_redirects=False,
        )

        mock_post.assert_called_once()
        call_args = mock_post.call_args
        self.assertEqual(call_args[0][0], "http://gateway.com/_tunnel_response")

    @patch("gesher.client.requests.post")
    @patch("gesher.client.requests.request")
    def test_handle_task_local_service_error(self, mock_request, mock_post):
        task_data = {"id": "999", "method": "GET", "url": "/"}
        encrypted_payload = self.security.encrypt(json.dumps(task_data))

        mock_request.side_effect = requests.exceptions.ConnectionError

        client.handle_task(encrypted_payload, "http://localhost:8080", "http://gateway")

        # When local service fails, no response is posted back
        mock_post.assert_not_called()

    @patch("gesher.client.requests.post")
    def test_start_connector_auth_failure(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_post.return_value.__enter__.return_value = mock_resp

        client.start_connector("http://gateway", "bad-secret", "http://local", "PIN", 9999)

        mock_post.assert_called_once()

    def test_handle_task_invalid_encrypted_payload(self):
        """handle_task should gracefully handle corrupted payloads."""
        # Should not raise, just log the error
        client.handle_task("invalid-encrypted-data", "http://localhost:8080", "http://gateway")

    def test_handle_task_system_update(self):
        """handle_task should handle system_update events without forwarding."""
        system_msg = {"type": "system_update", "event": "client_list", "clients": ["id1", "id2"]}
        encrypted = self.security.encrypt(json.dumps(system_msg))

        with patch("gesher.client.requests.request") as mock_request:
            client.handle_task(encrypted, "http://localhost:8080", "http://gateway")
            mock_request.assert_not_called()
