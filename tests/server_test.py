import base64
import json
import queue
import threading
import unittest
from unittest.mock import MagicMock, patch

from gesher import server
from gesher.security import SecurityLayer


class TestServer(unittest.TestCase):
    def setUp(self):
        self.security = SecurityLayer("test-secret")
        server.SECURITY = self.security
        server.GATEKEEPER_PIN = "TESTPIN"
        server.CLIENTS = {}
        server.PENDING_RESPONSES = {}
        server.NEXT_CLIENT_INDEX = 0
        server.SEEN_SIGNATURES = {}
        server.IP_REQUEST_COUNTS.clear()
        server.AUTH_FAILURES.clear()

    def create_mock_handler(self):
        handler = server.BridgeRequestHandler.__new__(
            server.BridgeRequestHandler
        )
        handler.request = MagicMock()
        handler.client_address = ("127.0.0.1", 5000)
        handler.server = MagicMock()
        handler.headers = MagicMock()
        handler.rfile = MagicMock()
        handler.wfile = MagicMock()
        handler.command = "GET"
        handler.path = "/"
        handler.request_version = "HTTP/1.1"
        handler.requestline = "GET / HTTP/1.1"

        handler.send_response = MagicMock()
        handler.send_error = MagicMock()
        handler.send_header = MagicMock()
        handler.end_headers = MagicMock()
        return handler

    def test_handle_tunnel_connect_invalid_signature(self):
        handler = self.create_mock_handler()
        handler.headers.get.return_value = "invalid-auth"

        handler.handle_tunnel_connect()

        handler.send_error.assert_called_with(403, "Forbidden")

    def test_handle_tunnel_response_valid(self):
        handler = self.create_mock_handler()
        req_id = "req-123"

        event = threading.Event()
        server.PENDING_RESPONSES[req_id] = {"event": event, "data": None}

        response_data = {"id": req_id, "status": 200, "body": ""}
        encrypted_body = self.security.encrypt(json.dumps(response_data))
        encrypted_bytes = encrypted_body.encode("utf-8")

        auth_header = self.security.get_auth_header()
        handler.headers.get.side_effect = lambda key, default=None: {
            "Authorization": auth_header,
            "Content-Length": str(len(encrypted_bytes)),
        }.get(key, default)
        handler.rfile.read.return_value = encrypted_bytes

        handler.handle_tunnel_response()

        self.assertTrue(event.is_set())
        self.assertEqual(server.PENDING_RESPONSES[req_id]["data"]["id"], req_id)
        handler.wfile.write.assert_called_with(b"OK")

    def test_handle_public_request_no_clients(self):
        handler = self.create_mock_handler()
        handler.command = "GET"
        handler.path = "/public-resource"

        handler.handle_public_request()

        handler.send_error.assert_called_with(503, "No Secure Agents Online")

    def test_handle_public_request_with_client_timeout(self):
        handler = self.create_mock_handler()
        handler.command = "GET"
        handler.path = "/api/data"
        handler.headers = MagicMock()
        handler.headers.get.return_value = "0"
        handler.headers.__iter__ = MagicMock(return_value=iter([]))

        client_queue = queue.Queue()
        server.CLIENTS["test-client"] = {
            "queue": client_queue,
            "address": ("127.0.0.1", 5000),
        }

        with patch("threading.Event.wait", return_value=False):
            handler.handle_public_request()

        handler.send_error.assert_called_with(504, "Timeout")

    def test_handle_public_request_success(self):
        handler = self.create_mock_handler()
        handler.command = "GET"
        handler.path = "/api/data"
        handler.headers = MagicMock()
        handler.headers.get.return_value = "0"
        handler.headers.__iter__ = MagicMock(return_value=iter([]))
        handler.headers.items.return_value = []

        client_queue = queue.Queue()
        server.CLIENTS["test-client"] = {
            "queue": client_queue,
            "address": ("127.0.0.1", 5000),
        }

        def populate_response(*args, **kwargs):
            req_id = list(server.PENDING_RESPONSES.keys())[0]
            server.PENDING_RESPONSES[req_id]["data"] = {
                "status": 200,
                "headers": {"Content-Type": "text/plain"},
                "body": base64.b64encode(b"Hello World").decode("utf-8"),
            }
            return True

        with patch("threading.Event.wait", side_effect=populate_response):
            handler.handle_public_request()

        self.assertFalse(client_queue.empty())

        handler.send_response.assert_called_with(200)
        handler.wfile.write.assert_called_with(b"Hello World")
