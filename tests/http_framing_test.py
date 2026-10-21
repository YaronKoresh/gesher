import json
import threading
import unittest

import requests

from gesher import server
from gesher.security import SecurityLayer


class TestHttpFraming(unittest.TestCase):
    def setUp(self):
        self.security = SecurityLayer("framing-secret")
        server.SECURITY = self.security
        server.GATEKEEPER_PIN = "FRAMEPIN"
        server.CLIENTS = {}
        server.PENDING_RESPONSES = {}
        server.SEEN_SIGNATURES = {}
        server.IP_REQUEST_COUNTS.clear()
        server.AUTH_FAILURES.clear()
        self.httpd = server.ThreadedHTTPServer(
            ("127.0.0.1", 0), server.BridgeRequestHandler
        )
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def test_sync_stats_reply_has_content_length_and_returns_at_once(self):
        r = requests.post(
            f"{self.base}/_sys/sync_stats",
            headers={
                "Authorization": self.security.get_auth_header(),
                "X-Join-Code": "FRAMEPIN",
            },
            timeout=3,
        )

        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.headers["Content-Length"], str(len(r.content)))
        stats = json.loads(self.security.decrypt(r.text))
        self.assertIn("uptime", stats)

    def test_tunnel_response_reply_has_content_length_when_delivered(self):
        event = threading.Event()
        server.PENDING_RESPONSES["req-1"] = {"event": event, "data": None}
        body = self.security.encrypt(
            json.dumps({"id": "req-1", "status": 200, "body": ""})
        )

        r = requests.post(
            f"{self.base}/_tunnel_response",
            data=body,
            headers={"Authorization": self.security.get_auth_header()},
            timeout=3,
        )

        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.content, b"OK")
        self.assertEqual(r.headers["Content-Length"], "2")
        self.assertTrue(event.is_set())

    def test_tunnel_response_reply_has_content_length_when_unknown(self):
        body = self.security.encrypt(
            json.dumps({"id": "nobody", "status": 200, "body": ""})
        )

        r = requests.post(
            f"{self.base}/_tunnel_response",
            data=body,
            headers={"Authorization": self.security.get_auth_header()},
            timeout=3,
        )

        self.assertEqual(r.status_code, 404)
        self.assertEqual(r.headers["Content-Length"], "0")


if __name__ == "__main__":
    unittest.main()
