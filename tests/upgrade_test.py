import http.client
import queue
import threading
import unittest

from gesher import server
from gesher.security import SecurityLayer


class TestUpgradeRequests(unittest.TestCase):
    def setUp(self):
        server.SECURITY = SecurityLayer("secret")
        server.GATEKEEPER_PIN = "PIN"
        server.CLIENTS = {}
        server.PENDING_RESPONSES = {}
        server.NEXT_CLIENT_INDEX = 0
        server.SEEN_SIGNATURES = {}
        server.IP_REQUEST_COUNTS.clear()
        server.AUTH_FAILURES.clear()
        self.queue = queue.Queue()
        server.CLIENTS["c1"] = {
            "queue": self.queue,
            "address": ("127.0.0.1", 1),
        }
        self.httpd = server.ThreadedHTTPServer(
            ("127.0.0.1", 0), server.BridgeRequestHandler
        )
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def send(self, headers):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", "/socket", headers=headers)
        resp = conn.getresponse()
        resp.read()
        conn.close()
        return resp.status

    def test_websocket_handshake_is_refused_without_a_task(self):
        status = self.send(
            {
                "Connection": "Upgrade",
                "Upgrade": "websocket",
                "Sec-WebSocket-Version": "13",
                "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
            }
        )
        self.assertEqual(status, 501)
        self.assertTrue(self.queue.empty())
        self.assertEqual(server.PENDING_RESPONSES, {})

    def test_h2c_upgrade_is_refused(self):
        self.assertEqual(
            self.send(
                {"Connection": "Upgrade, HTTP2-Settings", "Upgrade": "h2c"}
            ),
            501,
        )
        self.assertTrue(self.queue.empty())

    def test_plain_requests_still_create_a_task(self):
        def answer():
            item = self.queue.get(timeout=5)
            task = server.SECURITY.decrypt(item["payload"])
            self.assertIn("/socket", task)
            import base64
            import json

            data = json.loads(task)
            pending = server.PENDING_RESPONSES[data["id"]]
            pending["data"] = {
                "id": data["id"],
                "status": 200,
                "headers": {},
                "body": base64.b64encode(b"ok").decode(),
            }
            pending["event"].set()

        worker = threading.Thread(target=answer, daemon=True)
        worker.start()
        self.assertEqual(self.send({}), 200)
        worker.join(5)


if __name__ == "__main__":
    unittest.main()
