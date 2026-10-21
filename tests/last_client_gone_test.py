import base64
import threading
import time
import unittest

import requests

from gesher import server
from gesher.security import SecurityLayer


class TestLastClientGone(unittest.TestCase):
    def setUp(self):
        self.security = SecurityLayer("last-client-secret")
        server.SECURITY = self.security
        server.GATEKEEPER_PIN = "LASTPIN"
        server.CLIENTS = {}
        server.PENDING_RESPONSES = {}
        server.SEEN_SIGNATURES = {}
        server.NEXT_CLIENT_INDEX = 0
        server.IP_REQUEST_COUNTS.clear()
        server.AUTH_FAILURES.clear()
        self.saved_interval = server.DISCONNECT_CHECK_INTERVAL
        server.DISCONNECT_CHECK_INTERVAL = 1.5
        self.httpd = server.ThreadedHTTPServer(
            ("127.0.0.1", 0), server.BridgeRequestHandler
        )
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def tearDown(self):
        server.DISCONNECT_CHECK_INTERVAL = self.saved_interval
        self.httpd.shutdown()
        self.httpd.server_close()

    def test_request_queued_for_the_last_client_gets_503_at_once(self):
        tunnel = requests.post(
            f"{self.base}/_connect_tunnel",
            headers={
                "Authorization": self.security.get_auth_header(),
                "X-Join-Code": "LASTPIN",
            },
            stream=True,
            timeout=10,
        )
        deadline = time.time() + 5
        while not server.CLIENTS and time.time() < deadline:
            time.sleep(0.05)
        tunnel.close()
        time.sleep(0.3)
        result = {}

        def visit():
            started = time.time()
            reply = requests.get(f"{self.base}/hello", timeout=40)
            result["status"] = reply.status_code
            result["seconds"] = time.time() - started

        visitor = threading.Thread(target=visit)
        visitor.start()
        visitor.join(10)

        self.assertFalse(visitor.is_alive(), "visitor still waiting")
        self.assertEqual(result["status"], 503)
        self.assertLess(result["seconds"], 5)

    def test_reject_task_answers_the_waiting_request(self):
        event = threading.Event()
        server.PENDING_RESPONSES["r1"] = {"event": event, "data": None}
        task = server.PublicTask(payload="x", req_id="r1")

        self.assertFalse(server.redistribute_task(task))

        self.assertTrue(event.is_set())
        data = server.PENDING_RESPONSES["r1"]["data"]
        self.assertEqual(data["status"], 503)
        self.assertEqual(
            base64.b64decode(data["body"]), b"No Secure Agents Online"
        )

    def test_public_task_serializes_without_the_request_id(self):
        import json

        task = server.PublicTask(payload="x", req_id="r1")

        self.assertEqual(json.loads(json.dumps(task)), {"payload": "x"})

    def test_task_without_a_waiting_request_is_ignored(self):
        self.assertFalse(server.redistribute_task({"payload": "x"}))
        self.assertFalse(
            server.redistribute_task(
                server.PublicTask(payload="x", req_id="missing")
            )
        )


if __name__ == "__main__":
    unittest.main()
