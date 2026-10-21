import base64
import http.client
import json
import queue
import threading
import unittest

from gesher import server
from gesher.security import SecurityLayer


class TestWithForwardedFor(unittest.TestCase):
    def test_header_is_added_when_missing(self):
        result = server.with_forwarded_for({"Host": "a"}, "203.0.113.7")
        self.assertEqual(result["X-Forwarded-For"], "203.0.113.7")
        self.assertEqual(result["Host"], "a")

    def test_existing_value_is_extended(self):
        result = server.with_forwarded_for(
            {"x-forwarded-for": "10.0.0.1"}, "203.0.113.7"
        )
        self.assertEqual(result, {"x-forwarded-for": "10.0.0.1, 203.0.113.7"})

    def test_same_last_address_is_not_added_twice(self):
        result = server.with_forwarded_for(
            {"X-Forwarded-For": "10.0.0.1, 203.0.113.7"}, "203.0.113.7"
        )
        self.assertEqual(result["X-Forwarded-For"], "10.0.0.1, 203.0.113.7")

    def test_input_is_not_modified(self):
        headers = {"X-Forwarded-For": "10.0.0.1"}
        server.with_forwarded_for(headers, "203.0.113.7")
        self.assertEqual(headers, {"X-Forwarded-For": "10.0.0.1"})

    def test_duplicate_spellings_collapse_to_one_header(self):
        result = server.with_forwarded_for(
            {"X-Forwarded-For": "1.1.1.1", "x-forwarded-for": "2.2.2.2"},
            "203.0.113.7",
        )
        keys = [k for k in result if k.lower() == "x-forwarded-for"]
        self.assertEqual(len(keys), 1)
        self.assertEqual(result[keys[0]], "1.1.1.1, 2.2.2.2, 203.0.113.7")


class TestTaskCarriesTheAddress(unittest.TestCase):
    def setUp(self):
        server.SECURITY = SecurityLayer("test-secret")
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
        self.tasks = []
        self.stop = threading.Event()
        threading.Thread(target=self.answer, daemon=True).start()
        self.httpd = server.ThreadedHTTPServer(
            ("127.0.0.1", 0), server.BridgeRequestHandler
        )
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def tearDown(self):
        self.stop.set()
        self.httpd.shutdown()
        self.httpd.server_close()

    def answer(self):
        while not self.stop.is_set():
            try:
                item = self.queue.get(timeout=0.1)
            except queue.Empty:
                continue
            task = json.loads(server.SECURITY.decrypt(item["payload"]))
            self.tasks.append(task)
            pending = server.PENDING_RESPONSES[task["id"]]
            pending["data"] = {
                "id": task["id"],
                "status": 200,
                "headers": {},
                "body": base64.b64encode(b"ok").decode(),
            }
            pending["event"].set()

    def get(self, headers):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("GET", "/", headers=headers)
        resp = conn.getresponse()
        resp.read()
        conn.close()
        return self.tasks[-1]["headers"]

    def test_direct_request_carries_the_peer_address(self):
        headers = self.get({})
        self.assertEqual(headers["X-Forwarded-For"], "127.0.0.1")

    def test_existing_header_is_extended(self):
        headers = self.get({"X-Forwarded-For": "10.0.0.1"})
        self.assertEqual(headers["X-Forwarded-For"], "10.0.0.1, 127.0.0.1")

    def test_tunnel_visitor_address_is_not_repeated(self):
        headers = self.get(
            {
                "CF-Connecting-IP": "203.0.113.7",
                "X-Forwarded-For": "203.0.113.7",
            }
        )
        self.assertEqual(headers["X-Forwarded-For"], "203.0.113.7")


if __name__ == "__main__":
    unittest.main()
