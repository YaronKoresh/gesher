import base64
import http.client
import json
import queue
import threading
import unittest

from gesher import server
from gesher.security import SecurityLayer


class TestHeadAndOptions(unittest.TestCase):
    def setUp(self):
        server.SECURITY = SecurityLayer("test-secret")
        server.GATEKEEPER_PIN = "TESTPIN"
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
        self.seen = []
        self.stop = threading.Event()
        self.worker = threading.Thread(target=self.answer, daemon=True)
        self.worker.start()
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
            self.seen.append(task["method"])
            if task["method"] == "HEAD":
                status, headers, body = 200, {"Content-Length": "5"}, b""
            elif task["method"] == "OPTIONS":
                status, headers, body = 204, {"Allow": "GET, OPTIONS"}, b""
            else:
                status, headers, body = 200, {}, b"hello"
            pending = server.PENDING_RESPONSES[task["id"]]
            pending["data"] = {
                "id": task["id"],
                "status": status,
                "headers": headers,
                "body": base64.b64encode(body).decode(),
            }
            pending["event"].set()

    def request(self, method):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request(method, "/")
        resp = conn.getresponse()
        body = resp.read()
        result = (resp.status, resp.getheader("Content-Length"), body)
        allow = resp.getheader("Allow")
        conn.close()
        return result, allow

    def test_head_is_forwarded_with_length_and_without_body(self):
        (status, length, body), _ = self.request("HEAD")
        self.assertEqual(status, 200)
        self.assertEqual(length, "5")
        self.assertEqual(body, b"")
        self.assertEqual(self.seen, ["HEAD"])

    def test_options_is_forwarded(self):
        (status, _, _), allow = self.request("OPTIONS")
        self.assertEqual(status, 204)
        self.assertEqual(allow, "GET, OPTIONS")
        self.assertEqual(self.seen, ["OPTIONS"])

    def test_get_still_returns_the_body(self):
        (status, length, body), _ = self.request("GET")
        self.assertEqual((status, length, body), (200, "5", b"hello"))


if __name__ == "__main__":
    unittest.main()
