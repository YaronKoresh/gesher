import json
import queue
import socket
import threading
import unittest

from gesher import server
from gesher.security import SecurityLayer


class TestRawPathBytes(unittest.TestCase):
    def setUp(self):
        server.SECURITY = SecurityLayer("test-secret")
        server.GATEKEEPER_PIN = "PIN"
        server.CLIENTS = {}
        server.PENDING_RESPONSES = {}
        server.IP_REQUEST_COUNTS.clear()
        server.AUTH_FAILURES.clear()
        self.httpd = server.ThreadedHTTPServer(
            ("127.0.0.1", 0), server.BridgeRequestHandler
        )
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)

    def forwarded_url(self, request_line):
        tasks = queue.Queue()
        server.CLIENTS["c"] = {"queue": tasks, "address": ("127.0.0.1", 1)}
        seen = []

        def agent():
            task = tasks.get(timeout=5)
            data = json.loads(server.SECURITY.decrypt(task["payload"]))
            seen.append(data["url"])
            pending = server.PENDING_RESPONSES[data["id"]]
            pending["data"] = {"id": data["id"], "status": 204}
            pending["event"].set()

        thread = threading.Thread(target=agent, daemon=True)
        thread.start()
        conn = socket.create_connection(self.httpd.server_address)
        conn.sendall(request_line + b"\r\nHost: h\r\nConnection: close\r\n\r\n")
        conn.settimeout(5)
        while conn.recv(4096):
            pass
        conn.close()
        thread.join(5)
        return seen[0]

    def test_raw_bytes_are_percent_encoded_once(self):
        url = self.forwarded_url(b"GET /a%20b?y=\xd7\xa9 HTTP/1.1")
        self.assertEqual(url, "/a%20b?y=%D7%A9")

    def test_ascii_path_is_unchanged(self):
        url = self.forwarded_url(b"GET /a/b?x=1&y=%26 HTTP/1.1")
        self.assertEqual(url, "/a/b?x=1&y=%26")


if __name__ == "__main__":
    unittest.main()
