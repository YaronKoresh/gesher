import http.client
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

from gesher import client
from gesher.security import SecurityLayer

STATS = '{"uptime":1,"requests":2,"tx":3,"rx":4,"clients":[]}'


class TestDashboardPage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        client.SECURITY = SecurityLayer("secret")
        response = MagicMock(
            status_code=200, text=client.SECURITY.encrypt(STATS)
        )
        cls.port = 18796
        cls.patch = patch("gesher.client.requests.post", return_value=response)
        cls.patch.start()
        threading.Thread(
            target=client.run_local_dashboard,
            args=(cls.port, "http://gateway", "PIN"),
            daemon=True,
        ).start()
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.patch.stop()

    def get(self, path):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request("GET", path)
        resp = conn.getresponse()
        body = resp.read()
        content_type = resp.getheader("Content-Type")
        conn.close()
        return resp.status, content_type, body

    def test_page_declares_utf8_in_header_and_in_the_document(self):
        status, content_type, body = self.get("/")
        self.assertEqual(status, 200)
        self.assertEqual(content_type, "text/html; charset=utf-8")
        self.assertIn(b'<meta charset="utf-8">', body)
        self.assertIn("🌉".encode(), body)

    def test_stats_declare_utf8(self):
        status, content_type, _ = self.get("/api/stats")
        self.assertEqual(status, 200)
        self.assertEqual(content_type, "application/json; charset=utf-8")

    def test_query_strings_do_not_change_the_route(self):
        for path in ("/?x=1", "/?", "/api/stats?t=123", "/api/stats?"):
            self.assertEqual(self.get(path)[0], 200, path)

    def test_unknown_paths_are_still_not_found(self):
        for path in ("/other", "/api/stats/extra", "/index.html?x=1"):
            self.assertEqual(self.get(path)[0], 404, path)


if __name__ == "__main__":
    unittest.main()
