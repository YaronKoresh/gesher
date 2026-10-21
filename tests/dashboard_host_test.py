import http.client
import threading
import time
import unittest
from unittest.mock import MagicMock, patch

from gesher import client
from gesher.security import SecurityLayer

STATS = '{"uptime":1,"requests":2,"tx":3,"rx":4,"clients":[]}'


class TestHostHeaderCheck(unittest.TestCase):
    def test_local_names_are_accepted(self):
        for value in (
            "localhost",
            "localhost:9000",
            "LOCALHOST:9000",
            "127.0.0.1",
            "127.0.0.1:9000",
            "[::1]",
            "[::1]:9000",
            None,
        ):
            self.assertTrue(client.is_local_host_header(value), value)

    def test_other_names_are_rejected(self):
        for value in (
            "attacker.example",
            "attacker.example:9000",
            "localhost.attacker.example",
            "127.0.0.1.attacker.example:9000",
            "localhost:abc",
            "[::1",
            "[::1]x",
            "",
            "192.168.1.5:9000",
        ):
            self.assertFalse(client.is_local_host_header(value), value)


class TestDashboardHost(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        client.SECURITY = SecurityLayer("secret")
        cls.response = MagicMock(
            status_code=200, text=client.SECURITY.encrypt(STATS)
        )
        cls.port = 18795
        cls.patch = patch(
            "gesher.client.requests.post", return_value=cls.response
        )
        cls.patch.start()
        thread = threading.Thread(
            target=client.run_local_dashboard,
            args=(cls.port, "http://gateway", "PIN"),
            daemon=True,
        )
        thread.start()
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.patch.stop()

    def get(self, path, host):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.putrequest("GET", path, skip_host=True)
        conn.putheader("Host", host)
        conn.endheaders()
        resp = conn.getresponse()
        body = resp.read()
        conn.close()
        return resp.status, body

    def test_local_host_gets_the_page_and_the_stats(self):
        for host in (f"localhost:{self.port}", f"127.0.0.1:{self.port}"):
            self.assertEqual(self.get("/", host)[0], 200)
            status, body = self.get("/api/stats", host)
            self.assertEqual(status, 200)
            self.assertIn(b"uptime", body)

    def test_foreign_host_is_refused(self):
        for path in ("/", "/api/stats"):
            status, body = self.get(path, f"attacker.example:{self.port}")
            self.assertEqual(status, 403, path)
            self.assertNotIn(b"uptime", body)


if __name__ == "__main__":
    unittest.main()
