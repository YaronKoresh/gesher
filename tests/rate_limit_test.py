import unittest
from unittest.mock import patch

from gesher import server


def handler_for(ip):
    handler = server.BridgeRequestHandler.__new__(server.BridgeRequestHandler)
    handler.client_address = (ip, 5000)
    handler.headers = {}
    return handler


class TestRateLimitState(unittest.TestCase):
    def setUp(self):
        server.IP_REQUEST_COUNTS.clear()
        server.AUTH_FAILURES.clear()
        server.LAST_RATE_PRUNE = 0.0

    def check(self, ip, now):
        with patch("gesher.server.time.time", return_value=now):
            return handler_for(ip).check_rate_limit()

    def test_stale_addresses_are_removed_after_the_window(self):
        for i in range(500):
            self.check(f"10.0.{i // 256}.{i % 256}", 1000.0)
        self.assertEqual(len(server.IP_REQUEST_COUNTS), 500)

        self.check("192.168.0.1", 1000.0 + server.AUTH_FAILURE_WINDOW + 1)

        self.assertEqual(list(server.IP_REQUEST_COUNTS), ["192.168.0.1"])
        self.assertEqual(len(server.AUTH_FAILURES), 0)

    def test_stale_failures_are_removed_after_their_window(self):
        with patch("gesher.server.time.time", return_value=1000.0):
            handler_for("10.1.1.1").record_auth_failure()
        self.assertEqual(len(server.AUTH_FAILURES), 1)

        self.check("192.168.0.2", 1000.0 + server.AUTH_FAILURE_WINDOW + 1)

        self.assertNotIn("10.1.1.1", server.AUTH_FAILURES)

    def test_clean_addresses_do_not_create_failure_entries(self):
        for i in range(50):
            self.check(f"10.2.0.{i}", 2000.0)

        self.assertEqual(len(server.AUTH_FAILURES), 0)

    def test_request_limit_still_blocks_and_then_releases(self):
        for _ in range(server.RATE_LIMIT_MAX_REQ):
            self.assertTrue(self.check("10.3.0.1", 3000.0))

        self.assertFalse(self.check("10.3.0.1", 3000.5))
        self.assertTrue(self.check("10.3.0.2", 3000.5))
        self.assertTrue(
            self.check("10.3.0.1", 3000.0 + server.RATE_LIMIT_WINDOW + 1)
        )

    def test_auth_failures_still_block_and_then_release(self):
        with patch("gesher.server.time.time", return_value=4000.0):
            for _ in range(server.MAX_AUTH_FAILURES):
                handler_for("10.4.0.1").record_auth_failure()

        self.assertFalse(self.check("10.4.0.1", 4001.0))
        self.assertTrue(self.check("10.4.0.2", 4001.0))
        self.assertTrue(
            self.check("10.4.0.1", 4000.0 + server.AUTH_FAILURE_WINDOW + 1)
        )


if __name__ == "__main__":
    unittest.main()
