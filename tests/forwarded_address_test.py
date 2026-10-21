import unittest
from unittest.mock import patch

from gesher import server


def handler_for(peer, forwarded=None):
    handler = server.BridgeRequestHandler.__new__(server.BridgeRequestHandler)
    handler.client_address = (peer, 5000)
    handler.headers = (
        {} if forwarded is None else {"CF-Connecting-IP": forwarded}
    )
    return handler


class TestRemoteAddress(unittest.TestCase):
    def setUp(self):
        server.IP_REQUEST_COUNTS.clear()
        server.AUTH_FAILURES.clear()
        server.LAST_RATE_PRUNE = 0.0

    def test_loopback_peer_uses_the_forwarded_address(self):
        self.assertEqual(
            handler_for("127.0.0.1", "203.0.113.7").remote_ip(), "203.0.113.7"
        )
        self.assertEqual(
            handler_for("::1", " 2001:db8::5 ").remote_ip(), "2001:db8::5"
        )

    def test_loopback_peer_without_the_header_keeps_its_address(self):
        self.assertEqual(handler_for("127.0.0.1").remote_ip(), "127.0.0.1")

    def test_invalid_forwarded_values_are_ignored(self):
        for value in ("", "not-an-address", "1.2.3.4, 5.6.7.8", "999.1.1.1"):
            self.assertEqual(
                handler_for("127.0.0.1", value).remote_ip(), "127.0.0.1", value
            )

    def test_remote_peer_cannot_forge_its_address(self):
        self.assertEqual(
            handler_for("198.51.100.4", "203.0.113.7").remote_ip(),
            "198.51.100.4",
        )

    def test_visitors_behind_the_tunnel_have_separate_request_limits(self):
        with patch("gesher.server.time.time", return_value=5000.0):
            for i in range(server.RATE_LIMIT_MAX_REQ + 5):
                allowed = handler_for(
                    "127.0.0.1", f"203.0.113.{i % 250}.".rstrip(".")
                ).check_rate_limit()
                if i < 250:
                    self.assertTrue(allowed, i)

    def test_one_visitor_still_hits_the_request_limit(self):
        with patch("gesher.server.time.time", return_value=6000.0):
            results = [
                handler_for("127.0.0.1", "203.0.113.9").check_rate_limit()
                for _ in range(server.RATE_LIMIT_MAX_REQ + 1)
            ]
        self.assertTrue(all(results[:-1]))
        self.assertFalse(results[-1])

    def test_auth_failures_block_only_the_failing_visitor(self):
        with patch("gesher.server.time.time", return_value=7000.0):
            for _ in range(server.MAX_AUTH_FAILURES):
                handler_for("127.0.0.1", "198.51.100.9").record_auth_failure()
            blocked = handler_for(
                "127.0.0.1", "198.51.100.9"
            ).check_rate_limit()
            other = handler_for("127.0.0.1", "203.0.113.200").check_rate_limit()
        self.assertFalse(blocked)
        self.assertTrue(other)


if __name__ == "__main__":
    unittest.main()
