import unittest
from unittest.mock import patch

from gesher import server
from gesher.security import SIGNATURE_WINDOW_SECONDS, SecurityLayer

T0 = 1_000_000.0


def handler_with(header):
    handler = server.BridgeRequestHandler.__new__(server.BridgeRequestHandler)
    handler.headers = {"Authorization": header}
    return handler


class TestReplayWindow(unittest.TestCase):
    def setUp(self):
        server.SECURITY = SecurityLayer("secret")
        server.SEEN_SIGNATURES = {}

    def header_at(self, offset):
        with patch("gesher.security.time.time", return_value=T0 + offset):
            return server.SECURITY.get_auth_header()

    def verify_at(self, header, now):
        with patch("gesher.server.time.time", return_value=T0 + now), patch(
            "gesher.security.time.time", return_value=T0 + now
        ):
            return handler_with(header).verify_signature()

    def test_future_dated_signature_is_rejected_for_its_whole_validity(self):
        header = self.header_at(SIGNATURE_WINDOW_SECONDS - 5)
        self.assertTrue(self.verify_at(header, 0))
        for now in range(1, 2 * SIGNATURE_WINDOW_SECONDS, 3):
            self.assertFalse(self.verify_at(header, now), now)

    def test_signature_is_accepted_only_once(self):
        header = self.header_at(0)
        self.assertTrue(self.verify_at(header, 0))
        self.assertFalse(self.verify_at(header, 1))

    def test_signature_outside_the_window_is_rejected_by_the_timestamp(self):
        header = self.header_at(0)
        self.assertFalse(self.verify_at(header, SIGNATURE_WINDOW_SECONDS + 5))

    def test_old_entries_are_removed(self):
        header = self.header_at(0)
        self.assertTrue(self.verify_at(header, 0))
        later = self.header_at(server.SEEN_SIGNATURE_TTL + 10)
        self.assertTrue(self.verify_at(later, server.SEEN_SIGNATURE_TTL + 10))
        self.assertEqual(len(server.SEEN_SIGNATURES), 1)

    def test_retention_covers_the_longest_validity(self):
        self.assertGreater(
            server.SEEN_SIGNATURE_TTL, 2 * SIGNATURE_WINDOW_SECONDS
        )


if __name__ == "__main__":
    unittest.main()
