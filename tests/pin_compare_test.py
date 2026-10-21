import unittest
from unittest.mock import MagicMock, patch

from gesher import server
from gesher.security import SecurityLayer


class TestPinMatches(unittest.TestCase):
    def setUp(self):
        server.GATEKEEPER_PIN = "7A9F2B"

    def test_correct_pin_is_accepted(self):
        self.assertTrue(server.pin_matches("7A9F2B"))

    def test_wrong_missing_and_odd_values_are_rejected(self):
        for value in (
            "7A9F2C",
            "7a9f2b",
            "7A9F2B ",
            "",
            None,
            "é",
            "7A9F2Bé",
            MagicMock(),
            123,
        ):
            self.assertFalse(server.pin_matches(value), value)

    def test_no_pin_set_rejects_everything(self):
        server.GATEKEEPER_PIN = None
        self.assertFalse(server.pin_matches("7A9F2B"))
        self.assertFalse(server.pin_matches(""))

    def test_the_comparison_is_made_in_constant_time(self):
        with patch(
            "gesher.server.hmac.compare_digest", return_value=True
        ) as compare:
            self.assertTrue(server.pin_matches("7A9F2B"))
        compare.assert_called_once_with(b"7A9F2B", b"7A9F2B")


class TestPinInHandlers(unittest.TestCase):
    def setUp(self):
        server.SECURITY = SecurityLayer("secret")
        server.GATEKEEPER_PIN = "7A9F2B"
        server.CLIENTS = {}
        server.SEEN_SIGNATURES = {}
        server.IP_REQUEST_COUNTS.clear()
        server.AUTH_FAILURES.clear()

    def handler(self, pin):
        handler = server.BridgeRequestHandler.__new__(
            server.BridgeRequestHandler
        )
        headers = {
            "Authorization": server.SECURITY.get_auth_header(),
            "X-Join-Code": pin,
        }
        handler.headers = headers
        handler.client_address = ("127.0.0.1", 5000)
        handler.send_error = MagicMock()
        handler.send_response = MagicMock()
        handler.send_header = MagicMock()
        handler.end_headers = MagicMock()
        handler.wfile = MagicMock()
        return handler

    def test_non_ascii_pin_is_rejected_with_401_on_connect(self):
        handler = self.handler("7A9F2é")
        handler.handle_tunnel_connect()
        handler.send_error.assert_called_once_with(401)

    def test_non_ascii_pin_is_rejected_with_401_on_stats(self):
        handler = self.handler("é")
        handler.handle_sync_stats()
        handler.send_error.assert_called_once_with(401)

    def test_correct_pin_reaches_the_stats(self):
        handler = self.handler("7A9F2B")
        handler.handle_sync_stats()
        handler.send_error.assert_not_called()
        handler.send_response.assert_called_once_with(200)


if __name__ == "__main__":
    unittest.main()
