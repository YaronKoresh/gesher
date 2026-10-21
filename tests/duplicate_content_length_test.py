import io
import unittest
from http.client import parse_headers
from unittest.mock import MagicMock

from gesher import server


def handler_with(text):
    handler = server.BridgeRequestHandler.__new__(server.BridgeRequestHandler)
    handler.headers = parse_headers(io.BytesIO(text.encode() + b"\r\n\r\n"))
    handler.send_error = MagicMock()
    return handler


class TestDuplicateContentLength(unittest.TestCase):
    def test_different_values_are_rejected(self):
        handler = handler_with("Content-Length: 3\r\nContent-Length: 5")
        self.assertIsNone(handler.read_content_length())
        handler.send_error.assert_called_once_with(400, "Bad Content-Length")

    def test_identical_values_are_accepted(self):
        handler = handler_with("Content-Length: 3\r\nContent-Length: 3")
        self.assertEqual(handler.read_content_length(), 3)
        handler.send_error.assert_not_called()

    def test_single_and_missing_headers_still_work(self):
        self.assertEqual(
            handler_with("Content-Length: 7").read_content_length(), 7
        )
        self.assertEqual(handler_with("Host: h").read_content_length(), 0)


if __name__ == "__main__":
    unittest.main()
