import unittest
from unittest.mock import MagicMock

from gesher import server


def handler_with(value):
    handler = server.BridgeRequestHandler.__new__(server.BridgeRequestHandler)
    handler.headers = {} if value is None else {"Content-Length": value}
    handler.send_error = MagicMock()
    return handler


class TestContentLengthDigits(unittest.TestCase):
    def test_values_that_are_not_plain_digits_are_rejected(self):
        for value in ("1_0", "+5", "-0", "-1", "0x10", "5 5", "", "1.0"):
            with self.subTest(value=value):
                handler = handler_with(value)
                self.assertIsNone(handler.read_content_length())
                handler.send_error.assert_called_once_with(
                    400, "Bad Content-Length"
                )

    def test_plain_digits_and_a_missing_header_are_accepted(self):
        for value, expected in (("0", 0), ("12", 12), (None, 0)):
            with self.subTest(value=value):
                handler = handler_with(value)
                self.assertEqual(handler.read_content_length(), expected)
                handler.send_error.assert_not_called()

    def test_oversized_length_is_still_rejected(self):
        handler = handler_with(str(server.MAX_BODY_SIZE + 1))
        self.assertIsNone(handler.read_content_length())
        handler.send_error.assert_called_once_with(413)


if __name__ == "__main__":
    unittest.main()
