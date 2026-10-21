import io
import unittest
from unittest.mock import MagicMock

from gesher import server


def read(size_line, rest=b"x" * 20 + b"\r\n0\r\n\r\n"):
    handler = server.BridgeRequestHandler.__new__(server.BridgeRequestHandler)
    handler.rfile = io.BytesIO(size_line + b"\r\n" + rest)
    handler.send_error = MagicMock()
    return handler.read_chunked_body(), handler.send_error


class TestChunkSizeDigits(unittest.TestCase):
    def test_sizes_that_are_not_plain_hex_digits_are_rejected(self):
        for line in (b"1_0", b"+a", b"0x5", b"-0", b"", b"g", b"1 1"):
            with self.subTest(line=line):
                body, send_error = read(line)
                self.assertIsNone(body)
                send_error.assert_called_once_with(400, "Bad Chunk Size")

    def test_plain_hex_sizes_extensions_and_spaces_are_accepted(self):
        for line, expected in (
            (b"5", b"x" * 5),
            (b" 5 ", b"x" * 5),
            (b"A", b"x" * 10),
            (b"a;name=value", b"x" * 10),
        ):
            with self.subTest(line=line):
                body, send_error = read(line, b"x" * 20 + b"\r\n0\r\n\r\n")
                self.assertTrue(body.startswith(expected))
                send_error.assert_not_called()

    def test_zero_size_ends_the_body(self):
        handler = server.BridgeRequestHandler.__new__(
            server.BridgeRequestHandler
        )
        handler.rfile = io.BytesIO(b"0\r\n\r\n")
        handler.send_error = MagicMock()
        self.assertEqual(handler.read_chunked_body(), b"")


if __name__ == "__main__":
    unittest.main()
