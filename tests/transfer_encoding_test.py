import unittest
from unittest.mock import MagicMock

from gesher import server


def handler_with(value):
    handler = server.BridgeRequestHandler.__new__(server.BridgeRequestHandler)
    handler.headers = {} if value is None else {"Transfer-Encoding": value}
    handler.send_error = MagicMock()
    return handler


class TestTransferEncoding(unittest.TestCase):
    def test_only_a_plain_chunked_coding_is_chunked(self):
        for value in ("chunked", "Chunked", " CHUNKED ", "identity, chunked"):
            with self.subTest(value=value):
                self.assertTrue(handler_with(value).is_chunked_request())
        for value in (
            None,
            "",
            "identity",
            "gzip",
            "chunkedx",
            "gzip, chunked",
        ):
            with self.subTest(value=value):
                self.assertFalse(handler_with(value).is_chunked_request())

    def test_other_codings_are_listed_as_unsupported(self):
        for value in ("gzip", "chunkedx", "gzip, chunked", "chunked, gzip"):
            with self.subTest(value=value):
                codings = handler_with(value).transfer_codings()
                self.assertNotEqual(codings, [])
                self.assertNotEqual(codings, ["chunked"])

    def test_absent_or_identity_means_no_coding(self):
        for value in (None, "", "identity"):
            with self.subTest(value=value):
                self.assertEqual(handler_with(value).transfer_codings(), [])


if __name__ == "__main__":
    unittest.main()
