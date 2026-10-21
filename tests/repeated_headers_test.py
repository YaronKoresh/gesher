import io
import unittest
from http.client import parse_headers

from gesher import server


def parsed(text):
    return parse_headers(io.BytesIO(text.encode() + b"\r\n\r\n"))


class TestRepeatedRequestHeaders(unittest.TestCase):
    def test_repeated_cookie_headers_are_joined_with_semicolons(self):
        result = server.merge_repeated_headers(
            parsed("Cookie: a=1\r\nCookie: b=2")
        )
        self.assertEqual(result, {"Cookie": "a=1; b=2"})

    def test_other_repeated_headers_are_joined_with_commas(self):
        result = server.merge_repeated_headers(
            parsed("Accept: x\r\nAccept: y\r\naccept: z")
        )
        self.assertEqual(result, {"Accept": "x, y, z"})

    def test_single_headers_are_unchanged(self):
        result = server.merge_repeated_headers(
            parsed("Host: h\r\nAccept: x")
        )
        self.assertEqual(result, {"Host": "h", "Accept": "x"})

    def test_forwarded_for_still_gets_the_peer_address_once(self):
        headers = server.merge_repeated_headers(
            parsed("X-Forwarded-For: 1.1.1.1\r\nX-Forwarded-For: 2.2.2.2")
        )
        result = server.with_forwarded_for(headers, "3.3.3.3")
        self.assertEqual(
            result, {"X-Forwarded-For": "1.1.1.1, 2.2.2.2, 3.3.3.3"}
        )


if __name__ == "__main__":
    unittest.main()
