import unittest

from gesher import server


class TestHopByHopRequestHeaders(unittest.TestCase):
    def test_connection_level_headers_are_removed(self):
        headers = {
            "Host": "h",
            "Connection": "keep-alive",
            "Keep-Alive": "300",
            "TE": "trailers",
            "Proxy-Connection": "keep-alive",
            "Expect": "100-continue",
            "Accept": "x",
        }
        self.assertEqual(
            server.drop_connection_headers(headers),
            {"Host": "h", "Accept": "x"},
        )

    def test_headers_named_by_connection_are_removed(self):
        headers = {
            "Connection": "close, X-Private",
            "x-private": "1",
            "X-Keep": "2",
        }
        self.assertEqual(
            server.drop_connection_headers(headers), {"X-Keep": "2"}
        )

    def test_host_and_content_length_survive_a_connection_list(self):
        headers = {
            "Connection": "Host, Content-Length",
            "Host": "h",
            "Content-Length": "3",
        }
        self.assertEqual(
            server.drop_connection_headers(headers),
            {"Host": "h", "Content-Length": "3"},
        )


if __name__ == "__main__":
    unittest.main()
