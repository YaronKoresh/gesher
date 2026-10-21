import argparse
import unittest

from gesher import cli


class TestHttpUrlArgument(unittest.TestCase):
    def test_unusable_addresses_are_rejected(self):
        for value in (
            "http://h:abc",
            "http://h:99999",
            "http://h:0",
            "http://ho st",
            "http://:80",
            "http://user@:80",
            "http://h:",
            "http://h/p?q=1",
            "http://h/p#f",
            "http://h/p?",
            "http://[::1",
            "ftp://h",
            "localhost:8000",
            "http://h/\tp",
        ):
            with self.subTest(value=value):
                with self.assertRaises(argparse.ArgumentTypeError):
                    cli.http_url(value)

    def test_usable_addresses_are_accepted_unchanged(self):
        for value in (
            "http://localhost:3000",
            "https://example.com",
            "http://127.0.0.1:8000/",
            "http://host/app",
            "http://host:65535/app/",
            "http://[::1]:8080",
            "https://user:pw@host:8443/base",
        ):
            with self.subTest(value=value):
                self.assertEqual(cli.http_url(value), value)


if __name__ == "__main__":
    unittest.main()
