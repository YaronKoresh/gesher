import pathlib
import re
import unittest

from gesher import server

DOCS = pathlib.Path(__file__).resolve().parent.parent / "docs"


def read(name):
    return (DOCS / name).read_text(encoding="utf-8")


class TestDocsMatchCode(unittest.TestCase):
    def test_encryption_strength_is_stated_as_fernet_aes_128(self):
        for name in ("protocol.md", "architecture.md"):
            self.assertNotIn("AES-256", read(name), name)

    def test_x_client_id_is_documented_as_a_response_header(self):
        text = read("protocol.md")
        request = text.split("**Response (Success):**")[0]
        self.assertNotIn("X-Client-ID", request)
        self.assertIn("**X-Client-ID:**", text)

    def test_documented_methods_match_the_handler(self):
        handled = {
            name[3:]
            for name in dir(server.BridgeRequestHandler)
            if name.startswith("do_")
        }
        match = re.search(
            r"\*\*Request Methods:\*\*([^\n]*)", read("protocol.md")
        )
        self.assertIsNotNone(match)
        documented = set(re.findall(r"`([A-Z]+)`", match.group(1)))
        self.assertEqual(documented, handled)

    def test_server_full_status_is_documented(self):
        self.assertIn("503", read("protocol.md"))
        self.assertGreaterEqual(server.MAX_CLIENTS, 1)
        self.assertIn(
            f"maximum of {server.MAX_CLIENTS} connected", read("protocol.md")
        )

    def test_upgrade_requests_are_documented_as_refused(self):
        text = read("protocol.md")
        self.assertIn("`Upgrade` header", text)
        self.assertIn("`501`", text)

    def test_oversized_response_handling_is_documented(self):
        text = read("protocol.md")
        self.assertIn("`413 Request Entity Too Large`", text)
        self.assertEqual(server.MAX_BODY_SIZE, 10 * 1024 * 1024)
        self.assertIn("larger than 10 MB", text)

    def test_keepalive_numbers_match_the_code(self):
        from gesher import client

        text = read("protocol.md")
        self.assertIn(f"every {server.KEEPALIVE_INTERVAL} seconds", text)
        self.assertIn(f"after {client.TUNNEL_READ_TIMEOUT} seconds", text)

    def test_replay_window_matches_the_signature_window(self):
        import inspect

        from gesher.security import SecurityLayer

        default = (
            inspect.signature(SecurityLayer.verify_signature)
            .parameters["window_seconds"]
            .default
        )
        self.assertIn(
            f"more than {default} seconds later", read("architecture.md")
        )

    def test_architecture_does_not_promise_ip_bans(self):
        self.assertNotIn("IP Bans", read("architecture.md"))
        self.assertIn(str(server.MAX_AUTH_FAILURES), read("architecture.md"))
        self.assertIn(str(server.AUTH_FAILURE_WINDOW), read("architecture.md"))


if __name__ == "__main__":
    unittest.main()
