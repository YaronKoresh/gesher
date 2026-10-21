import http.client
import re
import threading
import unittest

from gesher import server
from gesher.security import SecurityLayer


class TestServerHeader(unittest.TestCase):
    def setUp(self):
        server.SECURITY = SecurityLayer("secret")
        server.GATEKEEPER_PIN = "PIN"
        server.CLIENTS = {}
        server.IP_REQUEST_COUNTS.clear()
        server.AUTH_FAILURES.clear()
        self.httpd = server.ThreadedHTTPServer(
            ("127.0.0.1", 0), server.BridgeRequestHandler
        )
        self.port = self.httpd.server_address[1]
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def header_for(self, method, path):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        conn.request(method, path, headers={"Content-Length": "0"})
        resp = conn.getresponse()
        resp.read()
        conn.close()
        return resp.status, resp.getheader("Server")

    def test_error_responses_name_only_the_product(self):
        status, header = self.header_for("GET", "/")
        self.assertEqual(status, 503)
        self.assertEqual(header, "gesher")

    def test_rejected_posts_name_only_the_product(self):
        status, header = self.header_for("POST", "/_connect_tunnel")
        self.assertEqual(status, 403)
        self.assertEqual(header, "gesher")

    def test_no_python_version_in_the_header(self):
        _, header = self.header_for("GET", "/anything")
        self.assertIsNone(re.search(r"Python|\d+\.\d+", header))


if __name__ == "__main__":
    unittest.main()
