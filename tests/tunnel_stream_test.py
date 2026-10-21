import json
import threading
import unittest

import requests

from gesher import server
from gesher.security import SecurityLayer


class TestTunnelStream(unittest.TestCase):
    def setUp(self):
        self.security = SecurityLayer("stream-secret")
        server.SECURITY = self.security
        server.GATEKEEPER_PIN = "STREAMPIN"
        server.CLIENTS = {}
        server.PENDING_RESPONSES = {}
        server.SEEN_SIGNATURES = {}
        server.IP_REQUEST_COUNTS.clear()
        server.AUTH_FAILURES.clear()
        self.httpd = server.ThreadedHTTPServer(
            ("127.0.0.1", 0), server.BridgeRequestHandler
        )
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()

    def _read_tasks(self, count, received, done):
        with requests.post(
            f"{self.base}/_connect_tunnel",
            headers={
                "Authorization": self.security.get_auth_header(),
                "X-Join-Code": "STREAMPIN",
            },
            stream=True,
            timeout=10,
        ) as r:
            for line in r.iter_lines():
                if not line:
                    continue
                task = json.loads(line.decode("utf-8"))
                if task.get("test"):
                    received.append(task)
                if len(received) >= count:
                    break
        done.set()

    def _wait_for_client(self):
        for _ in range(100):
            if server.CLIENTS:
                return list(server.CLIENTS.values())[0]["queue"]
            threading.Event().wait(0.05)
        self.fail("client did not connect")

    def _start_reader(self, count):
        received = []
        done = threading.Event()
        threading.Thread(
            target=self._read_tasks, args=(count, received, done), daemon=True
        ).start()
        client_queue = self._wait_for_client()
        return client_queue, received, done

    def test_task_larger_than_512_bytes_reaches_client_at_once(self):
        client_queue, received, done = self._start_reader(2)

        client_queue.put({"test": True, "payload": "A" * 1500})
        client_queue.put({"test": True, "payload": "B" * 20})

        self.assertTrue(done.wait(5), "tasks were held back by the stream")
        self.assertEqual(received[0]["payload"], "A" * 1500)
        self.assertEqual(received[1]["payload"], "B" * 20)

    def test_single_task_is_not_held_back(self):
        client_queue, received, done = self._start_reader(1)

        client_queue.put({"test": True, "payload": "C" * 700})

        self.assertTrue(done.wait(5), "task was held back by the stream")
        self.assertEqual(received[0]["payload"], "C" * 700)

    def test_frame_chunk(self):
        self.assertEqual(server.frame_chunk(b"abc\n"), b"4\r\nabc\n\r\n")
        self.assertEqual(
            server.frame_chunk(b"x" * 255), b"ff\r\n" + b"x" * 255 + b"\r\n"
        )


if __name__ == "__main__":
    unittest.main()
