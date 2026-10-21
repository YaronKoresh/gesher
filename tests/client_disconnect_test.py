import json
import threading
import time
import unittest

import requests

from gesher import server
from gesher.security import SecurityLayer


class TestClientDisconnect(unittest.TestCase):
    def setUp(self):
        self.security = SecurityLayer("disconnect-secret")
        server.SECURITY = self.security
        server.GATEKEEPER_PIN = "DISCPIN"
        server.CLIENTS = {}
        server.PENDING_RESPONSES = {}
        server.SEEN_SIGNATURES = {}
        server.NEXT_CLIENT_INDEX = 0
        server.IP_REQUEST_COUNTS.clear()
        server.AUTH_FAILURES.clear()
        self.httpd = server.ThreadedHTTPServer(
            ("127.0.0.1", 0), server.BridgeRequestHandler
        )
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.responses = []

    def tearDown(self):
        for r in self.responses:
            r.close()
        self.httpd.shutdown()
        self.httpd.server_close()

    def _connect(self):
        before = set(server.CLIENTS)
        r = requests.post(
            f"{self.base}/_connect_tunnel",
            headers={
                "Authorization": self.security.get_auth_header(),
                "X-Join-Code": "DISCPIN",
            },
            stream=True,
            timeout=10,
        )
        self.responses.append(r)
        self.assertEqual(r.status_code, 200)
        client_id = r.headers["X-Client-ID"]
        self._wait(lambda: client_id in server.CLIENTS)
        self.assertNotIn(client_id, before)
        return r, client_id

    def _wait(self, condition, timeout=5):
        deadline = time.time() + timeout
        while time.time() < deadline:
            if condition():
                return True
            time.sleep(0.05)
        self.fail("condition was not met in time")

    def test_closed_connection_is_removed_without_any_write(self):
        r, client_id = self._connect()

        r.close()

        self._wait(lambda: client_id not in server.CLIENTS)

    def test_task_queued_for_a_closed_client_goes_to_a_live_client(self):
        dead, dead_id = self._connect()
        live, live_id = self._connect()
        received = []
        done = threading.Event()

        def read_live():
            for line in live.iter_lines():
                if not line:
                    continue
                task = json.loads(line.decode("utf-8"))
                if task.get("test"):
                    received.append(task)
                    done.set()
                    return

        threading.Thread(target=read_live, daemon=True).start()
        dead_queue = server.CLIENTS[dead_id]["queue"]
        dead.close()
        dead_queue.put({"test": True, "payload": "keep me"})

        self.assertTrue(done.wait(5), "task was lost with the closed client")
        self.assertEqual(received[0]["payload"], "keep me")

    def test_system_messages_are_not_passed_to_other_clients(self):
        task = server.SystemTask({"payload": "list"})

        self.assertFalse(server.redistribute_task(task))

    def test_redistribute_without_live_clients_returns_false(self):
        self.assertFalse(server.redistribute_task({"payload": "x"}))


if __name__ == "__main__":
    unittest.main()
