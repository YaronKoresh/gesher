import json
import unittest
from unittest.mock import MagicMock, patch

from gesher import client
from gesher.security import SecurityLayer


def encrypted_task(security):
    task = {
        "id": "req-1",
        "method": "GET",
        "url": "/big",
        "headers": {},
        "body": "",
    }
    return security.encrypt(json.dumps(task))


class TestLargeLocalResponse(unittest.TestCase):
    def setUp(self):
        client.SECURITY = SecurityLayer("secret")

    def run_task(self, gateway_statuses):
        local = MagicMock(status_code=200, content=b"x" * 10)
        local.headers = {"Content-Length": "10"}
        local.raw.headers.getlist.return_value = []
        replies = [MagicMock(status_code=code) for code in gateway_statuses]
        with patch("gesher.client.requests.request", return_value=local), patch(
            "gesher.client.requests.post", side_effect=replies
        ) as post:
            client.handle_task(
                encrypted_task(client.SECURITY),
                "http://local",
                "http://gateway",
            )
        return [
            json.loads(client.SECURITY.decrypt(call.kwargs["data"]))
            for call in post.call_args_list
        ]

    def test_refused_response_is_replaced_by_a_502(self):
        sent = self.run_task([413, 200])
        self.assertEqual(len(sent), 2)
        self.assertEqual(sent[0]["status"], 200)
        self.assertEqual(sent[1]["id"], "req-1")
        self.assertEqual(sent[1]["status"], 502)

    def test_accepted_response_is_sent_once(self):
        sent = self.run_task([200])
        self.assertEqual(len(sent), 1)
        self.assertEqual(sent[0]["status"], 200)

    def test_post_gateway_response_returns_the_gateway_status(self):
        with patch(
            "gesher.client.requests.post",
            return_value=MagicMock(status_code=413),
        ):
            self.assertEqual(
                client.post_gateway_response("http://g", "id", 200, {}, b""),
                413,
            )


if __name__ == "__main__":
    unittest.main()
