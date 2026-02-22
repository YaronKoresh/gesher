import base64
import collections
import http.server
import json
import logging
import queue
import secrets
import socketserver
import threading
import time
import uuid

from .security import SecurityLayer

logging.basicConfig(
    level=logging.INFO, format="[%(asctime)s] [%(levelname)s] %(message)s"
)
logger = logging.getLogger("BridgeServer")


GATEKEEPER_PIN = None
SHARED_SECRET = None
SECURITY = None
CLIENTS = {}
CLIENT_LOCK = threading.Lock()
NEXT_CLIENT_INDEX = 0
PENDING_RESPONSES = {}
SEEN_SIGNATURES = {}
SIGNATURE_LOCK = threading.Lock()


MAX_CLIENTS = 50
MAX_BODY_SIZE = 10 * 1024 * 1024
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX_REQ = 100
IP_REQUEST_COUNTS = collections.defaultdict(list)
IP_LOCK = threading.Lock()


AUTH_FAILURES = collections.defaultdict(list)
MAX_AUTH_FAILURES = 5
AUTH_LOCKOUT_DURATION = 600


STATS = {
    "start_time": time.time(),
    "requests_processed": 0,
    "bytes_tx": 0,
    "bytes_rx": 0,
    "blocked_reqs": 0,
}
STATS_LOCK = threading.Lock()


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


class BridgeRequestHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_request(self, code="-", size="-"):
        pass

    def check_rate_limit(self):
        client_ip = self.client_address[0]
        now = time.time()

        with IP_LOCK:
            timestamps = IP_REQUEST_COUNTS[client_ip]
            IP_REQUEST_COUNTS[client_ip] = [
                t for t in timestamps if now - t < RATE_LIMIT_WINDOW
            ]

            if not IP_REQUEST_COUNTS[client_ip]:
                del IP_REQUEST_COUNTS[client_ip]
                IP_REQUEST_COUNTS[client_ip] = []

            if len(IP_REQUEST_COUNTS[client_ip]) >= RATE_LIMIT_MAX_REQ:
                return False

            IP_REQUEST_COUNTS[client_ip].append(now)

            failures = AUTH_FAILURES[client_ip]
            AUTH_FAILURES[client_ip] = [t for t in failures if now - t < 120]

            if not AUTH_FAILURES[client_ip]:
                del AUTH_FAILURES[client_ip]
                AUTH_FAILURES[client_ip] = []

            if len(AUTH_FAILURES[client_ip]) >= MAX_AUTH_FAILURES:
                return False

            return True

    def record_auth_failure(self):
        client_ip = self.client_address[0]
        with IP_LOCK:
            AUTH_FAILURES[client_ip].append(time.time())
        logger.warning(f"⛔ Auth Failure from {client_ip}")

    def track_traffic(self, tx=0, rx=0):
        with STATS_LOCK:
            STATS["bytes_tx"] += tx
            STATS["bytes_rx"] += rx

    def do_GET(self):
        self.handle_public_request()

    def handle_sync_stats(self):
        if not self.check_rate_limit():
            self.send_error(429)
            return

        if not self.verify_signature():
            self.record_auth_failure()
            self.send_error(403)
            return

        client_pin = self.headers.get("X-Join-Code")
        if not client_pin or client_pin != GATEKEEPER_PIN:
            self.record_auth_failure()
            self.send_error(401)
            return

        with STATS_LOCK:
            uptime = time.time() - STATS["start_time"]
            active_clients = []
            with CLIENT_LOCK:
                for cid, data in CLIENTS.items():
                    active_clients.append({"id": cid, "ip": data["address"][0]})

            data = {
                "uptime": uptime,
                "requests": STATS["requests_processed"],
                "tx": STATS["bytes_tx"],
                "rx": STATS["bytes_rx"],
                "clients": active_clients,
            }

        json_str = json.dumps(data)
        encrypted_payload = SECURITY.encrypt(json_str)

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(encrypted_payload.encode())

    def do_POST(self):
        if self.path == "/_connect_tunnel":
            self.handle_tunnel_connect()
        elif self.path == "/_tunnel_response":
            self.handle_tunnel_response()
        elif self.path == "/_sys/sync_stats":
            self.handle_sync_stats()
        else:
            self.handle_public_request()

    def verify_signature(self):
        auth_header = self.headers.get("Authorization")
        is_valid, signature = SECURITY.verify_signature(auth_header)

        if not is_valid:
            return False

        current_time = int(time.time())
        with SIGNATURE_LOCK:
            keys_to_delete = [
                k for k, t in SEEN_SIGNATURES.items() if current_time - t > 35
            ]
            for k in keys_to_delete:
                del SEEN_SIGNATURES[k]

            if signature in SEEN_SIGNATURES:
                logger.warning(f"⚠️ Replay Attack Blocked: {signature[:8]}...")
                return False
            SEEN_SIGNATURES[signature] = current_time
        return True

    def handle_tunnel_connect(self):
        if not self.check_rate_limit():
            self.send_error(429, "Too Many Requests")
            return

        with CLIENT_LOCK:
            if len(CLIENTS) >= MAX_CLIENTS:
                self.send_error(503, "Server Full")
                return

        if not self.verify_signature():
            self.record_auth_failure()
            self.send_error(403, "Forbidden")
            return

        client_pin = self.headers.get("X-Join-Code")
        if not client_pin or client_pin != GATEKEEPER_PIN:
            logger.warning("✋ Blocked Connection (Invalid PIN)")
            self.record_auth_failure()
            self.send_error(401)
            return

        client_id = str(uuid.uuid4())[:8]
        client_queue = queue.Queue()

        logger.info(f"🛡️  Client Connected: {client_id}")

        with CLIENT_LOCK:
            CLIENTS[client_id] = {
                "queue": client_queue,
                "address": self.client_address,
            }

        self.broadcast_client_list()

        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson")
        self.send_header("X-Client-ID", client_id)
        self.end_headers()

        try:
            while True:
                task = client_queue.get()
                json_str = json.dumps(task) + "\n"
                data = json_str.encode("utf-8")
                self.wfile.write(data)
                self.wfile.flush()
                self.track_traffic(tx=len(data))
        except Exception:
            pass
        finally:
            with CLIENT_LOCK:
                if client_id in CLIENTS:
                    del CLIENTS[client_id]
            logger.info(f"👋 Client Disconnected: {client_id}")
            self.broadcast_client_list()

    def handle_tunnel_response(self):
        if not self.verify_signature():
            self.send_error(403)
            return

        try:
            length = int(self.headers.get("Content-Length", 0))
            if length > MAX_BODY_SIZE:
                self.send_error(413)
                return
        except ValueError:
            self.send_error(400)
            return

        self.track_traffic(rx=length)
        encrypted_body = self.rfile.read(length).decode("utf-8")

        try:
            decrypted_json = SECURITY.decrypt(encrypted_body)
            response_data = json.loads(decrypted_json)
        except Exception:
            self.send_error(400, "Decryption Failed")
            return

        req_id = response_data.get("id")
        if req_id in PENDING_RESPONSES:
            PENDING_RESPONSES[req_id]["data"] = response_data
            PENDING_RESPONSES[req_id]["event"].set()
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")
        else:
            self.send_response(404)
            self.end_headers()

    def handle_public_request(self):
        if not self.check_rate_limit():
            with STATS_LOCK:
                STATS["blocked_reqs"] += 1
            self.send_error(429, "Too Many Requests")
            return

        global NEXT_CLIENT_INDEX
        target_queue = None

        with CLIENT_LOCK:
            clients = list(CLIENTS.keys())
            if not clients:
                self.send_error(503, "No Secure Agents Online")
                return
            target_id = clients[NEXT_CLIENT_INDEX % len(clients)]
            target_queue = CLIENTS[target_id]["queue"]
            NEXT_CLIENT_INDEX += 1

        req_id = str(uuid.uuid4())

        length = int(self.headers.get("Content-Length", 0))
        if length > MAX_BODY_SIZE:
            self.send_error(413, "Request Too Large")
            return

        self.track_traffic(rx=length)
        body_bytes = self.rfile.read(length) if length > 0 else b""

        raw_task = {
            "id": req_id,
            "method": self.command,
            "url": self.path,
            "headers": dict(self.headers),
            "body": base64.b64encode(body_bytes).decode(),
        }

        encrypted_task = SECURITY.encrypt(json.dumps(raw_task))

        with STATS_LOCK:
            STATS["requests_processed"] += 1

        response_event = threading.Event()
        PENDING_RESPONSES[req_id] = {"event": response_event, "data": None}

        try:
            target_queue.put({"payload": encrypted_task})

            if response_event.wait(timeout=30):
                resp = PENDING_RESPONSES[req_id]["data"]
                self.send_response(resp["status"])
                for k, v in resp.get("headers", {}).items():
                    if k.lower() not in [
                        "date",
                        "server",
                        "content-encoding",
                        "transfer-encoding",
                    ]:
                        self.send_header(k, v)
                self.end_headers()
                if resp.get("body"):
                    data = base64.b64decode(resp["body"])
                    self.wfile.write(data)
                    self.track_traffic(tx=len(data))
            else:
                self.send_error(504, "Timeout")
        finally:
            if req_id in PENDING_RESPONSES:
                del PENDING_RESPONSES[req_id]

    def broadcast_client_list(self):
        with CLIENT_LOCK:
            active_clients = list(CLIENTS.keys())
        system_msg = {
            "type": "system_update",
            "event": "client_list",
            "clients": active_clients,
        }
        encrypted_msg = SECURITY.encrypt(json.dumps(system_msg))
        with CLIENT_LOCK:
            for _cid, data in CLIENTS.items():
                try:
                    data["queue"].put({"payload": encrypted_msg})
                except Exception:
                    pass

    def do_PUT(self):
        self.handle_public_request()

    def do_DELETE(self):
        self.handle_public_request()

    def do_PATCH(self):
        self.handle_public_request()


def run_server(port=8000, secret="default-secret"):
    global SECURITY, GATEKEEPER_PIN
    SECURITY = SecurityLayer(secret)
    GATEKEEPER_PIN = secrets.token_hex(3).upper()

    server = ThreadedHTTPServer(("", port), BridgeRequestHandler)
    print("\n🌉 Gesher Secure Server")
    print("--------------------------------")
    print(f"📍 Port:       {port}")
    print(f"🛡️  PIN:        {GATEKEEPER_PIN}")
    print("📊 Dashboard:  Run 'gesher client' to view local stats.")
    print("--------------------------------\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()


if __name__ == "__main__":
    run_server()
