import base64
import collections
import hmac
import http.server
import ipaddress
import json
import logging
import queue
import secrets
import select
import socket
import socketserver
import sys
import threading
import time
import uuid

from .security import SIGNATURE_WINDOW_SECONDS, SecurityLayer

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
SEEN_SIGNATURE_TTL = 2 * SIGNATURE_WINDOW_SECONDS + 2


REQUEST_TIMEOUT = 30
MAX_CLIENTS = 50
MAX_BODY_SIZE = 10 * 1024 * 1024
MAX_CHUNK_LINE = 1024
RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX_REQ = 100
IP_REQUEST_COUNTS = collections.defaultdict(list)
IP_LOCK = threading.Lock()


AUTH_FAILURES = collections.defaultdict(list)
MAX_AUTH_FAILURES = 5
AUTH_FAILURE_WINDOW = 120
LAST_RATE_PRUNE = 0.0
AUTH_LOCKOUT_DURATION = 600


STATS = {
    "start_time": time.time(),
    "requests_processed": 0,
    "bytes_tx": 0,
    "bytes_rx": 0,
    "blocked_reqs": 0,
}
STATS_LOCK = threading.Lock()


DISCONNECT_CHECK_INTERVAL = 0.5
KEEPALIVE_INTERVAL = 15


class SystemTask(dict):
    pass


def redistribute_task(task):
    global NEXT_CLIENT_INDEX
    if isinstance(task, SystemTask):
        return False
    with CLIENT_LOCK:
        queues = [data["queue"] for data in CLIENTS.values()]
        if not queues:
            return False
        target = queues[NEXT_CLIENT_INDEX % len(queues)]
        NEXT_CLIENT_INDEX += 1
    target.put(task)
    return True


DROPPED_RESPONSE_HEADERS = frozenset(
    [
        "date",
        "server",
        "content-encoding",
        "content-length",
        "transfer-encoding",
        "connection",
        "keep-alive",
        "proxy-connection",
        "te",
        "trailer",
        "upgrade",
    ]
)


def prune_rate_state(now):
    global LAST_RATE_PRUNE
    if now - LAST_RATE_PRUNE < RATE_LIMIT_WINDOW:
        return
    LAST_RATE_PRUNE = now
    for ip in list(IP_REQUEST_COUNTS):
        if not any(now - t < RATE_LIMIT_WINDOW for t in IP_REQUEST_COUNTS[ip]):
            del IP_REQUEST_COUNTS[ip]
    for ip in list(AUTH_FAILURES):
        if not any(now - t < AUTH_FAILURE_WINDOW for t in AUTH_FAILURES[ip]):
            del AUTH_FAILURES[ip]


def with_forwarded_for(headers, address):
    name = "X-Forwarded-For"
    existing = None
    result = {}
    for key, item in headers.items():
        if key.lower() == "x-forwarded-for":
            name = key
            existing = item if not existing else f"{existing}, {item}"
        else:
            result[key] = item
    if not existing:
        value = address
    else:
        parts = [part.strip() for part in existing.split(",")]
        value = existing if parts[-1] == address else f"{existing}, {address}"
    result[name] = value
    return result


def pin_matches(candidate):
    if not isinstance(candidate, str) or not candidate or not GATEKEEPER_PIN:
        return False
    return hmac.compare_digest(
        candidate.encode("utf-8"), GATEKEEPER_PIN.encode("utf-8")
    )


def frame_chunk(data):
    return b"%x\r\n" % len(data) + data + b"\r\n"


def valid_tunnel_response(data):
    if not isinstance(data, dict) or not isinstance(data.get("id"), str):
        return False
    status = data.get("status")
    if isinstance(status, bool) or not isinstance(status, int):
        return False
    if not 100 <= status <= 599:
        return False
    headers = data.get("headers", {})
    if not isinstance(headers, dict):
        return False
    for key, value in headers.items():
        if not isinstance(key, str) or not isinstance(value, str):
            return False
    cookies = data.get("set_cookies", [])
    if not isinstance(cookies, list):
        return False
    if not all(isinstance(c, str) for c in cookies):
        return False
    body = data.get("body", "")
    if body is None or body == "":
        return True
    if not isinstance(body, str):
        return False
    try:
        base64.b64decode(body, validate=True)
    except Exception:
        return False
    return True


class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


class BridgeRequestHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = REQUEST_TIMEOUT
    server_version = "gesher"
    sys_version = ""

    def version_string(self):
        return self.server_version

    def log_request(self, code="-", size="-"):
        _junk = [code, size]
        pass

    def read_content_length(self):
        raw = self.headers.get("Content-Length", "0")
        try:
            length = int(raw)
        except ValueError:
            length = -1
        if length < 0:
            self.send_error(400, "Bad Content-Length")
            return None
        if length > MAX_BODY_SIZE:
            self.send_error(413)
            return None
        return length

    def is_chunked_request(self):
        encoding = self.headers.get("Transfer-Encoding")
        return isinstance(encoding, str) and "chunked" in encoding.lower()

    def read_chunked_body(self):
        body = bytearray()
        while True:
            line = self.rfile.readline(MAX_CHUNK_LINE)
            try:
                size = int(line.split(b";", 1)[0].strip(), 16)
            except ValueError:
                size = -1
            if size < 0:
                self.send_error(400, "Bad Chunk Size")
                return None
            if size == 0:
                while True:
                    trailer = self.rfile.readline(MAX_CHUNK_LINE)
                    if trailer in (b"\r\n", b"\n", b""):
                        return bytes(body)
            if len(body) + size > MAX_BODY_SIZE:
                self.send_error(413)
                return None
            chunk = self.rfile.read(size)
            if len(chunk) != size:
                self.send_error(400, "Truncated Chunk")
                return None
            body += chunk
            self.rfile.readline(MAX_CHUNK_LINE)

    def remote_ip(self):
        peer = self.client_address[0]
        try:
            is_local = ipaddress.ip_address(peer).is_loopback
        except ValueError:
            is_local = False
        if not is_local:
            return peer
        forwarded = self.headers.get("CF-Connecting-IP")
        if not isinstance(forwarded, str):
            return peer
        try:
            return str(ipaddress.ip_address(forwarded.strip()))
        except ValueError:
            return peer

    def check_rate_limit(self):
        client_ip = self.remote_ip()
        now = time.time()

        with IP_LOCK:
            prune_rate_state(now)

            timestamps = [
                t
                for t in IP_REQUEST_COUNTS.get(client_ip, [])
                if now - t < RATE_LIMIT_WINDOW
            ]

            if len(timestamps) >= RATE_LIMIT_MAX_REQ:
                IP_REQUEST_COUNTS[client_ip] = timestamps
                return False

            timestamps.append(now)
            IP_REQUEST_COUNTS[client_ip] = timestamps

            failures = [
                t
                for t in AUTH_FAILURES.get(client_ip, [])
                if now - t < AUTH_FAILURE_WINDOW
            ]
            if failures:
                AUTH_FAILURES[client_ip] = failures
            else:
                AUTH_FAILURES.pop(client_ip, None)

            if len(failures) >= MAX_AUTH_FAILURES:
                return False

            return True

    def record_auth_failure(self):
        client_ip = self.remote_ip()
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
        if not pin_matches(client_pin):
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

        payload = encrypted_payload.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

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
                k
                for k, t in SEEN_SIGNATURES.items()
                if current_time - t > SEEN_SIGNATURE_TTL
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
        if not pin_matches(client_pin):
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
                "address": (self.remote_ip(), self.client_address[1]),
            }

        self.broadcast_client_list()

        self.send_response(200)
        self.send_header("Content-Type", "application/x-ndjson")
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("X-Client-ID", client_id)
        self.end_headers()

        pending = None
        last_write = time.monotonic()
        try:
            while True:
                try:
                    task = client_queue.get(timeout=DISCONNECT_CHECK_INTERVAL)
                except queue.Empty:
                    if self.client_disconnected():
                        break
                    if time.monotonic() - last_write >= KEEPALIVE_INTERVAL:
                        self.wfile.write(frame_chunk(b"\n"))
                        self.wfile.flush()
                        last_write = time.monotonic()
                    continue
                pending = task
                if self.client_disconnected():
                    break
                json_str = json.dumps(task) + "\n"
                data = json_str.encode("utf-8")
                self.wfile.write(frame_chunk(data))
                self.wfile.flush()
                self.track_traffic(tx=len(data))
                last_write = time.monotonic()
                pending = None
        except Exception:
            pass
        finally:
            with CLIENT_LOCK:
                if client_id in CLIENTS:
                    del CLIENTS[client_id]
            logger.info(f"👋 Client Disconnected: {client_id}")
            leftovers = [] if pending is None else [pending]
            while True:
                try:
                    leftovers.append(client_queue.get_nowait())
                except queue.Empty:
                    break
            for task in leftovers:
                redistribute_task(task)
            self.broadcast_client_list()

    def client_disconnected(self):
        try:
            readable, _, _ = select.select([self.connection], [], [], 0)
            if not readable:
                return False
            return self.connection.recv(1, socket.MSG_PEEK) == b""
        except (OSError, ValueError):
            return True

    def handle_tunnel_response(self):
        if not self.verify_signature():
            self.send_error(403)
            return

        length = self.read_content_length()
        if length is None:
            return

        self.track_traffic(rx=length)

        try:
            encrypted_body = self.rfile.read(length).decode("utf-8")
            decrypted_json = SECURITY.decrypt(encrypted_body)
            response_data = json.loads(decrypted_json)
        except Exception:
            self.send_error(400, "Decryption Failed")
            return

        if not valid_tunnel_response(response_data):
            self.send_error(400, "Malformed Response")
            return

        req_id = response_data["id"]
        pending = PENDING_RESPONSES.get(req_id)
        if pending is not None:
            pending["data"] = response_data
            pending["event"].set()
            self.send_response(200)
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"OK")
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def handle_public_request(self):
        if not self.check_rate_limit():
            with STATS_LOCK:
                STATS["blocked_reqs"] += 1
            self.send_error(429, "Too Many Requests")
            return

        if not self.path.startswith("/"):
            self.send_error(400, "Bad Request Target")
            return

        upgrade = self.headers.get("Upgrade")
        if isinstance(upgrade, str) and upgrade.strip():
            self.send_error(501, "Upgrade Not Supported")
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

        request_headers = with_forwarded_for(
            dict(self.headers), self.remote_ip()
        )
        if self.is_chunked_request():
            body_bytes = self.read_chunked_body()
            if body_bytes is None:
                return
            self.track_traffic(rx=len(body_bytes))
            request_headers = {
                k: v
                for k, v in request_headers.items()
                if k.lower() not in ("transfer-encoding", "content-length")
            }
            request_headers["Content-Length"] = str(len(body_bytes))
        else:
            length = self.read_content_length()
            if length is None:
                return

            self.track_traffic(rx=length)
            body_bytes = self.rfile.read(length) if length > 0 else b""

        raw_task = {
            "id": req_id,
            "method": self.command,
            "url": self.path,
            "headers": request_headers,
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
                status = resp["status"]
                data = (
                    base64.b64decode(resp["body"]) if resp.get("body") else b""
                )
                self.send_response(status)
                is_head = self.command == "HEAD"
                head_length = None
                for k, v in resp.get("headers", {}).items():
                    if k.lower() not in DROPPED_RESPONSE_HEADERS:
                        self.send_header(k, v)
                    elif is_head and k.lower() == "content-length":
                        if v.isascii() and v.isdigit():
                            head_length = v
                for cookie in resp.get("set_cookies", []):
                    self.send_header("Set-Cookie", cookie)
                has_body = status >= 200 and status not in (204, 304)
                if has_body and is_head:
                    if head_length is not None:
                        self.send_header("Content-Length", head_length)
                elif has_body:
                    self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                if has_body and data and not is_head:
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
                    data["queue"].put(SystemTask({"payload": encrypted_msg}))
                except Exception:
                    pass

    def do_PUT(self):
        self.handle_public_request()

    def do_DELETE(self):
        self.handle_public_request()

    def do_PATCH(self):
        self.handle_public_request()

    def do_HEAD(self):
        self.handle_public_request()

    def do_OPTIONS(self):
        self.handle_public_request()


def run_server(port=8000, secret="default-secret"):
    global SECURITY, GATEKEEPER_PIN
    SECURITY = SecurityLayer(secret)
    GATEKEEPER_PIN = secrets.token_hex(3).upper()

    try:
        server = ThreadedHTTPServer(("", port), BridgeRequestHandler)
    except OSError as exc:
        print(
            f"\n❌ Cannot listen on port {port}: {exc.strerror or exc}\n",
            file=sys.stderr,
        )
        raise SystemExit(1) from None
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
