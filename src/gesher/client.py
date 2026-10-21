import base64
import http.server
import json
import logging
import threading
import time

import requests

from .security import SecurityLayer

logging.basicConfig(
    level=logging.INFO, format="[%(asctime)s] %(message)s", datefmt="%H:%M:%S"
)
logger = logging.getLogger("SecureClient")

SECURITY = None

LOCAL_CONNECT_TIMEOUT = 5
LOCAL_READ_TIMEOUT = 25
GATEWAY_POST_TIMEOUT = 15

DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>Gesher Local Monitor</title>
    <style>
        body { font-family: sans-serif; background: #111; color: #eee; padding: 20px; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; }
        .card { background: #222; padding: 20px; border-radius: 8px; border: 1px solid #333; }
        .val { font-size: 24px; font-weight: bold; color: #4CAF50; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        td, th { text-align: left; padding: 10px; border-bottom: 1px solid #333; }
        h1 { color: #4CAF50; }
    </style>
</head>
<body>
    <div style="max-width: 800px; margin: 0 auto;">
        <div style="display:flex; justify-content:space-between; align-items:center;">
            <h1>🌉 Gesher Local Monitor</h1>
            <div style="color: #666;">Connected to Remote Gateway</div>
        </div>

        <div class="grid">
            <div class="card"><div>Uptime</div><div class="val" id="uptime">-</div></div>
            <div class="card"><div>Clients</div><div class="val" id="clients">-</div></div>
            <div class="card"><div>Requests</div><div class="val" id="reqs">-</div></div>
            <div class="card"><div>Traffic</div><div class="val" id="traffic">-</div></div>
        </div>

        <div class="card" style="margin-top: 20px;">
            <h3>🔌 Network Mesh</h3>
            <table id="table"><tbody></tbody></table>
        </div>
    </div>
    <script>
        async function update() {
            try {
                const res = await fetch('/api/stats');
                const data = await res.json();

                document.getElementById('uptime').innerText = Math.floor(data.uptime / 60) + 'm';
                document.getElementById('clients').innerText = data.clients.length;
                document.getElementById('reqs').innerText = data.requests;
                document.getElementById('traffic').innerText = (data.tx/1024/1024).toFixed(2) + ' MB';

                const tbody = document.querySelector('#table tbody');
                tbody.innerHTML = '';

                data.clients.forEach(c => {
                    let row = tbody.insertRow();
                    row.insertCell(0).innerText = c.id;
                    row.insertCell(1).innerText = c.ip;
                    let statusCell = row.insertCell(2);
                    statusCell.innerText = "Active";
                    statusCell.style.color = "#4CAF50";
                });
            } catch(e) { console.error(e); }
        }
        setInterval(update, 2000);
        update();
    </script>
</body>
</html>
"""


def run_local_dashboard(port, gateway_url, pin):

    class LocalDashHandler(http.server.BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            _junk = [format, args]
            return

        def do_GET(self):
            if self.path == "/":
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(DASHBOARD_HTML.encode())

            elif self.path == "/api/stats":
                try:
                    resp = requests.post(
                        f"{gateway_url}/_sys/sync_stats",
                        headers={
                            "Authorization": SECURITY.get_auth_header(),
                            "X-Join-Code": pin,
                        },
                        timeout=5,
                    )
                    if resp.status_code == 200:
                        decrypted_json = SECURITY.decrypt(resp.text)
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.end_headers()
                        self.wfile.write(decrypted_json.encode())
                    else:
                        self.send_error(resp.status_code)
                except Exception:
                    self.send_error(500)
            else:
                self.send_error(404)

    logger.info(f"📊 Local Dashboard running at http://localhost:{port}")
    http.server.HTTPServer(
        ("localhost", port), LocalDashHandler
    ).serve_forever()


def is_valid_task_url(url):
    if not isinstance(url, str) or not url.startswith("/"):
        return False
    return not any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in url)


def post_gateway_response(gateway_url, task_id, status, headers, content):
    response_data = {
        "id": task_id,
        "status": status,
        "headers": headers,
        "body": base64.b64encode(content).decode("utf-8"),
    }

    encrypted_response = SECURITY.encrypt(json.dumps(response_data))

    requests.post(
        f"{gateway_url}/_tunnel_response",
        data=encrypted_response,
        headers={"Authorization": SECURITY.get_auth_header()},
        timeout=GATEWAY_POST_TIMEOUT,
    )


def handle_task(encrypted_payload, local_target, gateway_url):
    try:
        try:
            decrypted_json = SECURITY.decrypt(encrypted_payload)
            task = json.loads(decrypted_json)
        except Exception:
            logger.error("🛑 Received invalid/corrupted encrypted block.")
            return

        if task.get("type") == "system_update":
            if task.get("event") == "client_list":
                clients = task.get("clients", [])
                logger.info(f"👥 Network Update: Connected Peers: {clients}")
            return

        if not is_valid_task_url(task["url"]):
            logger.error("🛑 Rejected a task with an invalid request path.")
            post_gateway_response(
                gateway_url,
                task["id"],
                400,
                {"Content-Type": "text/plain"},
                b"Bad Request Target",
            )
            return

        logger.info(f"📥 Processing: {task['method']} {task['url']}")

        try:
            resp = requests.request(
                method=task["method"],
                url=f"{local_target}{task['url']}",
                headers=task.get("headers"),
                data=base64.b64decode(task["body"])
                if task.get("body")
                else None,
                allow_redirects=False,
                timeout=(LOCAL_CONNECT_TIMEOUT, LOCAL_READ_TIMEOUT),
            )
        except requests.exceptions.Timeout as e:
            logger.error(f"❌ Local Service Timeout: {e}")
            post_gateway_response(
                gateway_url,
                task["id"],
                504,
                {"Content-Type": "text/plain"},
                b"Local Service Timeout",
            )
            return
        except Exception as e:
            logger.error(f"❌ Local Service Error: {e}")
            post_gateway_response(
                gateway_url,
                task["id"],
                502,
                {"Content-Type": "text/plain"},
                b"Local Service Unavailable",
            )
            return

        post_gateway_response(
            gateway_url,
            task["id"],
            resp.status_code,
            dict(resp.headers),
            resp.content,
        )
        logger.info("📤 Response Sent (Encrypted)")

    except Exception as e:
        logger.error(f"Critical Worker Error: {e}")


def start_connector(gateway_url, secret, local_target, pin, dashboard_port):
    global SECURITY
    SECURITY = SecurityLayer(secret)

    dash_thread = threading.Thread(
        target=run_local_dashboard, args=(dashboard_port, gateway_url, pin)
    )
    dash_thread.daemon = True
    dash_thread.start()

    while True:
        try:
            logger.info(f"🔐 Initiating Secure Handshake with {gateway_url}...")

            with requests.post(
                f"{gateway_url}/_connect_tunnel",
                headers={
                    "Authorization": SECURITY.get_auth_header(),
                    "X-Join-Code": pin,
                },
                stream=True,
                timeout=None,
            ) as r:
                if r.status_code == 401:
                    logger.critical("⛔ Gatekeeper Rejected: Invalid PIN.")
                    return
                elif r.status_code == 403:
                    logger.critical(
                        "⛔ Access Denied: Invalid Secret or Signature."
                    )
                    return
                elif r.status_code != 200:
                    logger.warning(
                        f"⚠️ Gateway Status {r.status_code}. Retrying..."
                    )
                    time.sleep(5)
                    continue

                logger.info(
                    "✅ Secure Tunnel Established. Waiting for encrypted tasks..."
                )

                for line in r.iter_lines():
                    if not line:
                        continue
                    try:
                        wrapper = json.loads(line.decode("utf-8"))
                        encrypted_payload = wrapper.get("payload")

                        if encrypted_payload:
                            t = threading.Thread(
                                target=handle_task,
                                args=(
                                    encrypted_payload,
                                    local_target,
                                    gateway_url,
                                ),
                            )
                            t.daemon = True
                            t.start()
                    except json.JSONDecodeError:
                        pass

        except requests.exceptions.ConnectionError:
            logger.warning("❌ Connection Lost. Reconnecting in 5s...")
            time.sleep(5)
        except Exception as e:
            logger.error(f"❌ Unexpected Error: {e}")
            time.sleep(5)
