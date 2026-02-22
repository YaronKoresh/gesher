# 🌉 Gesher

**Gesher** (Hebrew for *Bridge*) is a secure, self-hosted, pure-Python HTTP tunneling system. It allows you to expose local web servers to the internet or a private network without opening ports or configuring firewalls. Built with a "Security-First" philosophy, Gesher ensures your data is protected by multiple layers of encryption and authorization.

---

## ✨ Key Features

* **🔒 End-to-End Encryption:** All traffic between the Client and Server is encrypted using **Fernet (AES-128-CBC + HMAC-SHA256)**. Even if SSL is stripped, the payload remains "gibberish" to attackers.
* **🛡️ The "Triple-Lock" Security Model:**
* **HMAC-SHA256 Signatures:** Prevents unauthorized command injection; the secret is never sent over the wire.
* **Replay Protection:** Blocks captured request replays by tracking signatures within a time-window.
* **Gatekeeper PIN:** A session-specific code required to join the network, serving as a 2FA layer for your tunnel.


* **⚖️ Load Balancing:** Connect multiple clients to a single server to create a high-availability cluster using **Round-Robin** distribution.
* **📊 Local-First Monitoring:** A real-time dashboard that runs **only on your local machine**, fetching encrypted stats from the server for maximum privacy.
* **🌍 One-Click Public URL:** Integrated `cloudflared` support to instantly generate a public HTTPS URL on Windows, macOS, or Linux.

---

## 🚀 Installation

### Prerequisites

* Python 3.8+

### Install from Source

```bash
git clone https://github.com/YaronKoresh/gesher.git
cd gesher
pip install .

```

---

## 📖 Quick Start

### 1. Start the Bridge Server

Run this on your public-facing machine (e.g., a VPS or a cloud instance).

```bash
gesher server --port 8000 --secret "your-long-secret-key"

```

**Output:**

```text
🌉 Gesher Secure Server
--------------------------------
📍 Port:       8000
🛡️  PIN:        7A9F2B
📊 Dashboard:  Run 'gesher client' to view local stats.
--------------------------------
```

*Note the **PIN** (`7A9F2B`). You will need this to connect your clients.*

### 2. Start the Local Connector (Client)

Run this on your local machine where your web app (e.g., `localhost:3000`) is running.

```bash
gesher client --gateway http://<server-ip>:8000 --secret "your-long-secret-key" \
  --pin 7A9F2B \
  --target http://localhost:3000
```

### 3. Access the Dashboard

Open your browser to `http://localhost:9000` (the default `dashboard-port`). You will see live traffic stats and the status of all connected peers in your private bridge.

---

## ⚙️ Command Line Options

### Server Mode

| Flag | Description | Default |
| --- | --- | --- |
| `--secret` | The shared encryption/auth secret. | *Required* |
| `--port` | Port to listen on for public requests. | `8000` |
| `--public` | Automatically start a Cloudflare tunnel for a public URL. | `False` |

### Client Mode

| Argument/Flag | Description | Default |
| --- | --- | --- |
| `--gateway` | The URL of your remote Gesher server. | *Required* |
| `--secret` | The shared encryption/auth secret. | *Required* |
| `--pin` | The session PIN shown on the server console. | *Required* |
| `--target` | Your local service URL (where traffic is sent). | `http://localhost:8080` |
| `--dashboard-port` | Port to host the local-only monitor UI. | `9000` |

---

## 🛠️ Project Structure

* **`gesher/server.py`**: The "Dark Server" that manages tunnels and load balancing.
* **`gesher/client.py`**: The connector that executes local requests and hosts the UI.
* **`gesher/security.py`**: The core cryptographic engine handling AES and HMAC.
* **`gesher/cli.py`**: The entry point and automation for `cloudflared` installation.

---

## ⚖️ License & Usage (IMPORTANT)

This project is released under the **Universal Copyleft Source License (UCSL-1.0)**. Please read the following carefully before integrating this code into your projects:

* **✅ Free for Open Source, Personal & Commercial Use:** You are absolutely free to use, modify, distribute, and even monetize this software, *provided* that your project is fully open-source and complies with the UCSL-1.0 terms.
* **⚠️ Strict Copyleft (Viral License):** If you integrate, import, link (statically or dynamically), or bundle this code into your own application, your **entire combined project** becomes a derivative work. You will be legally required to release your entire source code to the public under the exact same UCSL-1.0 terms.
* **💼 Closed-Source / Proprietary License:** Want to use this software in a proprietary, closed-source product without being forced to open-source your own codebase? **Contact me** to arrange a separate commercial license.

For the full legal terms, see the [LICENSE](./LICENSE) file.
