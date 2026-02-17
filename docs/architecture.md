# 🏗️ Gesher Architecture

Gesher is a secure, self-hosted HTTP tunneling system designed to expose local services to the internet (or a private network) without opening incoming ports.

Unlike simple reverse proxies, Gesher uses a **Client-Initiated Bridge** model, meaning the local machine dials out to the server, establishing a persistent connection that traffic flows through.

---

## 🧩 Core Components

### 1. The Bridge Server (`server.py`)
* **Role:** The public Gateway and Orchestrator.
* **Location:** Hosted on a public VPS or a central network node.
* **Responsibilities:**
    * Listens for public HTTP requests.
    * Manages the **Client Registry** (Load Balancing).
    * Enforces **DoS Protection** (Rate Limiting, IP Bans).
    * Generates the session-specific **Gatekeeper PIN**.
    * **Blind Routing:** It receives encrypted traffic and passes it to clients without being able to read the payload (if SSL is used inside the tunnel, though Gesher adds its own AES layer).

### 2. The Local Connector (`client.py`)
* **Role:** The private Worker.
* **Location:** Hosted on your local development machine or private server.
* **Responsibilities:**
    * Initiates the outbound TCP connection to the Server.
    * **Decrypts** incoming tasks from the Server.
    * Forwards the request to your local service (e.g., `localhost:3000`).
    * **Encrypts** the response and sends it back.
    * Hosts the **Local Dashboard** UI.

### 3. The Security Layer (`security.py`)
* **Role:** Shared cryptographic logic.
* **Algorithm:** Fernet (AES-128 with CBC mode + HMAC-SHA256).
* **Function:** Ensures that all traffic flowing between Client and Server is "gibberish" to any middleman.

---

## 🛡️ The "Triple-Lock" Security Model

Gesher uses a defense-in-depth approach to prevent unauthorized access.

### Layer 1: The Shared Secret (Identity)
* **What is it?** A long, permanent password stored in config/CLI args.
* **Usage:**
    * **Encryption Key Derivation:** The secret is hashed to create the AES key. Without this, the traffic is unreadable.
    * **HMAC Signing:** Every request is signed. The secret itself is **never sent** over the network.

### Layer 2: The Gatekeeper PIN (Session)
* **What is it?** A short, ephemeral 6-character code (e.g., `7A9F2B`) generated when the Server starts.
* **Usage:** Acts as "2-Factor Authentication" for the tunnel. Even if a hacker steals your Shared Secret, they cannot join the network without physically seeing the Server's console output to get the current PIN.

### Layer 3: Replay Protection (Network)
* **Mechanism:** The server tracks request signatures.
* **Rule:** If a valid signed request is intercepted and resent (Replay Attack) more than 35 seconds later—or duplicated within the window—it is instantly rejected.

---

## ⚖️ Load Balancing & High Availability

Gesher is not just a 1-to-1 tunnel; it is a **Many-to-One** cluster.

1.  **Registration:** Multiple Clients can connect to a single Server using the same credentials.
2.  **Distribution:** The Server uses a **Round-Robin** algorithm to distribute incoming public requests across all available Clients.
3.  **Failover:** If a Client disconnects, it is removed from the registry immediately. Traffic is routed to the remaining active Clients.

**Use Case:** You can run the Client on 3 different laptops. If one developer goes offline, the tunnel stays up, served by the other two.

---

## 📊 Local-First Monitoring

To maximize security, Gesher does **not** expose an Admin Dashboard on the public Server IP.

1.  **The Dark Server:** The Server has no HTML interface. It only has a secured API endpoint `/_sys/sync_stats`.
2.  **The Local Viewer:** When you run `gesher client`, it spins up a local web server (default port `9000`).
3.  **Secure Tunneling:** When you view the dashboard on `localhost:9000`, your Client securely fetches the stats from the Server, decrypts them, and renders them locally.

**Benefit:** An attacker scanning your public Server IP sees nothing. Only an authenticated Client can view the traffic stats.
