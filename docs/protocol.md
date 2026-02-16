# 📡 Gesher Wire Protocol

This document specifies the communication protocol between the Gesher Server (Gateway) and the Gesher Client (Connector).

The protocol is designed to be **Firewall-Friendly** (outbound HTTP only) and **Zero-Trust** (all payloads are encrypted).

---

## 🔐 Security Primitives

All communication relies on two shared secrets:
1.  **`SHARED_SECRET`**: Used for AES-256 encryption and HMAC signatures. Never sent over the wire.
2.  **`GATEKEEPER_PIN`**: A session-specific token sent in headers to authorize the connection.

### Encryption (The "Gibberish" Layer)
* **Algorithm:** Fernet (AES-128 in CBC mode + HMAC-SHA256).
* **Key Derivation:** `SHA256(SHARED_SECRET) -> Base64 encoded`.
* **Payloads:** All HTTP bodies in this protocol (except the initial handshake response) are base64-encoded Fernet tokens.

---

## 1. Connection Handshake

The Client initiates a long-lived HTTP POST request to establish the tunnel.

**Endpoint:** `POST /_connect_tunnel`

**Headers:**
* `Authorization`: `TIMESTAMP:SIGNATURE`
    * `TIMESTAMP`: Current Unix time (seconds).
    * `SIGNATURE`: `HMAC_SHA256(SHARED_SECRET, TIMESTAMP)`.
* `X-Join-Code`: The active `GATEKEEPER_PIN`.
* `X-Client-ID`: (Optional) Client identifier.

**Response (Success):**
* **Status:** `200 OK`
* **Content-Type:** `application/x-ndjson` (Newline Delimited JSON)
* **Body:** An infinite stream of JSON objects. Each line is a "Task".

**Response (Failure):**
* `401 Unauthorized`: Invalid PIN.
* `403 Forbidden`: Invalid HMAC Signature or Replay Attack detected.
* `429 Too Many Requests`: Rate limit exceeded.

---

## 2. The Tunneling Loop

Once connected, the Server pushes **Encrypted Tasks** to the Client via the open connection.

### A. Server -> Client (The Request)
The Server sends a JSON object on a new line.

**Structure (Decrypted):**
```json
{
  "id": "uuid-v4",
  "method": "GET",
  "url": "/api/users?id=1",
  "headers": {
    "User-Agent": "Mozilla/5.0...",
    "Accept": "application/json"
  },
  "body": "base64_encoded_body_content"
}

```

**Wire Format:**

```json
{"payload": "gAAAAABl..."} // Encrypted Fernet Token

```

### B. Client -> Server (The Response)

The Client executes the request locally (e.g., against `localhost:3000`) and posts the result back.

**Endpoint:** `POST /_tunnel_response`

**Structure (Decrypted):**

```json
{
  "id": "uuid-v4", // Must match the Request ID
  "status": 200,
  "headers": {
    "Content-Type": "application/json",
    "Server": "MyLocalApp"
  },
  "body": "base64_encoded_response_content"
}

```

**Wire Format:**
The body of the POST request is the raw Encrypted Fernet Token (string).

---

## 3. System Events

The Server may push system-level events to the Client via the same open connection. These allow the Client to be aware of the wider network mesh.

**Event Structure (Decrypted):**

```json
{
  "type": "system_update",
  "event": "client_list",
  "clients": ["id_1", "id_2", "id_3"]
}

```

---

## 4. Monitoring API (Local-First)

The Server does **not** expose a UI. Instead, the Client fetches raw stats securely and renders them locally.

**Endpoint:** `POST /_sys/sync_stats`

**Headers:** Same as Handshake (`Authorization` + `X-Join-Code`).

**Response:**

* **Body:** Encrypted Fernet Token containing:
```json
{
  "uptime": 120.5,
  "requests": 1500,
  "tx": 1048576,
  "rx": 524288,
  "clients": [
      {"id": "abc-123", "ip": "203.0.113.1"}
  ]
}

```