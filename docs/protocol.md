# 📡 Gesher Wire Protocol

This document specifies the communication protocol between the Gesher Server (Gateway) and the Gesher Client (Connector).

The protocol is designed to be **Firewall-Friendly** (outbound HTTP only) and **Zero-Trust** (all payloads are encrypted).

---

## 🔐 Security Primitives

All communication relies on two shared secrets:
1.  **`SHARED_SECRET`**: Used for Fernet encryption (AES-128) and HMAC signatures. Never sent over the wire.
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
* `Authorization`: `TIMESTAMP:NONCE.SIGNATURE`
    * `TIMESTAMP`: Current Unix time (seconds).
    * `NONCE`: A random hex string (at most 64 characters), new for every request, so that two requests in the same second never share a signature.
    * `SIGNATURE`: `HMAC_SHA256(SHARED_SECRET, TIMESTAMP + "." + NONCE)`.
    * The legacy form `TIMESTAMP:SIGNATURE`, with `SIGNATURE = HMAC_SHA256(SHARED_SECRET, TIMESTAMP)`, is still accepted.
* `X-Join-Code`: The active `GATEKEEPER_PIN`.

**Response (Success):**
* **Status:** `200 OK`
* **X-Client-ID:** The identifier the Server assigned to this Client.
* **Content-Type:** `application/x-ndjson` (Newline Delimited JSON)
* **Transfer-Encoding:** `chunked`. Every Task is sent as its own chunk, so the Client receives it as soon as it is sent, whatever its size.
* **Body:** An infinite stream of JSON objects. Each line is a "Task".
* **Keepalive:** While no Task is sent, the Server writes an empty line every 15 seconds. The Client ignores empty lines and drops the connection and reconnects after 45 seconds of silence.

**Response (Failure):**
* `401 Unauthorized`: Invalid PIN.
* `403 Forbidden`: Invalid HMAC Signature or Replay Attack detected.
* `429 Too Many Requests`: Rate limit exceeded.
* `503 Service Unavailable`: The Server already has the maximum of 50 connected Clients (`Server Full`).

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

**Request Methods:** The Server forwards `GET`, `POST`, `PUT`, `DELETE`, `PATCH`, `HEAD` and `OPTIONS` requests. Any other method is answered with `501`. The answer to a `HEAD` request carries the `Content-Length` of the local service and no body.

**Upgrades:** A public request that has an `Upgrade` header (WebSocket, `h2c`) is answered with `501` at once and is not forwarded, because a Task carries exactly one request and one response.

**Request Body:** A public request sent with `Transfer-Encoding: chunked` is read to the end by the Server (up to 10 MB) and forwarded with a plain `Content-Length` instead.

**Request Path:** `url` always starts with `/`. The Server answers `400 Bad Request` to a public request whose path does not, and the Client does not forward such a task: it answers it with a `400` response instead.

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
  "body": "base64_encoded_response_content",
  "set_cookies": ["a=1; Path=/", "b=2; Path=/"] // Optional, every Set-Cookie header of the response
}

```

**Wire Format:**
The body of the POST request is the raw Encrypted Fernet Token (string).

If the local service cannot be reached the Client answers with status `502`, and if it does not answer within 25 seconds with status `504`, using the same endpoint, so the public request ends at once instead of waiting for the Server timeout.

**Responses:**
* `200 OK`: The response was delivered to the waiting request.
* `400 Bad Request`: The body is not valid UTF-8, cannot be decrypted, or is not a response object with a string `id`, an integer `status` from 100 to 599, string `headers` and a base64 `body`.
* `404 Not Found`: No request with that `id` is waiting.

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
