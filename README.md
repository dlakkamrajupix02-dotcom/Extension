# Payload Shield

> **Threat Model & Security Notice**: Payload Shield is an application-layer response payload encryption library for FastAPI and React. Its purpose is to raise the cost of casual scraping, prevent naive automated scripts from fetching unencrypted JSON API responses without executing JavaScript, and obscure response bodies in proxy network logs.
>
> **What it DOES NOT protect against**:
> - Authenticated users inspecting browser DevTools or application memory within their own session.
> - Cross-Site Scripting (XSS) attacks (if an attacker can execute arbitrary JS, they can access stored keys).
> - Motivated reverse engineers who inspect client bundles to reimplement the ECDH handshake protocol.
>
> Payload Shield **MUST** be layered on top of HTTPS/TLS, and does **NOT** replace standard authentication, authorization, or transport security.

---

## Key Features

- **X25519 ECDH Key Exchange**: Session symmetric keys are derived via ECDH key agreement. The symmetric key never travels over the network wire.
- **Session-Bound HKDF-SHA256**: Derived keys are cryptographically bound to server-authenticated session IDs.
- **AES-256-GCM Encryption**: Every response payload is encrypted using a fresh 12-byte random nonce with AEAD tamper protection.
- **Server-Side Session Store**: Supported by Redis with TTL expiration and immediate server-side key invalidation on logout.
- **Pluggable React Key Storage**: Supports `sessionStorage` (default), `memory`, and `localStorage` (with explicit XSS warning).
- **FastAPI Integration**: Simple `handle_handshake`, `handle_logout`, `PayloadShieldDependency` for per-route protection, and `PayloadShieldMiddleware` for blanket application encryption.

---

## Installation

### Backend (Python / FastAPI)

```bash
pip install payload-shield
# or
uv add payload-shield
```

### Frontend (React / TypeScript)

```bash
npm install payload-shield-client
# or
yarn add payload-shield-client
```

---

## Quickstart

### 1. Backend Integration (FastAPI)

```python
from fastapi import FastAPI, Request, Depends
from payload_shield import (
    SessionStore,
    PayloadShieldMiddleware,
    HandshakeRequest,
    HandshakeResponse,
    handle_handshake,
    handle_logout,
)

app = FastAPI()
session_store = SessionStore(redis_url="redis://localhost:6379/0")

# Blanket middleware with excluded paths
app.add_middleware(
    PayloadShieldMiddleware,
    session_store=session_store,
    exclude_paths=["/api/login", "/api/handshake", "/api/logout", "/docs"]
)

@app.post("/api/login")
def login(username: str):
    # Authenticate user and issue server-side session_id
    session_id = "sess_12345"
    return {"session_id": session_id}

@app.post("/api/handshake", response_model=HandshakeResponse)
def handshake(req: HandshakeRequest):
    return handle_handshake(req, session_store)

@app.post("/api/logout")
def logout(request: Request):
    session_id = request.headers.get("X-Payload-Shield-Session")
    if session_id:
        handle_logout(session_id, session_store)
    return {"status": "logged_out"}

@app.get("/api/user-profile")
def get_user_profile():
    # Response JSON payload is automatically encrypted by middleware
    return {"name": "Alice", "secret": "token_123"}
```

### 2. Frontend Integration (React)

```tsx
import React, { useState } from 'react';
import { PayloadShieldProvider, useEncryptedFetch, usePayloadShield } from 'payload-shield-client';

function Dashboard() {
  const { fetch: encryptedFetch } = useEncryptedFetch();
  const { logout } = usePayloadShield();
  const [data, setData] = useState(null);

  const loadData = async () => {
    const res = await encryptedFetch('http://localhost:8000/api/user-profile');
    if (res.ok) {
      const json = await res.json();
      setData(json);
    }
  };

  return (
    <div>
      <button onClick={loadData}>Load Profile</button>
      <button onClick={() => logout()}>Logout</button>
      {data && <pre>{JSON.stringify(data, null, 2)}</pre>}
    </div>
  );
}

export function App() {
  const [sessionId, setSessionId] = useState<string | null>("sess_12345");

  if (!sessionId) return <div>Please Log In</div>;

  return (
    <PayloadShieldProvider baseUrl="http://localhost:8000" sessionId={sessionId}>
      <Dashboard />
    </PayloadShieldProvider>
  );
}
```

---

## Package Compatibility Matrix

| `payload-shield` (PyPI) | `payload-shield-client` (npm) | Compatibility Status |
| :--- | :--- | :--- |
| `v0.1.x` | `v0.1.x` | Fully Compatible |

---

## Security & Threat Model

For expanded technical security boundaries, see [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) and [`docs/SECURITY.md`](docs/SECURITY.md).
