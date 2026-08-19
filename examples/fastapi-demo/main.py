"""
FastAPI Demo Application for Payload Shield.

Demonstrates:
1. Server-side session creation at `/api/login`.
2. Key exchange handshake at `/api/handshake`.
3. Encrypted API route `/api/user-profile` returning base64 AES-256-GCM ciphertext to network tab.
4. Server-side key invalidation at `/api/logout`.
5. Public un-encrypted endpoint `/api/public`.

Threat Model Notice:
This app demonstrates payload encryption in transit over HTTPS to deter casual scraping
via browser DevTools Network tab.
Does NOT protect against logged-in users inspecting memory in their browser session.
"""

import uuid
from fastapi import FastAPI, Depends, Request, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from payload_shield import (
    SessionStore,
    PayloadShieldDependency,
    PayloadShieldMiddleware,
    HandshakeRequest,
    HandshakeResponse,
    handle_handshake,
    handle_logout,
)

app = FastAPI(title="Payload Shield FastAPI Demo")

# Configure CORS for local React demo
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize SessionStore (backed by Redis or in-memory fallback)
session_store = SessionStore(use_memory_fallback=True)

# Register PayloadShieldMiddleware with route exclusion list
app.add_middleware(
    PayloadShieldMiddleware,
    session_store=session_store,
    exclude_paths=["/api/login", "/api/handshake", "/api/logout", "/api/public", "/docs", "/openapi.json"]
)

# Active mock server sessions database
active_sessions = set()


class LoginRequest(BaseModel):
    username: str


class LoginResponse(BaseModel):
    session_id: str
    message: str


@app.post("/api/login", response_model=LoginResponse)
def login(req: LoginRequest):
    """
    Simulate user authentication and server-side session issuance.
    """
    if not req.username:
        raise HTTPException(status_code=400, detail="Username is required.")
    
    session_id = f"sess_{uuid.uuid4().hex[:12]}"
    active_sessions.add(session_id)
    return LoginResponse(session_id=session_id, message="Login successful. Use session_id for handshake.")


def validate_session(session_id: str) -> bool:
    """Session validator verifying session_id was issued server-side."""
    return session_id in active_sessions


@app.post("/api/handshake", response_model=HandshakeResponse)
def handshake(req: HandshakeRequest):
    """
    Perform ECDH key exchange and bind symmetric key to authenticated session.
    """
    return handle_handshake(req, session_store, session_validator=validate_session)


@app.post("/api/logout")
def logout(request: Request):
    """
    Invalidate session key server-side in SessionStore on logout.
    """
    session_id = request.headers.get("X-Payload-Shield-Session")
    if session_id:
        if session_id in active_sessions:
            active_sessions.remove(session_id)
        handle_logout(session_id, session_store)
    return {"status": "success", "message": "Logged out. Key invalidated server-side."}


@app.get("/api/user-profile")
def get_user_profile(request: Request):
    """
    Protected route: response body is automatically encrypted by PayloadShieldMiddleware.
    Raw JSON in Network tab will show base64 ciphertext & nonce.
    """
    session_id = getattr(request.state, "payload_shield_session_id", "unknown")
    return {
        "user_id": 1001,
        "username": "Alice Security",
        "email": "alice@payloadshield.org",
        "role": "Lead Architect",
        "sensitive_data": {
            "account_balance": "$125,450.00",
            "api_key_secret": "sk_live_998877665544332211",
            "active_session": session_id,
        }
    }


@app.get("/api/public")
def public_data():
    """
    Public unencrypted endpoint.
    """
    return {"status": "ok", "notice": "This endpoint is public and unencrypted."}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)

