"""
Integration tests for payload_shield.dependency route protection and handshake.
"""

import pytest
from fastapi import FastAPI, Depends, Request, HTTPException
from fastapi.testclient import TestClient

from payload_shield import (
    SessionStore,
    PayloadShieldDependency,
    HandshakeRequest,
    HandshakeResponse,
    handle_handshake,
    handle_logout,
    generate_key_pair,
    public_key_to_base64,
)

store = SessionStore(use_memory_fallback=True)
shield_dep = PayloadShieldDependency(store)
valid_server_sessions = {"sess_authenticated_100"}


def session_validator(session_id: str) -> bool:
    return session_id in valid_server_sessions


app = FastAPI()


@app.post("/handshake", response_model=HandshakeResponse)
def handshake_endpoint(req: HandshakeRequest):
    return handle_handshake(req, store, session_validator=session_validator)


@app.post("/logout")
def logout_endpoint(request: Request):
    sid = request.headers.get("X-Payload-Shield-Session")
    if sid:
        return handle_logout(sid, store)
    return {"status": "ignored"}


@app.get("/protected")
def protected_endpoint(key: bytes = Depends(shield_dep)):
    return {"status": "authorized", "key_len": len(key)}


client = TestClient(app)


def test_handshake_unauthenticated_session_rejection():
    c_priv, c_pub = generate_key_pair()
    req_body = {
        "client_public_key": public_key_to_base64(c_pub),
        "session_id": "made_up_unauthenticated_session"
    }
    res = client.post("/handshake", json=req_body)
    assert res.status_code == 401
    assert "validation failed" in res.json()["detail"].lower()


def test_handshake_and_protected_route_success():
    c_priv, c_pub = generate_key_pair()
    sid = "sess_authenticated_100"
    req_body = {
        "client_public_key": public_key_to_base64(c_pub),
        "session_id": sid
    }
    res = client.post("/handshake", json=req_body)
    assert res.status_code == 200
    assert "server_public_key" in res.json()

    # Call protected endpoint
    prot_res = client.get("/protected", headers={"X-Payload-Shield-Session": sid})
    assert prot_res.status_code == 200
    assert prot_res.json()["key_len"] == 32


def test_missing_header_rejection():
    res = client.get("/protected")
    assert res.status_code == 401
    assert "missing" in res.json()["detail"].lower()


def test_logout_invalidates_protected_access():
    c_priv, c_pub = generate_key_pair()
    sid = "sess_authenticated_100"
    client.post("/handshake", json={"client_public_key": public_key_to_base64(c_pub), "session_id": sid})

    # Access verified
    assert client.get("/protected", headers={"X-Payload-Shield-Session": sid}).status_code == 200

    # Logout
    logout_res = client.post("/logout", headers={"X-Payload-Shield-Session": sid})
    assert logout_res.status_code == 200

    # Access denied
    assert client.get("/protected", headers={"X-Payload-Shield-Session": sid}).status_code == 401
