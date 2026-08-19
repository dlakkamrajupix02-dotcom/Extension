"""
Integration tests for payload_shield.middleware blanket ASGI middleware protection.
"""

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from payload_shield import (
    SessionStore,
    PayloadShieldMiddleware,
    HandshakeRequest,
    handle_handshake,
    generate_key_pair,
    public_key_to_base64,
    base64_to_public_key,
    derive_shared_symmetric_key,
    get_session_info,
    decrypt_payload,
)

store = SessionStore(use_memory_fallback=True)
app = FastAPI()

app.add_middleware(
    PayloadShieldMiddleware,
    session_store=store,
    exclude_paths=["/public", "/handshake", "/docs", "/openapi.json"]
)


@app.post("/handshake")
def handshake_endpoint(req: HandshakeRequest):
    return handle_handshake(req, store)


@app.get("/public")
def public_endpoint():
    return {"message": "unencrypted"}


@app.get("/api/data")
def protected_data():
    return {"secret": "super_secret_payload_12345"}


client = TestClient(app)


def test_middleware_exclusion():
    res = client.get("/public")
    assert res.status_code == 200
    assert res.json() == {"message": "unencrypted"}


def test_middleware_encrypted_response_flow():
    c_priv, c_pub = generate_key_pair()
    sid = "sess_middleware_test"

    # Handshake
    hs_res = client.post("/handshake", json={"client_public_key": public_key_to_base64(c_pub), "session_id": sid})
    assert hs_res.status_code == 200
    s_pub_b64 = hs_res.json()["server_public_key"]

    key = derive_shared_symmetric_key(c_priv, base64_to_public_key(s_pub_b64), info=get_session_info(sid))

    # Request protected route
    res = client.get("/api/data", headers={"X-Payload-Shield-Session": sid})
    assert res.status_code == 200

    payload = res.json()
    assert "nonce" in payload
    assert "ciphertext" in payload

    # Decrypt response
    decrypted_bytes = decrypt_payload(key, payload["nonce"], payload["ciphertext"])
    assert b"super_secret_payload_12345" in decrypted_bytes
