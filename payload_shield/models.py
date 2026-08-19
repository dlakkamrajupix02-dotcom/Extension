"""
Pydantic Models for Payload Shield Handshake & Encrypted Payload Schemas.
"""

from pydantic import BaseModel, Field


class HandshakeRequest(BaseModel):
    client_public_key: str = Field(..., description="Base64-encoded client X25519 public key")
    session_id: str = Field(..., description="Session or user ID to bind key with")


class HandshakeResponse(BaseModel):
    server_public_key: str = Field(..., description="Base64-encoded server X25519 public key")
    session_id: str = Field(..., description="Session ID bound to this key")


class EncryptedPayload(BaseModel):
    nonce: str = Field(..., description="Base64-encoded 12-byte GCM nonce")
    ciphertext: str = Field(..., description="Base64-encoded ciphertext with appended tag")

