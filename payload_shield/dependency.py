"""
FastAPI Depends()-based Per-Route Payload Encryption.

Provides handshake handlers and dependencies for opting specific routes into Payload Shield response
encryption and request decryption.

Threat Model Notice:
Encrypts data payloads specifically for opted-in endpoints returning sensitive API data to deter casual scraping.
Does not protect against authenticated users with local DevTools inspection or in-page XSS.
Must be used alongside HTTPS/TLS.
"""

import json
from typing import Any, Dict, Optional, Callable, Awaitable
from fastapi import Request, Response, HTTPException, status, Depends
from fastapi.responses import JSONResponse

from payload_shield.crypto import (
    generate_key_pair,
    public_key_to_base64,
    base64_to_public_key,
    derive_shared_symmetric_key,
    get_session_info,
    encrypt_payload,
    decrypt_payload,
)
from payload_shield.session_store import SessionStore
from payload_shield.models import HandshakeRequest, HandshakeResponse, EncryptedPayload
from payload_shield.exceptions import KeyExpiredError, PayloadDecryptionError, HandshakeError
from payload_shield.config import settings


def handle_handshake(
    request: HandshakeRequest,
    store: SessionStore,
    session_validator: Optional[Callable[[str], bool]] = None
) -> HandshakeResponse:
    """
    Perform ECDH key exchange with the client and store the derived symmetric key in SessionStore.

    Security Rule:
    `request.session_id` MUST be a server-issued session ID generated at login (e.g. session token or JWT).
    If a `session_validator` function is provided, it validates the session_id prior to creating key agreement.

    Args:
        request: HandshakeRequest with client public key and server-issued session ID.
        store: SessionStore instance.
        session_validator: Optional callback `(session_id: str) -> bool` to verify session authenticity.

    Returns:
        HandshakeResponse with server public key and session ID.

    Raises:
        HTTPException(401): If session_id is invalid or unauthenticated.
    """
    if not request.session_id or not request.session_id.strip():
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid session_id. Session ID must be an authenticated server-issued session identifier."
        )

    if session_validator is not None:
        if not session_validator(request.session_id):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session validation failed. Handshake requires a valid authenticated session."
            )

    server_private_key, server_public_key = generate_key_pair()
    client_public_key = base64_to_public_key(request.client_public_key)

    # Derive symmetric key bound to this session identity
    session_info = get_session_info(request.session_id)
    symmetric_key = derive_shared_symmetric_key(
        server_private_key,
        client_public_key,
        info=session_info
    )

    # Save to session store with TTL
    store.save_session_key(request.session_id, symmetric_key)

    return HandshakeResponse(
        server_public_key=public_key_to_base64(server_public_key),
        session_id=request.session_id,
    )



def handle_logout(session_id: str, store: SessionStore) -> Dict[str, str]:
    """
    Invalidate a session key server-side in SessionStore on logout.

    Threat Model Requirement:
    Server-side invalidation ensures that even if a key was leaked or cached on the client,
    the server will immediately refuse to encrypt or decrypt any further payloads for this session ID.

    Args:
        session_id: Session identifier to invalidate.
        store: SessionStore instance.

    Returns:
        Confirmation dictionary {"status": "success", "session_id": session_id}.
    """
    store.invalidate(session_id)
    return {"status": "success", "session_id": session_id}


class PayloadShieldDependency:

    """
    FastAPI dependency for managing payload encryption on specific routes.
    """

    def __init__(
        self,
        session_store: SessionStore,
        header_name: str = settings.header_name
    ):
        self.session_store = session_store
        self.header_name = header_name

    async def __call__(self, request: Request) -> bytes:
        """
        FastAPI dependency handler. Extracts session ID header, retrieves derived key,
        and attaches key to request.state.

        Returns:
            The 32-byte symmetric key for the request.
        """
        session_id = request.headers.get(self.header_name)
        if not session_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Missing required session header '{self.header_name}'."
            )

        key = self.session_store.get_session_key(session_id)
        if not key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session key invalid or expired. Please re-authenticate/handshake."
            )

        request.state.payload_shield_session_id = session_id
        request.state.payload_shield_key = key
        return key

    def encrypt_response(self, key: bytes, content: Any) -> Dict[str, str]:
        """
        Helper to serialize content to JSON and encrypt it with AES-256-GCM.
        """
        if isinstance(content, (dict, list)):
            json_str = json.dumps(content)
        elif isinstance(content, str):
            json_str = content
        else:
            json_str = json.dumps(content)

        return encrypt_payload(key, json_str)

    def decrypt_request_body(self, key: bytes, encrypted_payload: EncryptedPayload) -> Any:
        """
        Helper to decrypt an incoming encrypted request body and parse JSON.
        """
        try:
            plaintext_bytes = decrypt_payload(key, encrypted_payload.nonce, encrypted_payload.ciphertext)
            return json.loads(plaintext_bytes.decode("utf-8"))
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to decrypt request payload: {str(e)}"
            ) from e

