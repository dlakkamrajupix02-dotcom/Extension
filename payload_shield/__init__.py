"""
Payload Shield (Python/FastAPI)

FastAPI payload encryption helper library using X25519 ECDH key exchange and AES-256-GCM encryption.

Threat Model Notice:
This package deters casual scraping, naive API bots, and automated proxies.
It does NOT protect against logged-in users with DevTools access or XSS attacks.
Must be used alongside HTTPS/TLS.
"""

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
from payload_shield.dependency import PayloadShieldDependency, handle_handshake, handle_logout
from payload_shield.middleware import PayloadShieldMiddleware
from payload_shield.models import HandshakeRequest, HandshakeResponse, EncryptedPayload
from payload_shield.exceptions import (
    PayloadShieldException,
    HandshakeError,
    KeyExpiredError,
    PayloadDecryptionError,
)

__version__ = "0.1.0"

__all__ = [
    "SessionStore",
    "PayloadShieldDependency",
    "PayloadShieldMiddleware",
    "handle_handshake",
    "handle_logout",
    "HandshakeRequest",
    "HandshakeResponse",
    "EncryptedPayload",
    "PayloadShieldException",
    "HandshakeError",
    "KeyExpiredError",
    "PayloadDecryptionError",
    "generate_key_pair",
    "public_key_to_base64",
    "base64_to_public_key",
    "derive_shared_symmetric_key",
    "get_session_info",
    "encrypt_payload",
    "decrypt_payload",
]



