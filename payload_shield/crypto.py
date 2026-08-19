"""
ECDH Key Exchange and AES-256-GCM Encryption/Decryption Helpers.

Threat Model & Cryptographic Policy:
- Uses `cryptography.hazmat.primitives.asymmetric.x25519` for ECDH key agreement.
- Uses `cryptography.hazmat.primitives.kdf.hkdf.HKDF` with SHA-256 to derive a 256-bit AES key.
- Uses `cryptography.hazmat.primitives.ciphers.aead.AESGCM` for symmetric authenticated encryption.
- Generates a cryptographically secure, fresh 12-byte (96-bit) random nonce for every encryption call.
- Base64 encodes all binary primitives for safe JSON HTTP transport.
- No custom/home-grown cryptographic algorithms are implemented.

Threat Model Limitations:
- Obscures response payload contents from network sniffers, direct script scraping, and proxy log dumps over TLS.
- DOES NOT prevent a logged-in user from reading session keys in browser memory or DevTools.
- MUST be layered on top of HTTPS/TLS.
"""

import base64
import os
from typing import Dict, Union, Tuple, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidTag

from payload_shield.exceptions import PayloadDecryptionError, HandshakeError

# Default info string for HKDF key derivation
HKDF_INFO = b"payload-shield-v1"


def get_session_info(session_id: str) -> bytes:
    """
    Construct a session-bound HKDF context info byte string.
    """
    return f"payload-shield-v1:{session_id}".encode("utf-8")



def generate_key_pair() -> Tuple[X25519PrivateKey, X25519PublicKey]:
    """
    Generate an ephemeral X25519 private/public key pair.
    
    Returns:
        Tuple of (X25519PrivateKey, X25519PublicKey).
    """
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key


def public_key_to_base64(public_key: X25519PublicKey) -> str:
    """
    Serialize an X25519 public key to a base64-encoded string.
    """
    raw_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return base64.b64encode(raw_bytes).decode("utf-8")


def base64_to_public_key(public_key_b64: str) -> X25519PublicKey:
    """
    Deserialize an X25519 public key from a base64-encoded string.
    """
    try:
        raw_bytes = base64.b64decode(public_key_b64)
        if len(raw_bytes) != 32:
            raise ValueError(f"Invalid X25519 public key length: {len(raw_bytes)} bytes (expected 32)")
        return X25519PublicKey.from_public_bytes(raw_bytes)
    except Exception as e:
        raise HandshakeError(f"Failed to decode public key: {str(e)}") from e


def derive_shared_symmetric_key(
    private_key: X25519PrivateKey,
    peer_public_key: X25519PublicKey,
    info: bytes = HKDF_INFO
) -> bytes:
    """
    Perform ECDH key agreement and derive a 256-bit symmetric AES key using HKDF-SHA256.

    Args:
        private_key: The local X25519 private key.
        peer_public_key: The remote party's X25519 public key.
        info: Context/application-specific info string for HKDF.

    Returns:
        32-byte derived symmetric key.
    """
    raw_shared_secret = private_key.exchange(peer_public_key)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits for AES-256
        salt=None,
        info=info,
    )
    symmetric_key = hkdf.derive(raw_shared_secret)
    return symmetric_key


def encrypt_payload(
    key: bytes,
    plaintext: Union[str, bytes],
    associated_data: Optional[bytes] = None
) -> Dict[str, str]:
    """
    Encrypt a plaintext payload using AES-256-GCM with a fresh 12-byte random nonce.

    Args:
        key: 32-byte derived symmetric key.
        plaintext: String or bytes to encrypt.
        associated_data: Optional authenticated associated data (AAD).

    Returns:
        Dictionary containing base64-encoded 'nonce' and 'ciphertext' (with appended GCM tag).
    """
    if isinstance(plaintext, str):
        plaintext_bytes = plaintext.encode("utf-8")
    else:
        plaintext_bytes = plaintext

    # Generate a fresh 12-byte (96-bit) cryptographically secure random nonce for every encryption
    nonce = os.urandom(12)
    aesgcm = AESGCM(key)
    
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, associated_data)

    return {
        "nonce": base64.b64encode(nonce).decode("utf-8"),
        "ciphertext": base64.b64encode(ciphertext).decode("utf-8")
    }


def decrypt_payload(
    key: bytes,
    nonce_b64: str,
    ciphertext_b64: str,
    associated_data: Optional[bytes] = None
) -> bytes:
    """
    Decrypt an AES-256-GCM encrypted payload and verify tag integrity.

    Args:
        key: 32-byte derived symmetric key.
        nonce_b64: Base64-encoded 12-byte nonce.
        ciphertext_b64: Base64-encoded ciphertext (with appended tag).
        associated_data: Optional authenticated associated data (AAD).

    Returns:
        Decrypted plaintext bytes.

    Raises:
        PayloadDecryptionError: If decoding fails, nonce length is invalid, or GCM authentication tag validation fails.
    """
    try:
        nonce = base64.b64decode(nonce_b64)
        ciphertext = base64.b64decode(ciphertext_b64)
    except Exception as e:
        raise PayloadDecryptionError(f"Base64 decoding failed for payload: {str(e)}") from e

    if len(nonce) != 12:
        raise PayloadDecryptionError(f"Invalid GCM nonce length: {len(nonce)} bytes (expected 12)")

    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
        return plaintext
    except InvalidTag as e:
        raise PayloadDecryptionError("Payload decryption failed: invalid authentication tag (data tampered or wrong key)") from e
    except Exception as e:
        raise PayloadDecryptionError(f"Payload decryption failed: {str(e)}") from e

