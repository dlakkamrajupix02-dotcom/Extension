"""
Unit tests for payload_shield.crypto module.
"""

import base64
import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from payload_shield.crypto import (
    generate_key_pair,
    public_key_to_base64,
    base64_to_public_key,
    derive_shared_symmetric_key,
    get_session_info,
    encrypt_payload,
    decrypt_payload,
)
from payload_shield.exceptions import PayloadDecryptionError, HandshakeError


def test_key_generation_and_base64_serialization():
    priv, pub = generate_key_pair()
    assert isinstance(priv, X25519PrivateKey)
    assert isinstance(pub, X25519PublicKey)

    pub_b64 = public_key_to_base64(pub)
    assert isinstance(pub_b64, str)
    assert len(pub_b64) > 0

    reconstructed_pub = base64_to_public_key(pub_b64)
    reconstructed_b64 = public_key_to_base64(reconstructed_pub)
    assert pub_b64 == reconstructed_b64


def test_invalid_public_key_deserialization():
    with pytest.raises(HandshakeError):
        base64_to_public_key("invalid_base64_string!!!")

    # Invalid length (e.g. 10 bytes instead of 32)
    short_b64 = base64.b64encode(b"short12345").decode("utf-8")
    with pytest.raises(HandshakeError):
        base64_to_public_key(short_b64)


def test_ecdh_key_derivation_agreement():
    c_priv, c_pub = generate_key_pair()
    s_priv, s_pub = generate_key_pair()

    session_id = "test_sess_99"
    info = get_session_info(session_id)

    key_c = derive_shared_symmetric_key(c_priv, s_pub, info=info)
    key_s = derive_shared_symmetric_key(s_priv, c_pub, info=info)

    assert len(key_c) == 32
    assert len(key_s) == 32
    assert key_c == key_s


def test_aes_gcm_encrypt_decrypt_roundtrip():
    c_priv, c_pub = generate_key_pair()
    s_priv, s_pub = generate_key_pair()
    key = derive_shared_symmetric_key(c_priv, s_pub, info=get_session_info("sess_1"))

    plaintext = "Sensitive User JSON Payload: {'balance': 5000}"
    encrypted = encrypt_payload(key, plaintext)

    assert "nonce" in encrypted
    assert "ciphertext" in encrypted
    assert isinstance(encrypted["nonce"], str)
    assert isinstance(encrypted["ciphertext"], str)

    decrypted = decrypt_payload(key, encrypted["nonce"], encrypted["ciphertext"])
    assert decrypted.decode("utf-8") == plaintext


def test_tampered_ciphertext_rejection():
    c_priv, c_pub = generate_key_pair()
    s_priv, s_pub = generate_key_pair()
    key = derive_shared_symmetric_key(c_priv, s_pub, info=get_session_info("sess_1"))

    encrypted = encrypt_payload(key, "Hello World")
    
    # Tamper with ciphertext bytes
    raw_ct = bytearray(base64.b64decode(encrypted["ciphertext"]))
    raw_ct[0] ^= 0xFF
    tampered_ct_b64 = base64.b64encode(raw_ct).decode("utf-8")

    with pytest.raises(PayloadDecryptionError) as exc_info:
        decrypt_payload(key, encrypted["nonce"], tampered_ct_b64)
    assert "invalid authentication tag" in str(exc_info.value).lower()


def test_invalid_nonce_length_rejection():
    c_priv, c_pub = generate_key_pair()
    s_priv, s_pub = generate_key_pair()
    key = derive_shared_symmetric_key(c_priv, s_pub, info=get_session_info("sess_1"))

    encrypted = encrypt_payload(key, "Hello World")
    
    # 8-byte nonce instead of 12-byte
    short_nonce_b64 = base64.b64encode(b"12345678").decode("utf-8")

    with pytest.raises(PayloadDecryptionError) as exc_info:
        decrypt_payload(key, short_nonce_b64, encrypted["ciphertext"])
    assert "nonce length" in str(exc_info.value).lower()
