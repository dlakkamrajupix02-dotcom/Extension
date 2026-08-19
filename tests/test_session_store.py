"""
Unit tests for payload_shield.session_store module.
"""

import time
import pytest
from payload_shield.session_store import SessionStore


def test_session_store_save_get_invalidate_memory():
    store = SessionStore(use_memory_fallback=True)
    session_id = "test_session_001"
    key = b"0" * 32

    # Save key
    store.save_session_key(session_id, key, ttl_seconds=10)
    assert store.exists(session_id) is True

    # Retrieve key
    retrieved = store.get_session_key(session_id)
    assert retrieved == key

    # Invalidate key
    deleted = store.invalidate(session_id)
    assert deleted is True
    assert store.exists(session_id) is False
    assert store.get_session_key(session_id) is None


def test_session_store_key_expiration():
    store = SessionStore(use_memory_fallback=True)
    session_id = "test_expired_session"
    key = b"1" * 32

    # Save key with 1-second TTL
    store.save_session_key(session_id, key, ttl_seconds=1)
    assert store.get_session_key(session_id) == key

    # Wait for TTL expiry
    time.sleep(1.1)

    # Key should return None consistently
    assert store.get_session_key(session_id) is None
    assert store.exists(session_id) is False
