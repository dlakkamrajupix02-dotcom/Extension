"""
Redis-backed Session Key Store.

Manages session ID to derived symmetric key mapping with TTL support and explicit invalidation.

Threat Model Notice:
Server-side session store ensures immediate invalidation of payload decryption capabilities on logout
or session expiration. Even if a client session token or key is retained client-side,
server invalidation prevents further payload encryption/decryption by the backend.
"""

import base64
import logging
import time
from typing import Optional, Dict, Tuple

try:
    import redis
except ImportError:
    redis = None  # type: ignore

from payload_shield.config import settings
from payload_shield.exceptions import KeyExpiredError

logger = logging.getLogger("payload_shield.session_store")


class SessionStore:
    """
    Manages session keys backed by Redis (or an in-memory store for fallback/testing).
    """

    def __init__(
        self,
        redis_url: Optional[str] = None,
        default_ttl: Optional[int] = None,
        use_memory_fallback: bool = True
    ):
        self.redis_url = redis_url or settings.redis_url
        self.default_ttl = default_ttl or settings.session_key_ttl_seconds
        self.use_memory_fallback = use_memory_fallback
        self._memory_store: Dict[str, Tuple[bytes, float]] = {}  # session_id -> (key_bytes, expire_timestamp)
        self._redis_client = None

        if redis is not None:
            try:
                client = redis.Redis.from_url(self.redis_url, decode_responses=False)
                # Quick ping test to verify Redis connectivity
                client.ping()
                self._redis_client = client
            except Exception:
                if not self.use_memory_fallback:
                    raise

        if self._redis_client is None and self.use_memory_fallback:
            logger.warning(
                "Redis not configured or unreachable — falling back to in-memory session store. "
                "WARNING: In-memory store is NOT safe for multi-instance or production deployments!"
            )

    def _redis_key(self, session_id: str) -> str:
        return f"payload_shield:session:{session_id}"

    def save_session_key(self, session_id: str, key: bytes, ttl_seconds: Optional[int] = None) -> None:
        """
        Store a derived session key associated with a session ID and TTL.

        Args:
            session_id: Unique session identifier.
            key: 32-byte derived symmetric key.
            ttl_seconds: Optional TTL override in seconds. Defaults to configured TTL.
        """
        ttl = ttl_seconds if ttl_seconds is not None else self.default_ttl

        if self._redis_client is not None:
            rkey = self._redis_key(session_id)
            self._redis_client.setex(rkey, ttl, key)
        elif self.use_memory_fallback:
            expire_at = time.time() + ttl
            self._memory_store[session_id] = (key, expire_at)
        else:
            raise RuntimeError("Redis client unavailable and memory fallback disabled.")

    def get_session_key(self, session_id: str) -> Optional[bytes]:
        """
        Retrieve a derived session key for a given session ID.

        Returns:
            The 32-byte symmetric key, or None if not found, expired, or invalidated.
        """
        if self._redis_client is not None:
            rkey = self._redis_key(session_id)
            key_bytes = self._redis_client.get(rkey)
            if key_bytes is None:
                return None
            return key_bytes
        elif self.use_memory_fallback:
            if session_id not in self._memory_store:
                return None
            key, expire_at = self._memory_store[session_id]
            if time.time() > expire_at:
                del self._memory_store[session_id]
                return None
            return key
        else:
            raise RuntimeError("Redis client unavailable and memory fallback disabled.")

    def invalidate(self, session_id: str) -> bool:
        """
        Invalidate and delete a session key (e.g. on logout).

        Args:
            session_id: Session identifier to delete.

        Returns:
            True if the session key existed and was deleted, False otherwise.
        """
        deleted = False
        if self._redis_client is not None:
            rkey = self._redis_key(session_id)
            result = self._redis_client.delete(rkey)
            deleted = bool(result > 0)
        
        if self.use_memory_fallback and session_id in self._memory_store:
            del self._memory_store[session_id]
            deleted = True

        return deleted

    def exists(self, session_id: str) -> bool:
        """
        Check whether an active session key exists.
        """
        return self.get_session_key(session_id) is not None


