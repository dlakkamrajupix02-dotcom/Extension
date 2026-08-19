"""
FastAPI Middleware for Blanket Payload Encryption.

Applies payload encryption to all routes except those included in an exclusion list.

Threat Model Notice:
Provides blanket encryption across application routes to deter casual Network tab JSON scraping over HTTPS.
Does not protect against end-users inspecting memory or DevTools within their authenticated browser session.
Must be layered on top of HTTPS/TLS.
"""

import json
from typing import Set, List, Optional, Union

from fastapi import Request, Response, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from payload_shield.config import settings
from payload_shield.crypto import encrypt_payload, decrypt_payload
from payload_shield.session_store import SessionStore
from payload_shield.exceptions import PayloadDecryptionError


class PayloadShieldMiddleware(BaseHTTPMiddleware):
    """
    ASGI Middleware for automatic response payload encryption across API endpoints.
    """

    def __init__(
        self,
        app,
        session_store: SessionStore,
        exclude_paths: Optional[Union[Set[str], List[str]]] = None,
        header_name: str = settings.header_name,
        auto_encrypt_responses: bool = True
    ):
        super().__init__(app)
        self.session_store = session_store
        self.exclude_paths: Set[str] = set(exclude_paths or [])
        # Always exclude common docs and handshake endpoints by default if not specified
        self.exclude_paths.update({"/docs", "/redoc", "/openapi.json", "/api/handshake", "/login"})
        self.header_name = header_name
        self.auto_encrypt_responses = auto_encrypt_responses

    def _is_excluded(self, path: str) -> bool:
        if path in self.exclude_paths:
            return True
        for excluded in self.exclude_paths:
            if excluded.endswith("*") and path.startswith(excluded[:-1]):
                return True
            if not excluded.endswith("*") and path.startswith(excluded):
                return True
        return False

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        if self._is_excluded(request.url.path):
            return await call_next(request)

        session_id = request.headers.get(self.header_name)
        if not session_id:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": f"Missing required session header '{self.header_name}'."}
            )

        key = self.session_store.get_session_key(session_id)
        if not key:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Session key invalid or expired. Handshake required."}
            )

        request.state.payload_shield_session_id = session_id
        request.state.payload_shield_key = key

        response = await call_next(request)

        # Intercept and encrypt JSON responses if status is 2xx and content-type is application/json
        content_type = response.headers.get("content-type", "")
        if (
            self.auto_encrypt_responses
            and 200 <= response.status_code < 300
            and "application/json" in content_type
        ):
            response_body = [section async for section in response.body_iterator]
            body_bytes = b"".join(response_body)

            if body_bytes:
                encrypted_dict = encrypt_payload(key, body_bytes)
                # Create replacement JSON response with encrypted payload
                encrypted_json_bytes = json.dumps(encrypted_dict).encode("utf-8")
                
                headers = dict(response.headers)
                headers["content-length"] = str(len(encrypted_json_bytes))
                
                return Response(
                    content=encrypted_json_bytes,
                    status_code=response.status_code,
                    headers=headers,
                    media_type="application/json"
                )

        return response

