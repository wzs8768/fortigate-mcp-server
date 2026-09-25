"""
Auth middleware for FortiGate MCP server.

Enforces Bearer token authentication when ``require_auth`` is enabled
in config.json.  Supports named tokens so logs can identify which client
is connecting.

Token format (config.json ``auth.api_tokens``):

    # Named tokens (recommended)
    [{"name": "hermes-local", "token": "..."}, {"name": "claude-win", "token": "..."}]

    # Bare tokens (backward compatible)
    ["token1", "token2"]

When a request is authenticated, the client name is attached to the
request scope as ``scope[\"fortigate_mcp_client\"]`` for downstream logging.
"""

import hmac
import logging

from starlette.responses import JSONResponse

logger = logging.getLogger("fortigate_mcp.auth")

PUBLIC_PREFIXES = ("/health",)


def _normalize_tokens(raw_tokens: list) -> dict:
    """Normalize ``api_tokens`` into ``{token: name}`` dict.

    Accepts two shapes:
      - list of strings  → each token gets name ``"(unnamed)"``
      - list of dicts    → ``{"name": "...", "token": "..."}``
    """
    lookup: dict[str, str] = {}
    for entry in raw_tokens:
        if isinstance(entry, str):
            lookup[entry] = "(unnamed)"
        elif isinstance(entry, dict):
            name = entry.get("name", "(unnamed)")
            token = entry.get("token", "")
            if token:
                lookup[token] = name
    return lookup


def make_auth_middleware(require_auth: bool, api_tokens: list):
    """Create a Starlette-style ASGI middleware with bound config.

    Returns an ``AuthMiddleware`` class that can be passed to
    ``app.add_middleware()``.  The class validates ``Authorization: Bearer <token>``
    headers against the normalised token lookup and logs the client name on
    each authenticated request.
    """
    token_lookup = _normalize_tokens(api_tokens)

    class AuthMiddleware:
        """ASGI middleware — Bearer token auth with client identification."""

        def __init__(self, app):
            self.app = app

        async def __call__(self, scope, receive, send):
            if scope["type"] not in ("http",):
                await self.app(scope, receive, send)
                return

            if not require_auth:
                await self.app(scope, receive, send)
                return

            # Fast path for public paths
            path = scope.get("path", "")
            if path in PUBLIC_PREFIXES or path == "/" or path.startswith("/.well-known/"):
                await self.app(scope, receive, send)
                return

            # Read Authorization header from ASGI scope
            headers = dict(scope.get("headers", []))
            auth_bytes = headers.get(b"authorization", b"")
            auth_header = auth_bytes.decode("latin-1", errors="replace")

            if not auth_header.startswith("Bearer "):
                response = JSONResponse(
                    {"error": "unauthorized", "detail": "Missing or invalid Authorization header"},
                    status_code=401,
                    headers={"WWW-Authenticate": "Bearer"},
                )
                await response(scope, receive, send)
                return

            token = auth_header[7:]
            # Constant-time comparison to prevent timing side-channel attacks
            client_name = None
            for valid_token, name in token_lookup.items():
                if hmac.compare_digest(token, valid_token):
                    client_name = name
                    break
            if client_name is None:
                logger.warning("Auth rejected — unknown token (first 8 chars: %s...)", token[:8])
                response = JSONResponse(
                    {"error": "unauthorized", "detail": "Invalid token"},
                    status_code=401,
                )
                await response(scope, receive, send)
                return

            # Attach client identity to scope for downstream use
            scope["fortigate_mcp_client"] = client_name
            logger.info("Auth OK — client=%s path=%s", client_name, path)

            await self.app(scope, receive, send)

    return AuthMiddleware
