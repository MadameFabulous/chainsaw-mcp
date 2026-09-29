"""Authenticated remote HTTP transport; local stdio remains credential-free."""

from __future__ import annotations

import hmac
import logging
import os
import ssl
from collections.abc import Callable
from pathlib import Path
from typing import Any, TypedDict

from mcp.server.mcpserver import MCPServer
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from .security import transport_security

logger = logging.getLogger(__name__)


class TLSOptions(TypedDict):
    ssl_certfile: str
    ssl_keyfile: str
    ssl_version: int
    ssl_context_factory: Callable[[Any, Callable[[], ssl.SSLContext]], ssl.SSLContext]
    proxy_headers: bool


def tls12_context(config: Any, default: Callable[[], ssl.SSLContext]) -> ssl.SSLContext:
    """Raise the floor of the context uvicorn actually serves with to TLS 1.2."""
    context = default()
    context.minimum_version = max(context.minimum_version, ssl.TLSVersion.TLSv1_2)
    return context


def tls_options() -> TLSOptions:
    """Require native TLS, without trusting client-supplied forwarding headers."""
    cert = os.environ.get("MCP_TLS_CERT_FILE", "")
    key = os.environ.get("MCP_TLS_KEY_FILE", "")
    if not cert or not key:
        raise ValueError("Remote HTTP requires MCP_TLS_CERT_FILE and MCP_TLS_KEY_FILE for HTTPS")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(cert, key)
    return {
        "ssl_certfile": cert,
        "ssl_keyfile": key,
        "ssl_version": ssl.PROTOCOL_TLS_SERVER,
        "ssl_context_factory": tls12_context,
        "proxy_headers": False,
    }


class RequireTLS:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope.get("scheme") != "https":
            response = JSONResponse(
                {"error": "HTTPS required"},
                status_code=426,
                headers={"Cache-Control": "no-store"},
            )
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)


def bearer_token() -> str:
    """Read a mounted secret or environment token; remote HTTP always requires one."""
    token = os.environ.get("MCP_AUTH_TOKEN", "")
    token_file = os.environ.get("MCP_AUTH_TOKEN_FILE", "")
    if token and token_file:
        raise ValueError("Set only one of MCP_AUTH_TOKEN and MCP_AUTH_TOKEN_FILE")
    if token_file:
        with Path(token_file).open(encoding="utf-8") as fh:
            if os.fstat(fh.fileno()).st_mode & 0o077:
                raise ValueError(
                    "MCP_AUTH_TOKEN_FILE must not grant group or other access; chmod 0400 or 0600"
                )
            token = fh.read().strip()
        if not token:
            raise ValueError("MCP_AUTH_TOKEN_FILE is empty")
    if "MCP_REQUIRE_AUTH" in os.environ:
        logger.warning(
            "MCP_REQUIRE_AUTH is deprecated and ignored; remote HTTP always requires a bearer token"
        )
    if not token:
        raise ValueError("Remote HTTP requires MCP_AUTH_TOKEN or MCP_AUTH_TOKEN_FILE")
    if token and (len(token) < 32 or not token.isascii() or any(c.isspace() for c in token)):
        raise ValueError("MCP auth token must be at least 32 ASCII characters without whitespace")
    return token


class BearerAuth:
    def __init__(self, app: ASGIApp, token: str) -> None:
        self.app = app
        self.expected = token.encode("ascii")

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            headers = [v for k, v in scope["headers"] if k.lower() == b"authorization"]
            parts = headers[0].split(b" ", 1) if len(headers) == 1 else []
            if (
                len(parts) != 2
                or parts[0].lower() != b"bearer"
                or not hmac.compare_digest(parts[1], self.expected)
            ):
                response = JSONResponse(
                    {"error": "Bearer authentication required"},
                    status_code=401,
                    headers={"WWW-Authenticate": "Bearer", "Cache-Control": "no-store"},
                )
                await response(scope, receive, send)
                return
        await self.app(scope, receive, send)


def http_app(
    server: MCPServer, *, host: str, port: int, path: str, json_response: bool, token: str
) -> ASGIApp:
    if not token:
        raise ValueError("Remote HTTPS requires a bearer token; use stdio for local access")
    app = server.streamable_http_app(
        streamable_http_path=path,
        json_response=json_response,
        stateless_http=True,
        transport_security=transport_security(host, port),
    )
    return RequireTLS(BearerAuth(app, token))
