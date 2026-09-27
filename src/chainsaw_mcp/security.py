"""Transport hardening for streamable-http: DNS-rebinding and origin checks."""

from __future__ import annotations

import os
from collections.abc import Mapping

from mcp.server.transport_security import TransportSecuritySettings

DEFAULT_ORIGINS = (
    "http://localhost",
    "http://localhost:*",
    "http://127.0.0.1",
    "http://127.0.0.1:*",
)


def _authority(host: str) -> str:
    """Host header form of a bind address: IPv6 literals are bracketed."""
    return f"[{host}]" if ":" in host and not host.startswith("[") else host


def _split(raw: str) -> list[str]:
    return [item.strip() for item in raw.split(",") if item.strip()]


def transport_security(
    host: str, port: int | None = None, env: Mapping[str, str] | None = None
) -> TransportSecuritySettings:
    """Allow the bind host (with and without port) plus MCP_ALLOWED_HOSTS/ORIGINS."""
    source: Mapping[str, str] = os.environ if env is None else env
    host = _authority(host)
    hosts = {host, f"{host}:*", "localhost", "localhost:*", "127.0.0.1", "127.0.0.1:*"}
    if port:
        hosts.add(f"{host}:{port}")
    hosts.update(_split(source.get("MCP_ALLOWED_HOSTS", "")))
    origins = set(DEFAULT_ORIGINS) | {f"http://{host}", f"http://{host}:*"}
    origins.update(_split(source.get("MCP_ALLOWED_ORIGINS", "")))
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=sorted(hosts),
        allowed_origins=sorted(origins),
    )
