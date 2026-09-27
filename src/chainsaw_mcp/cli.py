"""Command-line entry point: `chainsaw-mcp --transport stdio|streamable-http`."""

from __future__ import annotations

import argparse
import logging
import os
import sys

from . import __version__
from .config import load_settings
from .security import transport_security
from .server import build_server


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="chainsaw-mcp",
        description="MCP server (spec 2026-07-28) wrapping the Chainsaw forensic tool.",
    )
    parser.add_argument(
        "--transport",
        choices=("stdio", "streamable-http"),
        default=os.environ.get("MCP_TRANSPORT", "stdio"),
        help="stdio for a local agent, streamable-http for a shared service (MCP_TRANSPORT).",
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("MCP_HOST", "127.0.0.1"),
        help="Bind address for streamable-http; keep it loopback or private (MCP_HOST).",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("MCP_PORT", "18098")),
        help="Listening port for streamable-http (MCP_PORT).",
    )
    parser.add_argument(
        "--path",
        default=os.environ.get("MCP_PATH", "/mcp"),
        help="URL path of the MCP endpoint for streamable-http (MCP_PATH).",
    )
    parser.add_argument(
        "--json-response",
        action="store_true",
        help="Return plain JSON responses instead of SSE for streamable-http.",
    )
    parser.add_argument("--log-level", default=os.environ.get("LOG_LEVEL", "INFO"))
    parser.add_argument("--check", action="store_true", help="Print status JSON and exit.")
    parser.add_argument("--version", action="version", version=f"chainsaw-mcp {__version__}")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(level=args.log_level.upper(), stream=sys.stderr)
    settings = load_settings()
    server = build_server(settings)
    if args.check:
        ctx = server._chainsaw_ctx  # type: ignore[attr-defined]
        from .tools.evidence import EvidenceTools

        print(EvidenceTools(ctx).chainsaw_status())
        return 0
    if args.transport == "stdio":
        server.run(transport="stdio")
        return 0
    server.run(
        transport="streamable-http",
        host=args.host,
        port=args.port,
        streamable_http_path=args.path,
        json_response=args.json_response,
        stateless_http=True,
        transport_security=transport_security(args.host, args.port),
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
