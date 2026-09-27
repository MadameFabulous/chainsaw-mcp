"""Contract checks against the MCP 2026-07-28 revision as exposed by the Python SDK."""

import anyio
from mcp.client import Client
from mcp.types import LATEST_PROTOCOL_VERSION

from chainsaw_mcp.config import Settings
from chainsaw_mcp.server import build_server

PROTOCOL = "2026-07-28"


def test_sdk_targets_expected_protocol():
    assert LATEST_PROTOCOL_VERSION == PROTOCOL


def test_initialize_and_call_carry_spec_metadata(settings: Settings):
    server = build_server(settings)

    async def go():
        async with Client(server) as client:
            result = await client.call_tool("chainsaw_rule_stats", {})
            return (
                client.protocol_version,
                client.server_info,
                client.instructions,
                client.server_capabilities,
                result,
            )

    version, info, instructions, caps, result = anyio.run(go)
    assert version == PROTOCOL
    assert info is not None and info.name == "chainsaw-mcp" and info.version
    assert instructions and "chainsaw_hunt" in instructions
    assert caps is not None
    assert caps.tools is not None
    assert caps.resources is not None
    assert caps.prompts is not None
    assert result.result_type == "complete"
    assert result.is_error is False
    assert result.content[0].type == "text"


def test_streamable_http_app_builds_stateless(settings: Settings):
    from chainsaw_mcp.security import transport_security

    server = build_server(settings)
    app = server.streamable_http_app(
        streamable_http_path="/mcp",
        json_response=True,
        stateless_http=True,
        transport_security=transport_security("127.0.0.1", 18098),
    )
    assert app is not None
