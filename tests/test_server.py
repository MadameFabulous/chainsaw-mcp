import json

import anyio
import pytest
from mcp.client import Client

from chainsaw_mcp.cli import parse_args
from chainsaw_mcp.config import Settings
from chainsaw_mcp.security import transport_security
from chainsaw_mcp.server import annotations_for, build_server, collect_tools
from tests.conftest import MINIMAL_RULE

EXPECTED_TOOLS = [
    "chainsaw_analyse_evtx",
    "chainsaw_analyse_gaps",
    "chainsaw_analyse_shimcache",
    "chainsaw_analyse_srum",
    "chainsaw_delete_rule",
    "chainsaw_dump",
    "chainsaw_evidence_manifest",
    "chainsaw_evidence_validate",
    "chainsaw_get_mapping",
    "chainsaw_get_rule",
    "chainsaw_hunt",
    "chainsaw_jev_triage",
    "chainsaw_lint_rules",
    "chainsaw_list_evidence",
    "chainsaw_plan",
    "chainsaw_process_lineage",
    "chainsaw_reproduce",
    "chainsaw_result_chunk",
    "chainsaw_result_delete",
    "chainsaw_result_events",
    "chainsaw_result_export",
    "chainsaw_result_fields",
    "chainsaw_result_list",
    "chainsaw_result_manifest",
    "chainsaw_result_page",
    "chainsaw_result_summary",
    "chainsaw_rule_stats",
    "chainsaw_save_rule",
    "chainsaw_search",
    "chainsaw_search_rules",
    "chainsaw_status",
    "chainsaw_upload_begin",
    "chainsaw_upload_chunk",
    "chainsaw_upload_finish",
]


def call(server, name, args=None):
    async def go():
        async with Client(server) as client:
            return await client.call_tool(name, args or {})

    return anyio.run(go)


def payload(result) -> dict:
    assert not result.is_error, result.content[0].text
    return json.loads(result.content[0].text)


def test_tool_catalog_is_sorted_and_complete(settings: Settings):
    server = build_server(settings)

    async def go():
        async with Client(server) as client:
            return await client.list_tools()

    listing = anyio.run(go)
    names = [t.name for t in listing.tools]
    assert names == EXPECTED_TOOLS
    assert names == sorted(names)
    assert list(collect_tools(server._chainsaw_ctx)) == EXPECTED_TOOLS
    for tool in listing.tools:
        assert tool.description, tool.name
        assert tool.annotations is not None
        assert tool.annotations.title.startswith("Chainsaw:")
        assert tool.input_schema["type"] == "object"


def test_annotations_follow_house_rules():
    ro = annotations_for("chainsaw_result_page")
    assert ro.read_only_hint and ro.idempotent_hint and not ro.destructive_hint
    add = annotations_for("chainsaw_hunt")
    assert not add.read_only_hint and not add.destructive_hint
    rm = annotations_for("chainsaw_delete_rule")
    assert rm.destructive_hint and rm.idempotent_hint
    assert not annotations_for("chainsaw_status").open_world_hint


def test_status_without_binary_reports_error(settings: Settings, workspace):
    settings = Settings(**{**settings.__dict__, "binary": workspace / "nope"})
    data = payload(call(build_server(settings), "chainsaw_status"))
    assert data["chainsaw"]["version"] is None
    assert "bootstrap" in data["chainsaw"]["error"]
    assert data["rules"]["chainsaw"]["count"] == 1
    assert data["evidence_roots"][0]["top_level"] == ["host1"]


def test_list_evidence_and_sandboxing(settings: Settings):
    server = build_server(settings)
    data = payload(call(server, "chainsaw_list_evidence", {"path": "host1"}))
    assert [f["relative"] for f in data["files"]] == ["Security.evtx"]
    err = call(server, "chainsaw_list_evidence", {"path": "../outside"})
    assert err.is_error
    assert "allowed roots" in err.content[0].text
    err = call(server, "chainsaw_hunt", {"paths": ["/etc"]})
    assert err.is_error


def test_validation_errors_are_readable(settings: Settings):
    server = build_server(settings)
    err = call(server, "chainsaw_hunt", {"paths": ["host1"], "levels": ["urgent"]})
    assert "levels must be one of" in err.content[0].text
    err = call(server, "chainsaw_hunt", {"paths": ["host1"], "from_time": "yesterday"})
    assert "from_time" in err.content[0].text
    err = call(server, "chainsaw_search", {"paths": ["host1"]})
    assert "patterns or tau" in err.content[0].text
    err = call(server, "chainsaw_result_page", {"handle": "nope"})
    assert "handle" in err.content[0].text.lower()
    err = call(server, "chainsaw_get_rule", {"kind": "evil", "path": "x"})
    assert "kind must be one of" in err.content[0].text


def test_rule_tools_without_binary(settings: Settings):
    server = build_server(settings)
    stats = payload(call(server, "chainsaw_rule_stats"))
    assert stats["sigma"]["count"] == 1
    hits = payload(call(server, "chainsaw_search_rules", {"query": "mimikatz"}))
    assert hits["rules"][0]["uri"].startswith("chainsaw://rules/sigma/")
    rule = payload(
        call(server, "chainsaw_get_rule", {"kind": "chainsaw", "path": "evtx/test/test_rule.yml"})
    )
    assert rule["summary"]["level"] == "low"
    mapping = payload(call(server, "chainsaw_get_mapping", {"include_yaml": True}))
    assert "groups" in mapping and "yaml" in mapping
    saved = payload(
        call(
            server, "chainsaw_save_rule", {"name": "unit", "yaml_text": MINIMAL_RULE, "lint": False}
        )
    )
    assert saved["uri"] == "chainsaw://rules/custom/unit.yml"
    assert payload(call(server, "chainsaw_delete_rule", {"name": "unit"}))["deleted"] is True


def test_resources_and_prompts(settings: Settings):
    server = build_server(settings)

    async def go():
        async with Client(server) as client:
            templates = await client.list_resource_templates()
            resources = await client.list_resources()
            doc = await client.read_resource("chainsaw://docs/rule-format")
            rule = await client.read_resource("chainsaw://rules/chainsaw/evtx/test/test_rule.yml")
            listing = await client.read_resource("chainsaw://rules/chainsaw/evtx")
            mapping = await client.read_resource("chainsaw://mappings/sigma-event-logs-all.yml")
            prompts = await client.list_prompts()
            prompt = await client.get_prompt("triage_evtx", {"path": "host1"})
            blocked = []
            for uri in (
                "chainsaw://rules/chainsaw/../../outside/secret.evtx",
                "chainsaw://mappings/../rules/evtx/test/test_rule.yml",
                "chainsaw://results/../config",
            ):
                try:
                    await client.read_resource(uri)
                except Exception as exc:  # noqa: BLE001
                    blocked.append(type(exc).__name__)
            return templates, resources, doc, rule, listing, mapping, prompts, prompt, blocked

    templates, resources, doc, rule, listing, mapping, prompts, prompt, blocked = anyio.run(go)
    assert {t.uri_template for t in templates.resource_templates} == {
        "chainsaw://rules/{kind}/{+path}",
        "chainsaw://mappings/{name}",
        "chainsaw://results/{handle}",
    }
    assert {str(r.uri) for r in resources.resources} == {
        "chainsaw://docs/rule-format",
        "chainsaw://config",
    }
    assert doc.contents[0].text.startswith("# Chainsaw rule format")
    assert "title: Test Rule" in rule.contents[0].text
    assert json.loads(listing.contents[0].text)["directory"] is True
    assert "groups:" in mapping.contents[0].text
    assert {p.name for p in prompts.prompts} == {"triage_evtx", "pivot_on_indicator", "author_rule"}
    assert "chainsaw_hunt" in prompt.messages[0].content.text
    assert len(blocked) == 3


def test_cli_defaults_and_env(monkeypatch):
    args = parse_args([])
    assert args.transport == "stdio" and args.port == 18098 and args.path == "/mcp"
    monkeypatch.setenv("MCP_TRANSPORT", "streamable-http")
    monkeypatch.setenv("MCP_PORT", "19000")
    args = parse_args([])
    assert args.transport == "streamable-http" and args.port == 19000
    with pytest.raises(SystemExit):
        parse_args(["--transport", "websocket"])


def test_transport_security_allows_bind_host_and_env():
    sec = transport_security("100.64.0.1", 18098, env={"MCP_ALLOWED_HOSTS": "mcp.example:18098"})
    assert sec.enable_dns_rebinding_protection
    assert "100.64.0.1:18098" in sec.allowed_hosts
    assert "mcp.example:18098" in sec.allowed_hosts
    assert "http://localhost" in sec.allowed_origins
