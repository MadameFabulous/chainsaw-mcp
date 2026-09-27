"""Integration tests: real chainsaw binary + vendor rules + EVTX-ATTACK-SAMPLES."""

import json

import anyio
import pytest
from mcp.client import Client

from chainsaw_mcp.config import load_settings
from chainsaw_mcp.server import build_server
from tests.conftest import REPO, SAMPLES, requires_binary, requires_samples, requires_vendor_rules

pytestmark = [requires_binary, requires_samples, requires_vendor_rules, pytest.mark.integration]

CRED = "Credential Access"
BABYSHARK = f"{CRED}/babyshark_mimikatz_powershell.evtx"
MALSECLOGON = f"{CRED}/tutto_malseclogon.evtx"


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    out = tmp_path_factory.mktemp("results")
    custom = tmp_path_factory.mktemp("custom")
    env = {
        "CHAINSAW_HOME": str(REPO),
        "CHAINSAW_EVIDENCE_ROOTS": str(SAMPLES),
        "CHAINSAW_OUTPUT_DIR": str(out),
        "CHAINSAW_CUSTOM_RULES_DIR": str(custom),
    }
    return build_server(load_settings(env))


def call(server, name, args):
    async def go():
        async with Client(server) as client:
            return await client.call_tool(name, args)

    result = anyio.run(go)
    assert not result.is_error, result.content[0].text
    return json.loads(result.content[0].text)


def test_status_reports_binary_and_rules(server):
    data = call(server, "chainsaw_status", {})
    assert data["chainsaw"]["version"].startswith("2.")
    assert data["rules"]["sigma"]["count"] > 3000
    assert data["rules"]["chainsaw"]["count"] > 100


def test_analyse_evtx_and_gaps(server):
    evtx = call(server, "chainsaw_analyse_evtx", {"paths": [BABYSHARK]})
    assert evtx["files"] == 1 and evtx["records"] > 0
    assert "Microsoft-Windows-Sysmon/Operational" in evtx["by_channel"]
    gaps = call(server, "chainsaw_analyse_gaps", {"paths": [MALSECLOGON]})
    assert gaps["total"] > 0 and "record_id" in gaps["by_kind"]


def test_hunt_page_summary_export_roundtrip(server):
    hunt = call(server, "chainsaw_hunt", {"paths": [BABYSHARK], "preview": 2})
    assert hunt["total"] >= 5
    assert hunt["summary"]["shape"] == "detections"
    assert len(hunt["preview"]["rows"]) == 2
    handle = hunt["handle"]

    page = call(
        server,
        "chainsaw_result_page",
        {"handle": handle, "limit": 3, "fields": ["rule", "level", "computer", "event_id"]},
    )
    assert page["returned"] == 3 and set(page["rows"][0]) == {
        "rule",
        "level",
        "computer",
        "event_id",
    }

    filtered = call(server, "chainsaw_result_page", {"handle": handle, "where": {"level": "high"}})
    assert all(r["level"] == "high" for r in filtered["rows"])

    grouped = call(
        server, "chainsaw_result_summary", {"handle": handle, "group_by": ["rule", "computer"]}
    )
    assert grouped["total"] == hunt["total"] and grouped["combined"]

    fields = call(server, "chainsaw_result_fields", {"handle": handle})
    assert any(f["path"] == "document.data.Event.System.EventID" for f in fields["fields"])

    csv_out = call(server, "chainsaw_result_export", {"handle": handle, "format": "csv"})
    assert csv_out["content"].splitlines()[0].startswith("rule,level")
    jsonl_out = call(
        server, "chainsaw_result_export", {"handle": handle, "format": "jsonl", "max_rows": 1}
    )
    assert jsonl_out["truncated"] is True and json.loads(jsonl_out["content"])["name"]

    listed = call(server, "chainsaw_result_list", {})
    assert handle in {r["handle"] for r in listed["results"]}
    assert call(server, "chainsaw_result_delete", {"handle": handle})["deleted"] is True


def test_hunt_filters_and_collections(server):
    only_critical = call(
        server,
        "chainsaw_hunt",
        {"paths": [CRED], "levels": ["critical"], "kinds": ["chainsaw"], "preview": 0},
    )
    assert all(v["value"] == "critical" for v in only_critical["summary"]["by_level"])
    assert all(v["value"] == "chainsaw" for v in only_critical["summary"]["by_source"])
    subtree = call(
        server,
        "chainsaw_hunt",
        {
            "paths": [BABYSHARK],
            "sigma_collections": ["rules/windows/process_creation"],
            "chainsaw_rules": False,
            "preview": 0,
        },
    )
    assert subtree["total"] >= 1


def test_search_patterns_and_tau(server):
    hits = call(
        server, "chainsaw_search", {"paths": [CRED], "patterns": ["mimikatz"], "preview": 1}
    )
    assert hits["total"] >= 1 and hits["summary"]["shape"] == "events"
    tau = call(
        server,
        "chainsaw_search",
        {
            "paths": [CRED],
            "tau": ["Event.System.EventID: =4624"],
            "from_time": "2019-01-01T00:00:00",
            "preview": 0,
        },
    )
    assert tau["total"] > 0
    assert all(v["value"] in (4624, "4624") for v in tau["summary"]["by_event_id"])
    dump = call(server, "chainsaw_dump", {"paths": [BABYSHARK], "preview": 1})
    assert dump["total"] > 0


def test_custom_rule_author_lint_hunt(server):
    rule = """\
title: PowerShell ScriptBlock Logging Seen
group: Custom
description: any 4104
authors: [tests]
kind: evtx
level: info
status: experimental
timestamp: Event.System.TimeCreated_attributes.SystemTime
fields:
  - name: Event ID
    to: Event.System.EventID
filter:
  condition: a
  a:
    Event.System.EventID: 4104
"""
    saved = call(
        server, "chainsaw_save_rule", {"name": "it_4104", "yaml_text": rule, "overwrite": True}
    )
    assert saved["lint"]["ok"] is True
    hunt = call(
        server,
        "chainsaw_hunt",
        {
            "paths": [CRED],
            "sigma": False,
            "chainsaw_rules": False,
            "extra_rules": ["custom"],
            "preview": 0,
        },
    )
    assert hunt["total"] > 0
    assert {v["value"] for v in hunt["summary"]["by_event_id"]} == {"4104"}
    assert {v["value"] for v in hunt["summary"]["by_rule"]} == {
        "PowerShell ScriptBlock Logging Seen"
    }
    lint = call(
        server, "chainsaw_lint_rules", {"kind": "chainsaw", "path": "evtx/credential_access"}
    )
    assert lint["ok"] is True and lint["total"] >= 1
    assert call(server, "chainsaw_delete_rule", {"name": "it_4104"})["deleted"] is True
