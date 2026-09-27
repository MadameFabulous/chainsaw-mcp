"""Regressions from the publishing review: runner hygiene, path handling, result paging."""

from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from chainsaw_mcp import cli, security
from chainsaw_mcp.mapping import STOCK_MAPPING_SHA256
from chainsaw_mcp.paths import iter_artefacts
from chainsaw_mcp.result_budget import DEFAULT_MAX_BYTES
from chainsaw_mcp.results import _matches, event_identity
from chainsaw_mcp.rules import DERIVED_MAPPING, RuleCatalog, RuleError
from chainsaw_mcp.runner import ChainsawError, Runner, environment
from chainsaw_mcp.server import annotations_for, build_server
from chainsaw_mcp.tools._common import ToolContext, check_window
from chainsaw_mcp.tools.analyse import AnalyseTools
from chainsaw_mcp.tools.hunt import HuntTools
from chainsaw_mcp.tools.results import ResultTools
from chainsaw_mcp.tools.rules import _LINT_LINE, _relative_problem_path
from tests.conftest import MINIMAL_RULE, REPO, requires_binary
from tests.test_result_improvements import A, lineage_context
from tests.test_server import call, payload

STOCK_MAPPING = REPO / "vendor" / "chainsaw" / "mappings" / "sigma-event-logs-all.yml"


def seed_rows(store, rows, tool="chainsaw_hunt"):
    handle, path = store.reserve()
    path.write_text("".join(json.dumps(row) + "\n" for row in rows))
    store.commit(handle, tool=tool, argv=["hunt"], inputs={})
    return handle


def aggregate_row(name="Aggregate rule", level="high", hosts=("DC01", "WS01")):
    """A hunt row from an aggregate rule: several documents, no single 'document'."""
    return {
        "name": name,
        "level": level,
        "timestamp": "2024-01-01T00:00:00.000Z",
        "documents": [
            {
                "kind": "evtx",
                "path": f"/srv/evidence/{host}.evtx",
                "data": {
                    "Event": {
                        "System": {
                            "Computer": host,
                            "EventID": 4624 + index,
                            "Channel": "Security",
                            "EventRecordID": 10 + index,
                            "TimeCreated_attributes": {"SystemTime": "2024-01-01T00:00:00Z"},
                        }
                    }
                },
            }
            for index, host in enumerate(hosts)
        ],
    }


# --- runner -------------------------------------------------------------------------------


def test_runner_environment_is_minimal_and_colourless(monkeypatch):
    monkeypatch.setenv("PATH", "/usr/bin")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "leak")
    monkeypatch.setenv("TYPESAFE_API_KEY", "leak")
    env = environment()
    assert env["NO_COLOR"] == "1"
    assert env["PATH"] == "/usr/bin"
    assert "AWS_SECRET_ACCESS_KEY" not in env
    assert "TYPESAFE_API_KEY" not in env


def test_runner_never_silences_chainsaw(tmp_path, monkeypatch):
    fake = tmp_path / "chainsaw"
    fake.write_text(
        "#!/bin/sh\n"
        'printf "%s\\n" "$@"\n'
        'echo "NO_COLOR=$NO_COLOR" >&2\n'
        'echo "LEAK=${LEAK:-unset}" >&2\n'
    )
    fake.chmod(0o755)
    monkeypatch.setenv("LEAK", "secret")
    result = Runner(fake, timeout=5, threads=0).run(["hunt", "--rule", "x"])
    argv = result.stdout.splitlines()
    assert argv == ["--no-banner", "hunt", "--rule", "x"]
    assert "-q" not in argv and "--quiet" not in argv
    assert "NO_COLOR=1" in result.messages
    assert "LEAK=unset" in result.messages


# --- transport security --------------------------------------------------------------------


def test_transport_security_brackets_ipv6_and_keeps_origins_local():
    settings = security.transport_security("fd7a::1", 18098, env={})
    assert "[fd7a::1]" in settings.allowed_hosts
    assert "[fd7a::1]:18098" in settings.allowed_hosts
    assert "http://[fd7a::1]:*" in settings.allowed_origins
    assert all(origin.startswith("http://") for origin in settings.allowed_origins)
    assert "*" not in settings.allowed_hosts
    assert settings.enable_dns_rebinding_protection


# --- evidence paths and messages -------------------------------------------------------------


def test_evidence_paths_drop_duplicates_and_files_inside_listed_directories(settings):
    ctx = ToolContext(settings)
    root = settings.evidence_roots[0]
    resolved = ctx.evidence_paths(["host1", "host1/Security.evtx", "./host1", "host1/notes.txt"])
    assert resolved == [str(root / "host1")]
    single = ctx.evidence_paths(["host1/Security.evtx", "host1/Security.evtx"])
    assert single == [str(root / "host1" / "Security.evtx")]


def test_redact_replaces_server_paths_with_stable_names(settings):
    ctx = ToolContext(settings)
    root = settings.evidence_roots[0]
    messages = ctx.redact(
        [
            f"[+] Loading detection rules from: {settings.rules_dir}/evtx",
            f"[!] failed to load file: {root}/host1/Security.evtx",
            f"[+] Cache: {settings.output_dir}/.mappings/x.yml",
            "[+] 0 Detections found on 0 documents",
        ]
    )
    assert messages == [
        "[+] Loading detection rules from: <rules>/evtx",
        "[!] failed to load file: evidence/host1/Security.evtx",
        "[+] Cache: <results>/.mappings/x.yml",
        "[+] 0 Detections found on 0 documents",
    ]
    assert not any(str(settings.home) in line for line in messages)


@requires_binary
def test_hunt_messages_never_carry_server_paths(settings):
    out = payload(call(build_server(settings), "chainsaw_hunt", {"paths": ["host1"]}))
    messages = out["chainsaw_messages"]
    assert messages, "chainsaw's message stream must stay visible without -q"
    assert not any(str(settings.home) in line for line in messages)


def test_listing_skips_hidden_entries_and_escaping_symlinks(tmp_path):
    base = tmp_path / "evidence"
    (base / ".git").mkdir(parents=True)
    (base / ".git" / "HEAD.evtx").write_bytes(b"x")
    (base / ".hidden.evtx").write_bytes(b"x")
    (base / "visible.evtx").write_bytes(b"x")
    outside = tmp_path / "outside.evtx"
    outside.write_bytes(b"x")
    (base / "escape.evtx").symlink_to(outside)
    (base / "inside-link.evtx").symlink_to(base / "visible.evtx")
    assert [entry["relative"] for entry in iter_artefacts(base)] == [
        "inside-link.evtx",
        "visible.evtx",
    ]


# --- time windows --------------------------------------------------------------------------


def test_check_window_rejects_inverted_ranges():
    check_window(None, None)
    check_window("2024-01-01T00:00:00", "2024-01-01T00:00:00")
    check_window("2024-01-01T00:00:00", None)
    with pytest.raises(ValueError, match="later than to_time"):
        check_window("2024-01-02T00:00:00", "2024-01-01T00:00:00")


@pytest.mark.parametrize("tool", ["chainsaw_hunt", "chainsaw_search", "chainsaw_analyse_gaps"])
def test_tools_reject_inverted_windows_before_running(settings, tool):
    args = {
        "paths": ["host1"],
        "from_time": "2024-01-02T00:00:00",
        "to_time": "2024-01-01T00:00:00",
    }
    if tool == "chainsaw_search":
        args["patterns"] = ["x"]
    result = call(build_server(settings), tool, args)
    assert result.is_error
    assert "later than to_time" in result.content[0].text


# --- lint output ---------------------------------------------------------------------------


def test_lint_lines_without_a_file_name_map_to_the_linted_path(tmp_path):
    match = _LINT_LINE.match("[!] : missing field: authors")
    assert match
    assert match.group("file") == ""
    assert match.group("message") == "missing field: authors"
    rule = tmp_path / "custom" / "x.yml"
    rule.parent.mkdir()
    rule.write_text("title: x\n")
    assert _relative_problem_path("", rule, "x.yml") == "x.yml"
    assert _relative_problem_path(str(rule), rule, "x.yml") == "x.yml"
    assert _relative_problem_path(str(rule), rule.parent, ".") == "x.yml"


# --- result store --------------------------------------------------------------------------


def test_result_list_pages_newest_first(settings):
    ctx = ToolContext(settings)
    handles = {seed_rows(ctx.store, [{"name": f"r{i}"}]) for i in range(3)}
    tools = ResultTools(ctx)
    first = json.loads(tools.chainsaw_result_list(limit=2))
    assert (first["total"], first["returned"], first["next_offset"]) == (3, 2, 2)
    assert first["results"][0]["created"] >= first["results"][1]["created"]
    assert "argv" not in first["results"][0]
    last = json.loads(tools.chainsaw_result_list(offset=2, limit=2))
    assert (last["returned"], last["next_offset"]) == (1, None)
    assert {r["handle"] for r in first["results"] + last["results"]} == handles


def test_result_list_fits_metadata_pages_without_losing_handles(settings):
    server = build_server(settings)
    store = server._chainsaw_ctx.store
    handles = set()
    for index in range(6):
        handle, path = store.reserve()
        path.write_text("{}\n")
        store.commit(
            handle, tool="chainsaw_search", argv=[], inputs={"patterns": ["x" * 12_000, index]}
        )
        handles.add(handle)
    seen = []
    offset = 0
    while offset is not None:
        result = call(server, "chainsaw_result_list", {"offset": offset})
        page = payload(result)
        assert page["returned_bytes"] == len(result.content[0].text.encode()) <= DEFAULT_MAX_BYTES
        assert page["returned"] > 0
        seen.extend(entry["handle"] for entry in page["results"])
        for entry in page["results"]:
            assert len(entry["inputs"]["patterns"][0]) == 12_000
        next_offset = page["next_offset"]
        if next_offset is not None:
            assert next_offset == offset + page["returned"]
            assert page["truncated"] and page["truncation_reason"] == "max_bytes"
        else:
            assert not page["truncated"]
        offset = next_offset
    assert len(seen) == len(handles) and set(seen) == handles


@pytest.mark.parametrize("operand", [9007199254740993, "9007199254740993", "9007199254740993.0"])
def test_numeric_filters_preserve_large_integer_precision_over_mcp(settings, operand):
    server = build_server(settings)
    handle = seed_rows(
        server._chainsaw_ctx.store,
        [{"value": number} for number in (9007199254740992, 9007199254740993)],
        tool="chainsaw_dump",
    )
    args = {"handle": handle, "where": {"value": operand}}
    page = payload(call(server, "chainsaw_result_page", args))
    assert page["total"] == 1
    assert page["rows"] == [{"value": 9007199254740993}]
    summary = payload(call(server, "chainsaw_result_summary", args))
    assert summary["total"] == 1


def test_aggregate_rows_page_filter_and_group(settings):
    store = ToolContext(settings).store
    handle = seed_rows(store, [aggregate_row(), aggregate_row("Other", "low", ("SRV01",))])
    page = store.page(handle, where={"computer": "ws01"}, fields=["rule", "computer", "event_id"])
    assert page["total"] == 1
    assert page["rows"][0] == {
        "rule": "Aggregate rule",
        "computer": ["DC01", "WS01"],
        "event_id": [4624, 4625],
    }
    assert store.page(handle, where={"event_id": "4624"})["total"] == 2
    assert store.page(handle, where={"event_id": "4625"})["total"] == 1
    assert store.page(handle, where={"event_id": "462"})["total"] == 0
    assert store.page(handle, where={"level": "LOW"})["total"] == 1
    grouped = store.summary(handle, group_by=["computer"])["groups"]
    group = next(iter(grouped.values()))
    assert group["distinct"] == 3
    assert {entry["value"]: entry["count"] for entry in group["top"]} == {
        "DC01": 1,
        "WS01": 1,
        "SRV01": 1,
    }
    events = store.events(handle)
    assert events["total"] == 3


def test_where_matches_numbers_exactly_and_text_by_substring():
    assert _matches(4624, "4624")
    assert not _matches(4624, "462")
    assert _matches(4624.0, "4624")
    assert _matches(True, "true")
    assert not _matches(True, "1")
    assert _matches("DC01.corp.example", "dc01")
    assert not _matches(None, "")
    assert _matches(["a", "b"], "b")


def test_search_rows_without_a_source_path_keep_a_conservative_identity():
    system = {
        "Computer": "DC01",
        "Channel": "Security",
        "EventRecordID": 7,
        "TimeCreated_attributes": {"SystemTime": "2024-01-01T00:00:00Z"},
    }
    row = {"Event": {"System": system, "EventData": {"a": 1}}}
    other = {"Event": {"System": system, "EventData": {"a": 2}}}
    assert event_identity(row) == event_identity(json.loads(json.dumps(row)))
    assert event_identity(row) != event_identity(other)
    assert event_identity(row)[0] == ""
    assert event_identity({"Event": {"System": {"Computer": "DC01"}}}) is None
    detection = {"name": "r", "document": {"path": "/x/a.evtx", "data": row}}
    assert event_identity(detection)[0] == "/x/a.evtx"
    assert event_identity({"name": "r", "document": {"data": row}}) is None


# --- rules ---------------------------------------------------------------------------------


def test_save_rule_requires_every_chainsaw_field(settings):
    catalog = RuleCatalog(settings)
    with pytest.raises(RuleError, match="group"):
        catalog.save_custom_rule("incomplete", MINIMAL_RULE.replace("group: Test\n", ""))
    assert not (settings.custom_rules_dir / "incomplete.yml").exists()


def test_save_rule_rejects_aliases_and_oversized_documents(settings):
    catalog = RuleCatalog(settings)
    with pytest.raises(RuleError, match="aliases"):
        catalog.save_custom_rule("bomb", MINIMAL_RULE + "x: &a [1, 2]\ny: *a\n")
    with pytest.raises(RuleError, match="exceeds"):
        catalog.save_custom_rule("big", MINIMAL_RULE + "# " + "x" * 70_000 + "\n")
    assert not list(settings.custom_rules_dir.glob("*.yml"))


@pytest.mark.skipif(
    not STOCK_MAPPING.exists()
    or hashlib.sha256(STOCK_MAPPING.read_bytes()).hexdigest() != STOCK_MAPPING_SHA256,
    reason="stock Chainsaw mapping not installed",
)
def test_derived_mapping_is_addressable_by_name(settings):
    catalog = RuleCatalog(settings)
    with pytest.raises(RuleError, match="not installed"):
        catalog.mapping(DERIVED_MAPPING)
    assert DERIVED_MAPPING not in catalog.mapping_names()
    (settings.mappings_dir / "sigma-event-logs-all.yml").write_bytes(STOCK_MAPPING.read_bytes())
    assert DERIVED_MAPPING in catalog.mapping_names()
    derived = catalog.mapping(DERIVED_MAPPING)
    assert derived.name == DERIVED_MAPPING
    assert derived == catalog.mapping(None)
    assert catalog.mapping("sigma-event-logs-all.yml").name == "sigma-event-logs-all.yml"
    out = payload(call(build_server(settings), "chainsaw_get_mapping", {"name": DERIVED_MAPPING}))
    assert "provider-aware" in json.dumps(out)


# --- analysis ------------------------------------------------------------------------------


def test_srum_without_output_fails_instead_of_storing_an_empty_file(settings):
    ctx = ToolContext(settings)
    root = settings.evidence_roots[0]
    (root / "SRUDB.dat").write_bytes(b"x")
    (root / "SOFTWARE").write_bytes(b"x")
    ctx.runner = SimpleNamespace(
        run=lambda args: SimpleNamespace(stdout="", messages=[], argv=args, duration_seconds=0.0)
    )
    with pytest.raises(ChainsawError, match="no output"):
        AnalyseTools(ctx).chainsaw_analyse_srum("SRUDB.dat", "SOFTWARE")
    assert not list(settings.output_dir.glob("res_*"))


def test_lineage_query_cap_is_checked_before_each_guid(tmp_path):
    from chainsaw_mcp.tools.hunt import HuntTools

    ctx, evidence, calls = lineage_context(tmp_path)
    out = json.loads(
        HuntTools(ctx).chainsaw_process_lineage([str(evidence)], A, "pc", max_hops=3, max_queries=1)
    )
    lineage = out["lineage"]
    assert lineage["queries"] == 1
    assert lineage["queried_guids"] == 1
    assert lineage["query_limit_reached"]
    assert not lineage["hop_limit_reached"]
    assert not lineage["complete"]
    # Only the seed process was queried; its host matched case-insensitively ("pc" vs "PC").
    rows = list(ctx.store.rows(out["handle"]))
    assert [r["Event"]["EventData"]["ProcessGuid"] for r in rows] == [A]


# --- cli, annotations, configuration -------------------------------------------------------


def test_help_documents_environment_overrides(capsys):
    with pytest.raises(SystemExit) as exit_info:
        cli.main(["--help"])
    assert exit_info.value.code == 0
    text = capsys.readouterr().out
    for name in ("MCP_TRANSPORT", "MCP_HOST", "MCP_PORT", "MCP_PATH"):
        assert name in text


def test_save_rule_is_destructive_and_jev_is_open_world():
    save = annotations_for("chainsaw_save_rule")
    assert save.destructive_hint and not save.read_only_hint
    triage = annotations_for("chainsaw_jev_triage")
    assert triage.open_world_hint and not triage.read_only_hint and not triage.destructive_hint


def test_configuration_reports_where_jev_credentials_come_from(settings, monkeypatch, capsys):
    assert settings.describe()["jev"]["credential_source"] is None
    via_bws = replace(settings, jev_enabled=True, jev_bws_secret_id="x")
    assert via_bws.describe()["jev"]["credential_source"] == "bws"
    via_env = replace(via_bws, jev_api_key="k")
    assert via_env.describe()["jev"]["credential_source"] == "env"
    assert "k" not in json.dumps(via_env.describe())
    monkeypatch.setattr(cli, "load_settings", lambda: via_bws)
    monkeypatch.setattr(
        "chainsaw_mcp.jev.api_key", lambda *a, **k: pytest.fail("--check must not fetch the key")
    )
    assert cli.main(["--check"]) == 0
    jev_block = json.loads(capsys.readouterr().out)["config"]["jev"]
    assert (
        jev_block.items()
        >= {
            "enabled": True,
            "credentials_configured": True,
            "credential_source": "bws",
            "model": via_bws.jev_model,
            "timeout_seconds": via_bws.jev_timeout,
        }.items()
    )


# --- Review: same-document filters, primitive operands, hunt diagnostics -----------


def test_aggregate_filters_match_the_same_document(settings):
    store = ToolContext(settings).store
    handle = seed_rows(store, [aggregate_row()])
    same_event = {"computer": "DC01", "event_id": "4624"}
    crossed = {"computer": "DC01", "event_id": "4625"}
    assert store.page(handle, where=same_event)["total"] == 1
    assert store.page(handle, where=crossed)["total"] == 0
    assert store.summary(handle, where=crossed)["detection_count"] == 0
    assert store.page(handle, where={**same_event, "level": "low"})["total"] == 0
    assert store.page(handle, where={**same_event, "level": "HIGH"})["total"] == 1
    # Filtering selects whole detection rows: projection and summaries keep every document.
    page = store.page(handle, where=same_event, fields=["computer"])
    assert page["rows"][0]["computer"] == ["DC01", "WS01"]
    summary = store.summary(handle, where=same_event)
    assert (summary["detection_count"], summary["unique_event_count"]) == (1, 2)
    grouped = store.summary(handle, where=same_event, group_by=["computer"])["groups"]
    hosts = next(iter(grouped.values()))
    assert {entry["value"] for entry in hosts["top"]} == {"DC01", "WS01"}


def test_where_operands_accept_primitives_over_mcp(settings):
    store = ToolContext(settings).store
    flagged = {"name": "flag", "level": "low", "flagged": True}
    handle = seed_rows(store, [aggregate_row(), flagged])
    server = build_server(settings)

    def page(where):
        return payload(call(server, "chainsaw_result_page", {"handle": handle, "where": where}))

    def summary(where):
        args = {"handle": handle, "where": where}
        return payload(call(server, "chainsaw_result_summary", args))

    assert page({"event_id": 4624}) == page({"event_id": "4624"}) == page({"event_id": 4624.0})
    assert page({"event_id": 4624})["total"] == 1
    assert page({"event_id": 462})["total"] == 0
    assert summary({"event_id": 4624}) == summary({"event_id": "4624"})
    assert summary({"event_id": 4624})["detection_count"] == 1
    assert page({"flagged": True})["total"] == page({"flagged": "TRUE"})["total"] == 1
    assert page({"flagged": False})["total"] == page({"flagged": 1})["total"] == 0


@requires_binary
def test_hunt_keeps_every_load_warning_behind_a_diagnostics_handle(settings):
    ctx = ToolContext(settings)
    root = settings.evidence_roots[0] / "corrupt"
    root.mkdir()
    for i in range(600):
        (root / f"{i:04d}-corrupt.evtx").write_bytes(b"not an event log")
    raw = HuntTools(ctx).chainsaw_hunt(paths=["corrupt"], sigma=False, skip_errors=True, preview=0)
    assert len(raw.encode()) <= 65_536
    result = json.loads(raw)
    assert result["total"] == 0
    assert ctx.store.meta(result["handle"]).count == 0
    diagnostics = result["diagnostics"]
    assert "messages" not in diagnostics, "the preview lives under chainsaw_messages only"
    assert diagnostics["messages_truncated"] is True
    assert ctx.store.meta(diagnostics["handle"]).tool == "chainsaw_hunt_diagnostics"
    stored = [row["message"] for row in ctx.store.rows(diagnostics["handle"])]
    assert len(stored) == diagnostics["message_count"] >= 600
    preview = result["chainsaw_messages"]
    assert preview and preview == stored[: len(preview)]
    assert all(str(settings.home) not in line for line in stored)
    for i in range(600):
        assert any(f"{i:04d}-corrupt.evtx" in line for line in stored)


def test_empty_message_stream_keeps_the_diagnostics_contract(settings):
    ctx = ToolContext(settings)
    handle, _path = ctx.store.reserve()
    result = json.loads(
        HuntTools(ctx)._finish(
            tool="chainsaw_search",
            handle=handle,
            argv=[],
            inputs={},
            messages=[],
            duration=0,
            preview=0,
        )
    )
    assert result["chainsaw_messages"] == []
    diagnostics = result["diagnostics"]
    assert (diagnostics["message_count"], diagnostics["messages_truncated"]) == (0, False)
    assert ctx.store.page(diagnostics["handle"])["total"] == 0
    assert ctx.store.meta(diagnostics["handle"]).tool == "chainsaw_search_diagnostics"
