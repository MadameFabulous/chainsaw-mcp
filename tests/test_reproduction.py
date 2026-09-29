"""Execute exported scripts to check semantics, quoting, integrity and planning isolation."""

import hashlib
import json
import os
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from chainsaw_mcp.server import build_server
from tests.test_server import call, payload


@pytest.fixture
def replay_server(settings, tmp_path):
    binary = tmp_path / "fake chainsaw"
    binary.write_text(
        "#!/usr/bin/env python3\n"
        "import json, os, pathlib, sys\n"
        "args = sys.argv[1:]\n"
        "stdin = sys.stdin.read()\n"
        "result = json.dumps({'argv': args, 'no_color': os.environ.get('NO_COLOR'),"
        " 'stdin': stdin}) + '\\n'\n"
        "if '--output' in args:\n"
        "    pathlib.Path(args[args.index('--output') + 1]).write_text(result)\n"
        "else:\n"
        "    print(result)\n"
    )
    binary.chmod(0o700)
    return build_server(replace(settings, binary=binary, threads=2))


def seed(server, args, *, tool="chainsaw_search", commands=None):
    ctx = server._chainsaw_ctx
    handle, path = ctx.store.reserve()
    path.write_text('{"original":true}\n')
    ctx.store.commit(
        handle, tool=tool, argv=ctx.runner.command(args), inputs={"test": True}, commands=commands
    )
    return handle


def download(server, handle):
    chunks = []
    offset = 0
    while True:
        chunk = payload(
            call(
                server,
                "chainsaw_result_chunk",
                {
                    "handle": handle,
                    "byte_offset": offset,
                    "max_bytes": 4096,
                },
            )
        )
        chunks.append(chunk["content"])
        offset = chunk["next_byte_offset"]
        if offset is None:
            return "".join(chunks)


def run_script(server, script, tmp_path, binary=None, roots=None):
    path = tmp_path / "replay.sh"
    path.write_text(script)
    return subprocess.run(
        ["sh", str(path)],
        capture_output=True,
        text=True,
        # Replayed commands must not consume the caller's stdin, like live runs.
        input="caller stdin",
        env={
            **os.environ,
            "CHAINSAW_BIN": str(binary or server._chainsaw_ctx.settings.binary),
            "OUTPUT_PARENT": str(tmp_path),
            **(roots or {}),
        },
    )


def test_recorded_replay_preserves_arguments_and_quotes_untrusted_values(replay_server, tmp_path):
    server = replay_server
    root = server._chainsaw_ctx.settings.evidence_roots[0]
    evidence = root / "it's $(touch INJECTED); evidence.json"
    evidence.write_text('{"event":1}')
    pattern = "$(touch INJECTED); `id` 'quoted'\\pattern"
    handle = seed(
        server,
        [
            "search",
            "--jsonl",
            f"--regex={pattern}",
            "--from",
            "2025-01-01T00:00:00",
            "--output",
            "/old/.pending",
            "--",
            str(evidence),
        ],
    )
    result = payload(call(server, "chainsaw_reproduce", {"handles": [handle, handle]}))
    assert result["commands"] == 1 and result["mode"] == "recorded"
    script = download(server, result["script_handle"])
    assert hashlib.sha256(script.encode()).hexdigest() == result["script_sha256"]
    assert "/old/.pending" not in script
    executed = run_script(server, script, tmp_path)
    assert executed.returncode == 0, executed.stderr
    output = Path(executed.stdout.strip().split("Replay output: ")[-1])
    recorded = json.loads((output / f"001-{handle}.jsonl").read_text())
    assert recorded["no_color"] == "1" and recorded["stdin"] == ""
    argv = recorded["argv"]
    assert f"--regex={pattern}" in argv and str(evidence) in argv
    assert "--num-threads=2" in argv and "2025-01-01T00:00:00" in argv
    assert not Path("INJECTED").exists()
    manifest = [
        json.loads(line) for line in download(server, result["manifest_handle"]).splitlines()
    ]
    assert manifest[0]["mode"] == "recorded"
    assert any(row.get("path") == str(evidence) and row["sha256"] for row in manifest)
    evidence.write_text("changed after export")
    changed = run_script(server, script, tmp_path)
    assert changed.returncode == 1 and str(evidence) in changed.stderr
    assert "checksum mismatch" in changed.stderr


def test_replay_reports_binary_digest_mismatch(replay_server, tmp_path):
    server = replay_server
    root = server._chainsaw_ctx.settings.evidence_roots[0]
    handle = seed(server, ["search", "--jsonl", "--", str(root / "host1/Security.evtx")])
    result = payload(call(server, "chainsaw_reproduce", {"handles": [handle]}))
    script = download(server, result["script_handle"])
    other = tmp_path / "other chainsaw"
    other.write_text("#!/bin/sh\n")
    other.chmod(0o700)
    executed = run_script(server, script, tmp_path, binary=other)
    assert executed.returncode == 1 and str(other) in executed.stderr
    assert "digest mismatch" in executed.stderr


def test_overlapping_dependencies_are_inventoried_once(replay_server):
    server = replay_server
    root = server._chainsaw_ctx.settings.evidence_roots[0]
    nested = root / "host1"
    source = nested / "Security.evtx"
    handle = seed(server, ["search", "--jsonl", "--", str(root), str(nested), str(source)])
    result = payload(call(server, "chainsaw_reproduce", {"handles": [handle]}))
    rows = [json.loads(line) for line in download(server, result["manifest_handle"]).splitlines()]
    paths = [row["path"] for row in rows if row["kind"] == "input"]
    assert paths.count(str(source)) == 1 and len(paths) == len(set(paths))


def test_overlapping_roots_check_every_replay_expression(settings, replay_server, tmp_path):
    root = settings.evidence_roots[0]
    nested = root / "host1"
    source = nested / "Security.evtx"
    configured = replay_server._chainsaw_ctx.settings
    server = build_server(replace(configured, evidence_roots=[root, nested]))
    # The directory replays through EVIDENCE_1 and the file through EVIDENCE_2.
    handle = seed(server, ["search", "--jsonl", "--", str(root), str(source)])
    result = payload(call(server, "chainsaw_reproduce", {"handles": [handle]}))
    rows = [json.loads(line) for line in download(server, result["manifest_handle"]).splitlines()]
    expressions = {row["shell_path"] for row in rows if row.get("path") == str(source)}
    assert expressions == {'"${EVIDENCE_1}"/host1/Security.evtx', '"${EVIDENCE_2}"/Security.evtx'}
    script = download(server, result["script_handle"])
    assert run_script(server, script, tmp_path).returncode == 0
    relocated = tmp_path / "relocated"
    relocated.mkdir()
    (relocated / "Security.evtx").write_bytes(b"modified bytes")
    path = tmp_path / "replay.sh"
    path.write_text(script)
    changed = subprocess.run(
        ["sh", str(path)],
        capture_output=True,
        text=True,
        env={
            **os.environ,
            "CHAINSAW_BIN": str(server._chainsaw_ctx.settings.binary),
            "OUTPUT_PARENT": str(tmp_path),
            "EVIDENCE_2": str(relocated),
        },
    )
    assert changed.returncode == 1 and "checksum mismatch" in changed.stderr
    assert str(relocated / "Security.evtx") in changed.stderr


def test_plan_shares_real_arguments_without_running_chainsaw(replay_server, monkeypatch):
    server = replay_server

    def forbidden(*args, **kwargs):
        raise AssertionError("Planning must never execute Chainsaw")

    monkeypatch.setattr(subprocess, "run", forbidden)
    steps = [
        {
            "tool": "chainsaw_search",
            "arguments": {
                "paths": ["host1/Security.evtx"],
                "patterns": ["-literal"],
                "tau": ["Event.System.EventID: =4104"],
                "from_time": "2025-01-01T00:00:00",
            },
        },
        {"tool": "chainsaw_dump", "arguments": {"paths": ["host1/Security.evtx"]}},
    ]
    result = payload(call(server, "chainsaw_plan", {"steps": steps}))
    assert result["mode"] == "planned" and result["commands"] == 2
    rows = [json.loads(line) for line in download(server, result["manifest_handle"]).splitlines()]
    assert not any(row["kind"] == "result" for row in rows)
    commands = [row for row in rows if row["kind"] == "command"]
    assert all(row["executed"] is False and "recorded_argv" not in row for row in commands)
    assert "--regex=-literal" in commands[0]["planned_argv"]
    assert "--timestamp" in commands[0]["planned_argv"]
    assert not list(server._chainsaw_ctx.store.directory.glob("*.pending"))
    steps[0]["arguments"]["paths"] = ["../../outside"]
    assert call(server, "chainsaw_plan", {"steps": steps}).is_error
    steps[0]["arguments"]["paths"] = ["host1/Security.evtx"]
    steps[0]["arguments"]["typo"] = True
    assert call(server, "chainsaw_plan", {"steps": steps}).is_error


def test_mapping_snapshot_survives_original_removal(replay_server, tmp_path):
    ctx = replay_server._chainsaw_ctx
    derived = ctx.settings.output_dir / ".mappings" / "derived.yml"
    derived.parent.mkdir()
    derived.write_text("name: original mapping\n")
    handle = seed(
        replay_server,
        [
            "hunt",
            "--mapping",
            str(derived),
            "--jsonl",
            "--output",
            "/old/.pending",
            "--",
            str(ctx.settings.evidence_roots[0]),
        ],
        tool="chainsaw_hunt",
    )
    result = payload(call(replay_server, "chainsaw_reproduce", {"handles": [handle]}))
    script = download(replay_server, result["script_handle"])
    derived.unlink()
    executed = run_script(replay_server, script, tmp_path)
    assert executed.returncode == 0, executed.stderr
    output = Path(executed.stdout.strip().split("Replay output: ")[-1])
    assert (output / "assets/mapping-1.yml").read_text() == "name: original mapping\n"


def test_multicommand_and_legacy_results(replay_server):
    server = replay_server
    ctx = server._chainsaw_ctx
    source = str(ctx.settings.evidence_roots[0] / "host1/Security.evtx")
    commands = [
        ctx.runner.command(["search", f"--regex={guid}", "--", source])
        for guid in ("first", "second")
    ]
    handle = seed(
        server, ["search", "--", source], tool="chainsaw_process_lineage", commands=commands
    )
    assert payload(call(server, "chainsaw_reproduce", {"handles": [handle]}))["commands"] == 2
    legacy = seed(server, ["search", "--", source], tool="chainsaw_process_lineage")
    assert (
        "Legacy lineage"
        in call(server, "chainsaw_reproduce", {"handles": [legacy]}).content[0].text
    )
    assert call(server, "chainsaw_reproduce", {"handles": ["res_" + "0" * 16]}).is_error
    bad = seed(server, ["dump", "--", "/etc/passwd"])
    assert call(server, "chainsaw_reproduce", {"handles": [bad]}).is_error


@pytest.mark.parametrize("planned", [False, True])
def test_redacted_exports_require_roots_and_replay_relocated_inputs(
    replay_server, tmp_path, planned
):
    server = replay_server
    ctx = server._chainsaw_ctx
    source = ctx.settings.evidence_roots[0] / "host1/Security.evtx"
    if planned:
        tool = "chainsaw_plan"
        arguments = {"steps": [{"tool": "chainsaw_dump", "arguments": {"paths": [str(source)]}}]}
    else:
        tool = "chainsaw_reproduce"
        handle = seed(
            server, ["dump", "--jsonl", "--output", "/private/old.pending", "--", str(source)]
        )
        arguments = {"handles": [handle]}
    result = payload(call(server, tool, {**arguments, "redact_paths": True, "hash_inputs": True}))
    script = download(server, result["script_handle"])
    manifest = download(server, result["manifest_handle"])
    for path in [ctx.settings.binary, ctx.settings.output_dir, *ctx.settings.evidence_roots]:
        assert str(path) not in script + manifest
    assert "/private/old.pending" not in manifest
    rows = [json.loads(line) for line in manifest.splitlines()]
    assert result["path_mode"] == rows[0]["path_mode"] == "redacted"
    command = next(row for row in rows if row["kind"] == "command")
    assert "recorded_argv" not in command and "planned_argv" not in command
    assert command["rebased_argv"][0] == "${CHAINSAW_BIN}"
    assert command["executed"] is not planned
    missing = run_script(server, script, tmp_path)
    assert missing.returncode != 0 and "Set EVIDENCE_1" in missing.stderr
    relocated = tmp_path / "relocated inputs ' $(literal)"
    (relocated / "host1").mkdir(parents=True)
    target = relocated / "host1/Security.evtx"
    target.write_bytes(source.read_bytes())
    executed = run_script(server, script, tmp_path, roots={"EVIDENCE_1": str(relocated)})
    assert executed.returncode == 0, executed.stderr
    output = Path(executed.stdout.strip().split("Replay output: ")[-1])
    native = json.loads(next(output.glob("*.jsonl")).read_text())
    assert str(target) in native["argv"]
    target.write_text("modified")
    changed = run_script(server, script, tmp_path, roots={"EVIDENCE_1": str(relocated)})
    assert changed.returncode == 1
    original = payload(call(server, tool, arguments))
    assert original["path_mode"] == "verbatim"
    assert str(source) in download(server, original["manifest_handle"])


def test_redacted_mapping_paths_and_literal_path_leaks(replay_server):
    server = replay_server
    ctx = server._chainsaw_ctx
    source = str(ctx.settings.evidence_roots[0] / "host1/Security.evtx")
    mapping = ctx.settings.mappings_dir / "redacted.yml"
    mapping.write_text("name: replay mapping\n")
    handle = seed(server, ["hunt", "--mapping", str(mapping), "--", source])
    result = payload(
        call(server, "chainsaw_reproduce", {"handles": [handle], "redact_paths": True})
    )
    manifest = download(server, result["manifest_handle"])
    assert str(mapping) not in manifest
    rows = [json.loads(line) for line in manifest.splitlines()]
    command = next(row for row in rows if row["kind"] == "command")
    assert "${OUTPUT_DIR}/assets/mapping-1.yml" in command["rebased_argv"]
    mapping.write_text("name: " + str(ctx.settings.output_dir) + "\n")
    bad = call(server, "chainsaw_reproduce", {"handles": [handle], "redact_paths": True})
    assert bad.is_error and "Mapping contains server paths" in bad.content[0].text
    literal = seed(server, ["search", "--regex=" + source, "--", source])
    bad = call(server, "chainsaw_reproduce", {"handles": [literal], "redact_paths": True})
    assert bad.is_error and "literal command argument" in bad.content[0].text
    assert not list(ctx.store.directory.glob("*.pending"))


def test_legacy_evtx_partial_status_is_reported_per_handle(replay_server):
    server = replay_server
    ctx = server._chainsaw_ctx
    source = str(ctx.settings.evidence_roots[0] / "host1/Security.evtx")
    args = ["analyse", "evtx", "--", source]
    legacy = seed(server, args, tool="chainsaw_analyse_evtx")
    current = seed(server, args, tool="chainsaw_analyse_evtx", commands=[ctx.runner.command(args)])
    search = seed(server, ["search", "--", source])
    result = payload(call(server, "chainsaw_reproduce", {"handles": [legacy, current, search]}))
    expected = [{"handle": legacy, "reason": "legacy_evtx_command_history_missing"}]
    assert result["partial"] is True and result["partial_handles"] == expected
    rows = [json.loads(line) for line in download(server, result["manifest_handle"]).splitlines()]
    assert rows[0]["partial"] is True and rows[0]["partial_handles"] == expected
    by_handle = {row["handle"]: row for row in rows if row["kind"] == "result"}
    assert by_handle[legacy]["partial"] is True
    assert by_handle[legacy]["partial_reason"] == expected[0]["reason"]
    assert by_handle[current]["partial"] is False and by_handle[search]["partial"] is False
    complete = payload(call(server, "chainsaw_reproduce", {"handles": [current, search]}))
    assert complete["partial"] is False and complete["partial_handles"] == []


def test_redacted_plan_normalises_absolute_input_aliases(replay_server, tmp_path):
    server = replay_server
    root = server._chainsaw_ctx.settings.evidence_roots[0]
    alias = tmp_path / "private-server-layout"
    alias.symlink_to(root, target_is_directory=True)
    source = str(alias / "host1/Security.evtx")
    steps = [{"tool": "chainsaw_dump", "arguments": {"paths": [source]}}]
    result = payload(call(server, "chainsaw_plan", {"steps": steps, "redact_paths": True}))
    manifest = download(server, result["manifest_handle"])
    assert str(alias) not in manifest
    rows = [json.loads(line) for line in manifest.splitlines()]
    command = next(row for row in rows if row["kind"] == "command")
    assert command["inputs"]["paths"] == ["${EVIDENCE_1}/host1/Security.evtx"]
    original = payload(call(server, "chainsaw_plan", {"steps": steps}))
    assert source in download(server, original["manifest_handle"])
