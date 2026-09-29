"""Native replay must produce the same forensic records as the MCP invocation."""

import json
from pathlib import Path

import pytest

from chainsaw_mcp.server import build_server
from tests.conftest import requires_binary
from tests.test_reproduction import download, run_script
from tests.test_server import call, payload

pytestmark = [pytest.mark.integration, requires_binary]


@pytest.mark.parametrize(
    "tool,extra",
    [
        ("chainsaw_dump", {}),
        ("chainsaw_search", {"tau": ["Event.System.EventID: =4104"]}),
        ("chainsaw_hunt", {"sigma": False}),
    ],
)
def test_native_commands_reproduce_records(settings, tmp_path, tool, extra):
    evidence = settings.evidence_roots[0] / "records.json"
    evidence.write_text(
        json.dumps(
            {
                "Event": {
                    "System": {
                        "EventID": 4104,
                        "Computer": "test",
                        "TimeCreated_attributes": {
                            "SystemTime": "2025-01-01T01:00:00Z",
                        },
                    }
                }
            }
        )
    )
    server = build_server(settings)
    if tool == "chainsaw_hunt":
        rule = next(settings.rules_dir.rglob("*.yml"))
        rule.write_text(rule.read_text().replace("kind: evtx", "kind: json"))
    original = payload(call(server, tool, {"paths": [str(evidence)], **extra}))
    handle = original["handle"]
    bundle = payload(call(server, "chainsaw_reproduce", {"handles": [handle]}))
    replay = run_script(server, download(server, bundle["script_handle"]), tmp_path)
    assert replay.returncode == 0, replay.stderr
    output = Path(replay.stdout.strip().split("Replay output: ")[-1])
    recorded = list(server._chainsaw_ctx.store.rows(handle))
    reproduced = [
        json.loads(line) for line in (output / f"001-{handle}.jsonl").read_text().splitlines()
    ]
    # Detection IDs are generated anew by Chainsaw; the evidence and rule metadata match.
    for rows in (recorded, reproduced):
        for row in rows:
            row.pop("id", None)
    assert recorded == reproduced
    assert recorded
