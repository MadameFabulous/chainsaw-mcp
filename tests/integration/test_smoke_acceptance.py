"""Real MCP acceptance over hash-pinned curated EVTX (not a continuous incident)."""

import hashlib
import json
import re
import subprocess
from collections import Counter

import anyio
import pytest
from mcp.client import Client

from chainsaw_mcp.config import load_settings
from chainsaw_mcp.server import build_server
from tests.conftest import (
    REPO,
    SAMPLES,
    VENDOR_BIN,
    requires_binary,
    requires_samples,
    requires_vendor_rules,
)

pytestmark = [requires_binary, requires_samples, requires_vendor_rules, pytest.mark.integration]

PINNED = dict(
    [
        (
            "Execution/exec_persist_rundll32_mshta_scheduledtask_sysmon_1_3_11.evtx",
            "fb5679aec77dc45a35902f705b513811dfea0f2f93c9c8503464a20270c3222f",
        ),
        (
            "Execution/temp_scheduled_task_4698_4699.evtx",
            "a7decf0fbabc340e37de7e7c39fddd5398a7106a4f6acded0ea1d2ffa6bf8b70",
        ),
        (
            "Credential Access/Powershell_4104_MiniDumpWriteDump_Lsass.evtx",
            "54ff62eff26af588782e066b7b3b1b952bc83e1b75a84d81f9492e654cb5c319",
        ),
    ]
)


@pytest.fixture(scope="module")
def server(tmp_path_factory):
    for name, digest in PINNED.items():
        assert hashlib.sha256((SAMPLES / name).read_bytes()).hexdigest() == digest
    return build_server(
        load_settings(
            {
                "CHAINSAW_HOME": str(REPO),
                "CHAINSAW_EVIDENCE_ROOTS": str(SAMPLES),
                "CHAINSAW_OUTPUT_DIR": str(tmp_path_factory.mktemp("acceptance-results")),
                "CHAINSAW_CUSTOM_RULES_DIR": str(tmp_path_factory.mktemp("acceptance-rules")),
            }
        )
    )


async def call(client, name, args, *, error_ok=False):
    result = await client.call_tool(name, args)
    raw = result.content[0].text
    assert len(raw.encode()) <= args.get("max_bytes", 65536)
    if result.is_error:
        assert error_ok, raw
        return raw
    out = json.loads(raw)
    byte_field = "response_bytes" if "response_bytes" in out else "returned_bytes"
    assert out[byte_field] == len(raw.encode())
    return out


def test_rundll32_mshta_scheduled_task_preserves_all_associations(server):
    async def run():
        async with Client(server) as client:
            hunt = await call(client, "chainsaw_hunt", {"paths": list(PINNED)[:2], "preview": 2})
            assert hunt["total"] == hunt["summary"]["detection_count"] == 11
            assert hunt["summary"]["unique_event_count"] == 4
            handle = hunt["handle"]
            detections, events = [], []
            for tool, target in [
                ("chainsaw_result_page", detections),
                ("chainsaw_result_events", events),
            ]:
                offset = 0
                while offset is not None:
                    page = await call(
                        client, tool, {"handle": handle, "offset": offset, "limit": 2}
                    )
                    target.extend(page["rows"])
                    offset = page["next_offset"]
            assert len(events) == 4
            associations = [m for event in events for m in event["matches"]]
            assert len(associations) == len(detections) == 11

            def canonical(row):
                return json.dumps(row, sort_keys=True)

            assert Counter(map(canonical, associations)) == Counter(
                canonical({k: v for k, v in row.items() if k != "document"}) for row in detections
            )

    anyio.run(run)


def test_powershell_oversized_record_page_export_chunk_roundtrip(server):
    sample = list(PINNED)[2]
    raw = subprocess.check_output(
        [str(VENDOR_BIN), "dump", "--jsonl", "-q", str(SAMPLES / sample)], timeout=60
    )
    expected = [json.loads(line) for line in raw.splitlines() if line.strip()]
    assert max(len(json.dumps(row)) for row in expected) > 1200

    async def run():
        async with Client(server) as client:
            dump = await call(client, "chainsaw_dump", {"paths": [sample], "preview": 0})
            assert dump["total"] == len(expected) == 4
            handle = dump["handle"]
            recovered_chunks = 0
            for tool in ["chainsaw_result_page", "chainsaw_result_export"]:
                offset, rows = 0, []
                while offset is not None:
                    args = {"handle": handle, "offset": offset, "max_bytes": 1200}
                    if tool.endswith("export"):
                        args["format"] = "jsonl"
                    page = await call(client, tool, args, error_ok=True)
                    if isinstance(page, str):
                        match = re.search(r"row_offset=(\d+)", page)
                        assert match and int(match[1]) == offset
                        byte_offset, parts = 0, []
                        while byte_offset is not None:
                            chunk = await call(
                                client,
                                "chainsaw_result_chunk",
                                {
                                    "handle": handle,
                                    "row_offset": offset,
                                    "byte_offset": byte_offset,
                                    "max_bytes": 1200,
                                },
                            )
                            assert chunk["returned_bytes"] == len(chunk["content"].encode())
                            assert chunk["returned_bytes"] > 0
                            parts.append(chunk["content"])
                            byte_offset = chunk["next_byte_offset"]
                        rows.append(json.loads("".join(parts)))
                        recovered_chunks += 1
                        offset = offset + 1 if offset + 1 < len(expected) else None
                    else:
                        rows.extend(
                            page["rows"]
                            if tool.endswith("page")
                            else [json.loads(line) for line in page["content"].splitlines()]
                        )
                        offset = page["next_offset"]
                assert rows == expected
            assert recovered_chunks >= 2

    anyio.run(run)
