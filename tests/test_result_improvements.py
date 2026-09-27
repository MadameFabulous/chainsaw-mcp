import csv
import io
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from chainsaw_mcp.result_budget import encoded_size
from chainsaw_mcp.results import ResultError, ResultStore, summarize
from chainsaw_mcp.tools.hunt import HuntTools
from chainsaw_mcp.tools.results import ResultTools


def stored(tmp_path, rows, tool="chainsaw_hunt"):
    store = ResultStore(tmp_path / "results")
    handle, path = store.reserve()
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))
    store.commit(handle, tool=tool, argv=[], inputs={})
    return store, handle


@pytest.mark.parametrize("fmt", ["jsonl", "csv"])
def test_export_encoded_budget_and_continuation(tmp_path, fmt):
    rows = [{"x": 'é\\"\n' * 25, "n": i} for i in range(7)]
    store, handle = stored(tmp_path, rows)
    offset = 0
    got = []
    while offset is not None:
        out = store.export(handle, format=fmt, fields=["x", "n"], offset=offset, max_bytes=1800)
        assert encoded_size(out) <= 1800
        if fmt == "jsonl":
            got.extend(json.loads(line) for line in out["content"].splitlines())
        else:
            got.extend(dict(r, n=int(r["n"])) for r in csv.DictReader(io.StringIO(out["content"])))
        offset = out["next_offset"]
    assert got == rows


def test_page_budget_and_single_row_recovery(tmp_path):
    rows = [{"big": "😀" * 1000, "id": i} for i in range(3)]
    store, handle = stored(tmp_path, rows)
    with pytest.raises(ResultError, match="narrower fields"):
        store.page(handle, max_bytes=600)
    page = store.page(handle, fields=["id"], max_bytes=600)
    assert page["returned"] == 3
    content, offset = "", 0
    while offset is not None:
        part = store.chunk(handle, row_offset=0, byte_offset=offset, max_bytes=600)
        assert encoded_size(part) <= 600
        content += part["content"]
        offset = part["next_byte_offset"]
    assert json.loads(content) == rows[0]


def test_utf8_file_chunks_and_invalid_boundary(tmp_path):
    store = ResultStore(tmp_path / "results")
    handle, path = store.reserve(".txt")
    text = 'é😀\\"\n' * 100
    path.write_text(text, encoding="utf-8")
    store.commit(handle, tool="test", argv=[], inputs={}, fmt="txt")
    offset, content = 0, ""
    while offset is not None:
        out = store.export(handle, byte_offset=offset, max_bytes=500)
        assert encoded_size(out) <= 500
        content += out["content"]
        offset = out["next_byte_offset"]
    assert content == text
    with pytest.raises(ResultError, match="UTF-8 boundary"):
        store.chunk(handle, byte_offset=1)


def detection(path="a.evtx", name="Rule A"):
    return {
        "name": name,
        "document": {
            "path": path,
            "data": {
                "Event": {
                    "System": {
                        "Computer": "PC",
                        "Channel": "Sysmon",
                        "EventRecordID": 1,
                        "TimeCreated_attributes": {"SystemTime": "2020-01-01T00:00:00Z"},
                    },
                    "EventData": {"ProcessGuid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"},
                }
            },
        },
    }


def test_event_identity_and_lossless_associations(tmp_path):
    rows = [detection(), detection(name="Rule B"), detection(path="b.evtx"), {}, {}]
    summary = summarize(iter(rows))
    assert summary["detection_count"] == 3
    assert summary["unique_event_count"] == 2
    assert summary["unidentifiable_count"] == 2
    store, handle = stored(tmp_path, rows)
    page = store.events(handle, limit=1, fields=["process_guid"])
    assert page["total"] == 4
    assert len(page["rows"][0]["matches"]) == 2
    assert page["next_offset"] == 1
    assert page["rows"][0]["event"]["process_guid"].startswith("aaaa")
    conflicting = detection()
    conflicting["document"]["data"]["Event"]["EventData"]["Image"] = "different"
    assert summarize(iter([detection(), conflicting]))["unique_event_count"] == 2


def aggregate(*documents, name="Account Brute Force"):
    """Chainsaw aggregate rules emit every matched event under 'documents'."""
    return {
        "name": name,
        "level": "info",
        "source": "chainsaw",
        "kind": "aggregate",
        "documents": [d["document"] for d in documents],
    }


def test_aggregate_detections_are_counted_and_associated(tmp_path):
    first, second = detection(), detection(path="b.evtx")
    rows = [detection(name="Rule B"), aggregate(first, second)]
    summary = summarize(iter(rows))
    assert summary["detection_count"] == 2
    assert summary["unique_event_count"] == 2
    assert summary["unidentifiable_count"] == 0
    assert {"value": "Account Brute Force", "count": 1} in summary["by_rule"]
    assert {"value": "info", "count": 1} in summary["by_level"]
    assert {"value": "b.evtx", "count": 1} in summary["by_file"]
    store, handle = stored(tmp_path, rows)
    events = store.events(handle, limit=10)["rows"]
    assert [e["path"] for e in events] == ["a.evtx", "b.evtx"]
    assert [[m["name"] for m in e["matches"]] for e in events] == [
        ["Rule B", "Account Brute Force"],
        ["Account Brute Force"],
    ]
    assert all("documents" not in m for e in events for m in e["matches"])


def test_tools_budget_metadata_and_preview(tmp_path):
    store, handle = stored(tmp_path, [{"x": "é" * 100, "name": "n"} for _ in range(8)])
    ctx = SimpleNamespace(store=store, settings=SimpleNamespace(max_page=100))
    tools = ResultTools(ctx)
    text = tools.chainsaw_result_page(handle, max_bytes=1200)
    assert len(text.encode()) <= 1200
    assert json.loads(text)["next_offset"] is not None
    export = tools.chainsaw_result_export(handle, format="jsonl", fields=["name"], max_bytes=600)
    assert len(export.encode()) <= 600
    big_store, big_handle = stored(tmp_path / "big", [{"name": "x" * 100000, "document": {}}])
    with pytest.raises(ResultError, match="No metadata was truncated"):
        ResultTools(SimpleNamespace(store=big_store)).chainsaw_result_summary(big_handle)


A = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
B = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
C = "cccccccc-cccc-cccc-cccc-cccccccccccc"


def event(guid, parent, host="PC"):
    return {
        "Event": {
            "System": {"Computer": host},
            "EventData": {"ProcessGuid": guid, "ParentProcessGuid": parent, "Image": "cmd.exe"},
        }
    }


def lineage_context(tmp_path):
    evidence = tmp_path / "sample.jsonl"
    evidence.write_text("evidence")
    rows = [event(A, B), event(B, C), event(A, B, "UNRELATED")]
    calls = []

    def run(args):
        calls.append(args)
        guid = next(a.removeprefix("--regex=") for a in args if a.startswith("--regex="))
        out = Path(args[args.index("--output") + 1])
        out.write_text("".join(json.dumps(r) + "\n" for r in rows if guid in json.dumps(r)))
        return SimpleNamespace(argv=args, messages=[], duration_seconds=0)

    store = ResultStore(tmp_path / "results")
    return (
        SimpleNamespace(
            store=store,
            runner=SimpleNamespace(run=run),
            evidence_paths=lambda paths: paths,
            shown=lambda path: "shown/" + Path(path).name,
            redact=lambda messages: messages,
        ),
        evidence,
        calls,
    )


def test_lineage_queries_source_includes_unmatched_and_isolates(tmp_path):
    ctx, evidence, calls = lineage_context(tmp_path)
    out = json.loads(HuntTools(ctx).chainsaw_process_lineage([str(evidence)], A, "PC", max_hops=1))
    assert out["total"] == 2
    assert len(calls) == 2
    assert all(call[-1] == str(evidence) for call in calls)
    assert {get["Event"]["EventData"]["ProcessGuid"] for get in ctx.store.rows(out["handle"])} == {
        A,
        B,
    }
    assert out["lineage"]["hop_limit_reached"]
    assert not ctx.store._active
    limited = json.loads(
        HuntTools(ctx).chainsaw_process_lineage([str(evidence)], A, "PC", max_queries=1)
    )
    assert limited["lineage"]["query_limit_reached"]
    assert not limited["lineage"]["complete"]
    with pytest.raises(ValueError, match="canonical GUID"):
        HuntTools(ctx).chainsaw_process_lineage([str(evidence)], "x.*|evil", "PC")
    with pytest.raises(ValueError, match="explicit evidence files"):
        HuntTools(ctx).chainsaw_process_lineage([str(tmp_path)], A, "PC")


def test_lineage_event_cap_and_failure_cleanup(tmp_path):
    ctx, evidence, _ = lineage_context(tmp_path)
    out = json.loads(
        HuntTools(ctx).chainsaw_process_lineage([str(evidence)], A, "PC", max_events=1)
    )
    assert out["total"] == 1
    assert out["lineage"]["event_limit_reached"]

    def fail(args):
        raise RuntimeError("runner failed")

    ctx.runner.run = fail
    with pytest.raises(RuntimeError):
        HuntTools(ctx).chainsaw_process_lineage([str(evidence)], A, "PC")
    assert not ctx.store._active
    ctx.shown = lambda p: p
    with pytest.raises(RuntimeError):
        HuntTools(ctx).chainsaw_dump([str(evidence)])
    assert not ctx.store._active


def test_compact_preview_projection(tmp_path):
    store = ResultStore(tmp_path / "results")
    handle, path = store.reserve()
    row = detection()
    row["document"]["data"]["huge"] = "x" * 100000
    path.write_text(json.dumps(row) + "\n")
    ctx = SimpleNamespace(store=store, redact=lambda messages: messages)
    out = HuntTools(ctx)._finish(
        tool="chainsaw_hunt",
        handle=handle,
        argv=[],
        inputs={},
        messages=[],
        duration=0,
        preview=1,
        fields=["rule"],
    )
    assert len(out.encode()) <= 65536
    assert json.loads(out)["preview"]["rows"] == [{"rule": "Rule A"}]
