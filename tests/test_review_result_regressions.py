"""Regression coverage for result identity and delivery metadata."""

import json
import re
from types import SimpleNamespace

import pytest

from chainsaw_mcp.result_budget import annotate_delivery, encoded_size
from chainsaw_mcp.results import ResultError, event_identity
from chainsaw_mcp.tools.hunt import HuntTools
from tests.test_result_improvements import detection, stored


def test_identity_retains_bounded_digest_not_event_payload():
    small = detection()
    large = detection()
    large["document"]["data"]["payload"] = "x" * 2_000_000
    key = event_identity(large)
    assert key is not None
    assert len(json.dumps(key)) < 512
    assert key == event_identity(json.loads(json.dumps(large)))
    assert key != event_identity(small)
    other_source = json.loads(json.dumps(large))
    other_source["document"]["path"] = "other.evtx"
    assert key != event_identity(other_source)


def test_filtered_oversized_row_advertises_original_chunk_offset(tmp_path):
    rows = [
        {"match": "no"},
        {"match": "yes"},
        {"match": "no"},
        {"match": "yes", "payload": "x" * 5000},
    ]
    store, handle = stored(tmp_path, rows)
    with pytest.raises(ResultError) as error:
        store.page(handle, where={"match": "yes"}, offset=1, max_bytes=600)
    match = re.search(r"row_offset=(\d+)", str(error.value))
    assert match is not None, str(error.value)
    part = store.chunk(handle, row_offset=int(match[1]), max_bytes=10000)
    assert json.loads(part["content"]) == rows[3]


@pytest.mark.parametrize("method", ["page", "export", "chunk"])
def test_delivery_metadata_exact_including_envelope(tmp_path, method):
    store, handle = stored(tmp_path, [{"n": i, "x": 'é\\"' * 30} for i in range(8)])
    kwargs = {"format": "jsonl"} if method == "export" else {}
    out = getattr(store, method)(handle, max_bytes=1000, **kwargs)
    key = "response_bytes" if method == "chunk" else "returned_bytes"
    assert out[key] == encoded_size(out) <= 1000
    assert out["truncated"] is True
    assert out["truncation_reason"] == "max_bytes"
    if method == "chunk":
        assert out["returned_bytes"] == len(out["content"].encode())
    else:
        last = getattr(store, method)(handle, offset=8, max_bytes=1000, **kwargs)
        assert not last["truncated"]
        assert last["truncation_reason"] is None
        assert last["returned_bytes"] == encoded_size(last)


def test_preview_trim_reannotates_nested_and_outer_response(tmp_path):
    store, _ = stored(tmp_path, [])
    handle, path = store.reserve()
    path.write_text("".join(json.dumps({"x": "x" * 1000}) + "\n" for _ in range(70)))
    raw = HuntTools(SimpleNamespace(store=store, redact=lambda messages: messages))._finish(
        tool="chainsaw_dump",
        handle=handle,
        argv=[],
        inputs={},
        messages=["m" * 10000],
        duration=0,
        preview=70,
        fields=["x"],
    )
    out = json.loads(raw)
    assert out["returned_bytes"] == len(raw.encode()) <= 65536
    preview = out["preview"]
    assert preview["returned_bytes"] == encoded_size(preview)
    assert preview["returned"] == len(preview["rows"]) == preview["next_offset"]
    assert preview["truncated"] and out["truncated"]
    assert preview["truncation_reason"] == out["truncation_reason"] == "max_bytes"


@pytest.mark.parametrize("length", [0, 1, 9, 90, 900, 990, 9990])
def test_annotation_fixed_point_and_reannotation(length):
    out = {"content": "x" * length}
    assert annotate_delivery(out) is out
    assert out["returned_bytes"] == encoded_size(out)
    out["content"] += "é" * 100
    annotate_delivery(out, truncated=True, reason="max_bytes")
    assert out["returned_bytes"] == encoded_size(out)


def test_row_count_limits_are_not_byte_truncation(tmp_path):
    store, handle = stored(tmp_path, [{"x": i} for i in range(3)])
    page = store.page(handle, limit=1)
    export = store.export(handle, format="jsonl", max_rows=1)
    assert page["truncation_reason"] == "limit"
    assert export["truncation_reason"] == "max_rows"
    for out in (page, export):
        assert out["truncated"]
        assert out["returned_bytes"] == encoded_size(out)
