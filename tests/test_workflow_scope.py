"""Inventory provenance must survive the real MCP response -> workflow boundary."""

import shutil

import pytest

from chainsaw_mcp.server import build_server
from tests.test_server import call, payload
from tests.test_workflow_partition import execute, page

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="Node required")


def assert_rejected(pages, **kwargs):
    output = execute(pages, **kwargs)
    assert "error" in output, output
    assert output["prompts"] == []


def test_verbatim_filtered_mcp_inventory_is_rejected(settings, workspace):
    (workspace / "evidence" / "System.evtx").write_bytes(b"ElfFile\x00")
    response = payload(
        call(build_server(settings), "chainsaw_list_evidence", {"pattern": "Security"})
    )
    assert response["returned"] == 1
    assert response["truncated"] is False
    assert_rejected([response], path=str(workspace / "evidence"))


def test_verbatim_mcp_inventory_from_unrelated_base_is_rejected(settings, workspace):
    other = workspace / "evidence" / "other"
    other.mkdir()
    (other / "System.evtx").write_bytes(b"ElfFile\x00")
    response = payload(call(build_server(settings), "chainsaw_list_evidence", {"path": "host1"}))
    assert_rejected([response], path=str(other))


@pytest.mark.parametrize("pattern", [None, False, 0, [], {}])
def test_falsy_pattern_is_not_unfiltered_provenance(pattern):
    assert_rejected([{**page(["/evidence/a.evtx"]), "pattern": pattern}])


def test_absent_pattern_is_not_unfiltered_provenance():
    response = page(["/evidence/a.evtx"])
    del response["pattern"]
    assert_rejected([response])


@pytest.mark.parametrize(
    "root", [".", "evidence", "", "/evidence/../other", "/evidence/", "/evidence//child"]
)
def test_workflow_requires_canonical_absolute_root(root):
    assert_rejected([{**page(["/evidence/a.evtx"]), "base": root}], path=root)


@pytest.mark.parametrize("field", ["offset", "total"])
def test_required_pagination_provenance(field):
    response = page(["/evidence/a.evtx"])
    del response[field]
    assert_rejected([response])


def test_changed_total_between_pages_is_rejected():
    assert_rejected(
        [
            page(["/evidence/a.evtx"], more=True, total=3),
            page(["/evidence/b.evtx"], offset=1, total=2),
        ]
    )


@pytest.mark.parametrize("field,value", [("has_more", True), ("next_offset", 1)])
def test_terminal_pagination_metadata_must_agree(field, value):
    assert_rejected([{**page(["/evidence/a.evtx"]), field: value}])


@pytest.mark.parametrize("field,value", [("pattern", "Security"), ("base", "/other")])
def test_every_page_must_match_requested_scope(field, value):
    assert_rejected(
        [
            page(["/evidence/a.evtx"], more=True, total=2),
            {**page(["/evidence/b.evtx"], offset=1, total=2), field: value},
        ]
    )


def test_verbatim_unfiltered_mcp_pages_cover_requested_root(settings, workspace):
    root = workspace / "evidence"
    (root / "System.evtx").write_bytes(b"ElfFile\x00")
    server = build_server(settings)
    pages = []
    offset = 0
    while True:
        response = payload(
            call(
                server,
                "chainsaw_list_evidence",
                {
                    "path": str(root),
                    "limit": 1,
                    "offset": offset,
                },
            )
        )
        pages.append(response)
        if response["next_offset"] is None:
            break
        offset = response["next_offset"]
    output = execute(pages, path=str(root))
    assert "error" not in output, output
    assigned = [p for s in output["result"]["slices"] for b in s["batches"] for p in b["paths"]]
    assert set(assigned) == {str(root / "System.evtx"), str(root / "host1" / "Security.evtx")}
