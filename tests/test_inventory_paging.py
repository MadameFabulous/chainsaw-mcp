import json

from chainsaw_mcp.tools._common import ToolContext
from chainsaw_mcp.tools.evidence import EvidenceTools


def test_inventory_paging_is_complete_and_exact(settings):
    root = settings.evidence_roots[0]
    for n in range(5):
        (root / f"sample{n}.evtx").touch()
    tool = EvidenceTools(ToolContext(settings))
    offset = 0
    paths = []
    while True:
        page = json.loads(tool.chainsaw_list_evidence(limit=2, offset=offset))
        paths.extend(row["path"] for row in page["files"])
        assert page["total"] == 6
        if page["next_offset"] is None:
            assert not page["truncated"]
            break
        assert page["next_offset"] > offset
        offset = page["next_offset"]
    assert len(paths) == len(set(paths)) == 6


def test_exact_limit_is_not_truncated(settings):
    tool = EvidenceTools(ToolContext(settings))
    page = json.loads(tool.chainsaw_list_evidence(limit=1))
    assert page["returned"] == 1
    assert page["next_offset"] is None
    assert not page["truncated"]
