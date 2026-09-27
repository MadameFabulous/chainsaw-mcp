from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import yaml

from chainsaw_mcp.config import Settings
from chainsaw_mcp.mapping import provider_aware_default
from chainsaw_mcp.rules import RuleCatalog, mapping_summary
from chainsaw_mcp.tools._common import ToolContext
from chainsaw_mcp.tools.rules import RuleTools
from tests.conftest import REPO, requires_vendor_rules


def test_mapping_summary_exposes_bounded_applicability(settings: Settings):
    path = settings.mappings_dir / "sigma-event-logs-all.yml"
    doc = yaml.safe_load(path.read_text())
    doc["extensions"] = {
        "preconditions": [
            {
                "for": {"logsource.category": "process_creation"},
                "filter": [
                    {"Provider": "Microsoft-Windows-Sysmon", "int(EventID)": 1},
                    {"Provider": "Microsoft-Windows-Security-Auditing", "int(EventID)": 4688},
                ],
            }
        ]
    }
    doc["exclusions"] = ["Excluded test rule"]
    path.write_text(yaml.safe_dump(doc))
    summary = mapping_summary(path)
    assert summary["preconditions"] == doc["extensions"]["preconditions"]
    assert summary["exclusion_names"] == ["Excluded test rule"]
    assert summary["groups"][0]["translations"] == doc["groups"][0]["fields"]
    tool_result = json.loads(RuleTools(ToolContext(settings)).chainsaw_get_mapping())
    assert tool_result == summary
    assert "yaml" not in tool_result


def test_custom_default_mapping_is_not_rewritten(settings: Settings):
    catalog = RuleCatalog(settings)
    path = settings.mappings_dir / "sigma-event-logs-all.yml"
    assert catalog.mapping(None) == path
    assert catalog.mapping(path.name) == path


def test_summary_bounds_large_collections(tmp_path: Path):
    path = tmp_path / "large.yml"
    path.write_text(
        yaml.safe_dump(
            {
                "exclusions": [str(i) for i in range(300)],
                "extensions": {"preconditions": [{"for": {"id": str(i)}} for i in range(300)]},
                "groups": [
                    {
                        "name": "large",
                        "fields": [{"from": str(i), "to": str(i)} for i in range(300)],
                    }
                ],
            }
        )
    )
    summary = mapping_summary(path)
    assert summary["exclusions"] == 300
    assert len(summary["exclusion_names"]) == 200
    assert summary["exclusions_truncated"] is True
    assert summary["precondition_count"] == 300
    assert len(summary["preconditions"]) == 200
    assert summary["preconditions_truncated"] is True
    assert summary["groups"][0]["fields"] == 300
    assert len(summary["groups"][0]["translations"]) == 200
    assert summary["groups"][0]["translations_truncated"] is True


@requires_vendor_rules
def test_generated_mapping_is_atomic_reusable_and_preserves_vendor(tmp_path: Path):
    source = REPO / "vendor/chainsaw/mappings/sigma-event-logs-all.yml"
    original = source.read_bytes()
    with ThreadPoolExecutor(max_workers=8) as pool:
        paths = list(pool.map(lambda _: provider_aware_default(source, tmp_path), range(16)))
    assert len(set(paths)) == 1
    target = paths[0]
    assert target != source
    assert source.read_bytes() == original
    before = target.stat().st_mtime_ns
    assert provider_aware_default(source, tmp_path) == target
    assert target.stat().st_mtime_ns == before
    assert not list(tmp_path.rglob("*.tmp"))
    doc = yaml.safe_load(target.read_text())
    stock = yaml.safe_load(original)
    assert doc["extensions"] == stock["extensions"]
    assert doc["exclusions"] == stock["exclusions"]
    target.write_text("corrupt cache")
    assert yaml.safe_load(provider_aware_default(source, tmp_path).read_text()) == doc
