"""Real Chainsaw regressions for provider-scoped process image translations."""

from __future__ import annotations

import json
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest
import yaml

from chainsaw_mcp.config import load_settings
from chainsaw_mcp.rules import RuleCatalog
from chainsaw_mcp.tools._common import ToolContext
from chainsaw_mcp.tools.hunt import HuntTools
from chainsaw_mcp.tools.rules import RuleTools
from tests.conftest import (
    REPO,
    SAMPLES,
    VENDOR_BIN,
    requires_binary,
    requires_samples,
    requires_vendor_rules,
)

pytestmark = [requires_vendor_rules]

PROBE = r"""title: Security Image Mapping Regression
id: 3a55c660-7aa8-499c-a2ea-fc2e5f06975e
status: experimental
description: Mapping regression diagnostic only, not a threat detection
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\calc.exe'
  condition: selection
level: informational
"""


def hunt(mapping: Path, rule: Path, evidence: Path) -> list[dict]:
    result = subprocess.run(
        [
            str(VENDOR_BIN),
            "hunt",
            "--sigma",
            str(rule),
            "--mapping",
            str(mapping),
            "--jsonl",
            "-q",
            str(evidence),
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]


@pytest.mark.integration
@requires_binary
@requires_samples
def test_security_4688_image_matches_real_evtx(tmp_path: Path):
    rule = tmp_path / "probe.yml"
    rule.write_text(PROBE)
    catalog = RuleCatalog(
        load_settings(
            {
                "CHAINSAW_HOME": str(REPO),
                "CHAINSAW_OUTPUT_DIR": str(tmp_path / "results"),
            }
        )
    )
    evidence = SAMPLES / "Lateral Movement/LM_WMI_4624_4688_TargetHost.evtx"
    hits = hunt(catalog.mapping(None), rule, evidence)
    assert [row["document"]["data"]["Event"]["System"]["EventRecordID"] for row in hits] == [563299]
    assert hunt(catalog.mapping("sigma-event-logs-all.yml"), rule, evidence) == []


@pytest.mark.integration
@requires_binary
def test_mixed_provider_positive_negative_and_missing_fields(tmp_path: Path):
    """Use real binary over deterministic JSON fixtures with the same mapping.

    Only kind/timestamp/provider representation differs from EVTX's parser adapter.
    Conflicting fields prove routing is provider-aware, not a fallback/coalesce.
    """
    catalog = RuleCatalog(
        load_settings(
            {
                "CHAINSAW_HOME": str(REPO),
                "CHAINSAW_OUTPUT_DIR": str(tmp_path / "results"),
            }
        )
    )
    doc = yaml.safe_load(catalog.mapping(None).read_text())
    doc["kind"] = "json"
    mapping = tmp_path / "mapping.yml"
    mapping.write_text(yaml.safe_dump(doc))
    rule = tmp_path / "probe.yml"
    rule.write_text(PROBE)
    security = "Microsoft-Windows-Security-Auditing"
    sysmon = "Microsoft-Windows-Sysmon"
    cases = [
        (security, 4688, {"NewProcessName": r"C:\calc.exe"}),
        (sysmon, 1, {"Image": r"C:\calc.exe"}),
        (security, "4688", {"NewProcessName": r"C:\calc.exe", "Image": r"C:\safe.exe"}),
        (security, 4688, {"NewProcessName": r"C:\safe.exe", "Image": r"C:\calc.exe"}),
        (sysmon, 1, {"NewProcessName": r"C:\calc.exe", "Image": r"C:\safe.exe"}),
        (sysmon, 3, {"Image": r"C:\calc.exe"}),
        (security, 4689, {"NewProcessName": r"C:\calc.exe", "Image": r"C:\calc.exe"}),
        ("Unrelated-Provider", 1, {"Image": r"C:\calc.exe"}),
        (security, 4688, {}),
        (sysmon, 1, {"NewProcessName": r"C:\calc.exe"}),
    ]
    records = [
        {
            "Event": {
                "System": {
                    "Provider": provider,
                    "EventID": event_id,
                    "EventRecordID": index,
                    "TimeCreated": "2024-01-01T00:00:00Z",
                },
                "EventData": fields,
            }
        }
        for index, (provider, event_id, fields) in enumerate(cases)
    ]
    evidence = tmp_path / "mixed.json"
    evidence.write_text(json.dumps(records))
    rows = hunt(mapping, rule, evidence)
    ids = sorted(row["document"]["data"]["Event"]["System"]["EventRecordID"] for row in rows)
    assert ids == [0, 1, 2]

    # Splitting process-creation routing must not lose unrelated Security or Sysmon events.
    rule.write_text(
        PROBE.replace("category: process_creation", "service: security").replace(
            "Image|endswith: '\\calc.exe'",
            "EventID: 4689",
        )
    )
    rows = hunt(mapping, rule, evidence)
    assert [row["document"]["data"]["Event"]["System"]["EventRecordID"] for row in rows] == [6]
    rule.write_text(PROBE.replace("category: process_creation", "category: network_connection"))
    rows = hunt(mapping, rule, evidence)
    assert [row["document"]["data"]["Event"]["System"]["EventRecordID"] for row in rows] == [5]


@pytest.mark.integration
@requires_binary
@requires_samples
def test_real_sysmon_hits_preserved(tmp_path: Path):
    rule = tmp_path / "probe.yml"
    rule.write_text(PROBE.replace("\\calc.exe", "\\powershell.exe"))
    catalog = RuleCatalog(
        load_settings(
            {
                "CHAINSAW_HOME": str(REPO),
                "CHAINSAW_OUTPUT_DIR": str(tmp_path / "results"),
            }
        )
    )
    evidence = SAMPLES / "Credential Access/babyshark_mimikatz_powershell.evtx"
    stock = hunt(catalog.mapping("sigma-event-logs-all.yml"), rule, evidence)
    effective = hunt(catalog.mapping(None), rule, evidence)
    assert stock
    assert sorted(row["document"]["data"]["Event"]["System"]["EventRecordID"] for row in stock) == (
        sorted(row["document"]["data"]["Event"]["System"]["EventRecordID"] for row in effective)
    )


@pytest.mark.integration
@requires_binary
@requires_samples
def test_hunt_tool_uses_same_effective_mapping_as_summary(tmp_path: Path):
    sigma = tmp_path / "sigma"
    (sigma / "rules").mkdir(parents=True)
    (sigma / "rules/probe.yml").write_text(PROBE)
    settings = replace(
        load_settings(
            {
                "CHAINSAW_HOME": str(REPO),
                "CHAINSAW_OUTPUT_DIR": str(tmp_path / "results"),
                "CHAINSAW_EVIDENCE_ROOTS": str(SAMPLES),
            }
        ),
        sigma_dir=sigma,
    )
    ctx = ToolContext(settings)
    summary = json.loads(RuleTools(ctx).chainsaw_get_mapping())
    assert summary["name"] == "sigma-event-logs-provider-aware.yml"
    assert any(g["name"] == "Sigma Security Process Creation" for g in summary["groups"])
    args = {"paths": ["Lateral Movement/LM_WMI_4624_4688_TargetHost.evtx"], "chainsaw_rules": False}
    assert json.loads(HuntTools(ctx).chainsaw_hunt(**args))["total"] == 1
    assert (
        json.loads(
            HuntTools(ctx).chainsaw_hunt(
                **args,
                mapping="sigma-event-logs-all.yml",
            )
        )["total"]
        == 0
    )
