from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from chainsaw_mcp.config import Settings, load_settings

REPO = Path(__file__).resolve().parents[1]
VENDOR_BIN = REPO / "vendor" / "chainsaw" / "chainsaw"
SAMPLES = REPO / "evidence" / "EVTX-ATTACK-SAMPLES"

MINIMAL_RULE = """\
title: Test Rule
group: Test
description: unit-test rule
authors:
  - tests
kind: evtx
level: low
status: experimental
timestamp: Event.System.TimeCreated_attributes.SystemTime
fields:
  - name: Event ID
    to: Event.System.EventID
filter:
  condition: a
  a:
    Event.System.EventID: 4104
"""


@pytest.fixture
def workspace(tmp_path: Path) -> Path:
    """A self-contained CHAINSAW_HOME with tiny rule trees and an evidence root."""
    (tmp_path / "evidence" / "host1").mkdir(parents=True)
    (tmp_path / "evidence" / "host1" / "Security.evtx").write_bytes(b"ElfFile\x00" * 8)
    (tmp_path / "evidence" / "host1" / "notes.txt").write_text("x")
    (tmp_path / "outside").mkdir()
    (tmp_path / "outside" / "secret.evtx").write_bytes(b"ElfFile\x00")
    rules = tmp_path / "vendor" / "chainsaw" / "rules" / "evtx" / "test"
    rules.mkdir(parents=True)
    (rules / "test_rule.yml").write_text(MINIMAL_RULE)
    sigma = tmp_path / "vendor" / "chainsaw" / "sigma" / "rules" / "windows"
    sigma.mkdir(parents=True)
    (sigma / "proc_creation_win_test.yml").write_text(
        """\
title: Mimikatz Execution
id: 0f6d8a2e-1111-4c1c-9b7d-000000000001
status: test
description: A sigma rule for tests
references:
  - https://example.invalid
author: tests
date: 2024-01-01
tags:
  - attack.credential-access
  - attack.t1003.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\mimikatz.exe'
  condition: selection
level: critical
"""
    )
    mappings = tmp_path / "vendor" / "chainsaw" / "mappings"
    mappings.mkdir(parents=True)
    (mappings / "sigma-event-logs-all.yml").write_text(
        """\
name: Test mapping
kind: evtx
rules: sigma
groups:
  - name: Sigma
    timestamp: Event.System.TimeCreated
    filter:
      Provider: "*"
    fields:
      - name: Image
        to: Event.EventData.Image
"""
    )
    return tmp_path


@pytest.fixture
def settings(workspace: Path) -> Settings:
    env = {
        "CHAINSAW_HOME": str(workspace),
        "CHAINSAW_EVIDENCE_ROOTS": str(workspace / "evidence"),
        "CHAINSAW_OUTPUT_DIR": str(workspace / "results"),
        "CHAINSAW_BIN": str(VENDOR_BIN) if VENDOR_BIN.exists() else str(workspace / "nope"),
    }
    return load_settings(env)


def has_binary() -> bool:
    return VENDOR_BIN.exists() or shutil.which("chainsaw") is not None


requires_binary = pytest.mark.skipif(not has_binary(), reason="chainsaw binary not installed")
requires_samples = pytest.mark.skipif(
    not (SAMPLES / "Credential Access").is_dir(), reason="EVTX-ATTACK-SAMPLES not cloned"
)
requires_vendor_rules = pytest.mark.skipif(
    not (REPO / "vendor" / "chainsaw" / "sigma" / "rules").is_dir(),
    reason="vendor/chainsaw rules not installed (run chainsaw-mcp-bootstrap)",
)
