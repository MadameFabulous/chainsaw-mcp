"""Pinned record-level regressions; no assumption that every sample must detect."""

import hashlib
import json
import re
import shutil
import subprocess

import pytest

from tests.conftest import REPO, SAMPLES, requires_binary, requires_samples
from tests.integration.test_live_chainsaw import call, server  # noqa: F401
from tests.test_workflow_partition import execute

MANIFEST = json.loads((REPO / "tests/fixtures/scenario_manifest.json").read_text())
pytestmark = [requires_binary, requires_samples, pytest.mark.integration]


def test_manifest_pins_actual_sample_revision():
    revision = MANIFEST["revision"]
    assert re.fullmatch(r"[0-9a-f]{40}", revision)
    ids = [scenario["id"] for scenario in MANIFEST["scenarios"]]
    assert len(ids) == len(set(ids))
    for scenario in MANIFEST["scenarios"]:
        pinned = subprocess.run(
            ["git", "-C", str(SAMPLES), "show", f"{revision}:{scenario['path']}"],
            capture_output=True,
            check=True,
        ).stdout
        assert hashlib.sha256(pinned).hexdigest() == scenario["sha256"]


def field(row, path):
    for key in path.split("."):
        row = row[key]  # Missing and explicit null must not be conflated.
    return row


@pytest.mark.skipif(shutil.which("node") is None, reason="Node required")
def test_real_inventory_partition_keeps_root_sample(server):  # noqa: F811
    pages = []
    arguments = {"path": ".", "limit": 1000}
    while True:
        inventory = call(server, "chainsaw_list_evidence", arguments)
        pages.append(inventory)
        if not inventory["truncated"]:
            break
        assert inventory.get("next_offset") is not None, "complete inventory requires pagination"
        arguments["offset"] = inventory["next_offset"]
    output = execute(pages, max_slices=2)
    assert "error" not in output, output
    assigned = {
        path
        for worker in output["result"]["slices"]
        for batch in worker["batches"]
        for path in batch["paths"]
    }
    assert str(SAMPLES / "UACME_59_Sysmon.evtx") in assigned
    assert assigned == {str(path) for path in SAMPLES.rglob("*.evtx")}


@pytest.mark.parametrize("scenario", MANIFEST["scenarios"], ids=lambda s: s["id"])
def test_scenario_records(server, scenario):  # noqa: F811 - imported pytest fixture
    sample = SAMPLES / scenario["path"]
    assert hashlib.sha256(sample.read_bytes()).hexdigest() == scenario["sha256"], (
        f"Sample changed: restore {MANIFEST['revision']} or review the pinned expectations"
    )
    for expected in scenario["records"]:
        result = call(
            server,
            "chainsaw_search",
            {
                "paths": [scenario["path"]],
                "tau": [f"Event.System.EventRecordID: ={expected['Event.System.EventRecordID']}"],
                "preview": 0,
            },
        )
        assert result["total"] > 0, scenario["id"]
        page = call(server, "chainsaw_result_page", {"handle": result["handle"], "limit": 100})
        rows = page["rows"]
        # Stored search rows are raw event documents, unlike hunt detection wrappers.
        matches = [row for row in rows if all(field(row, k) == v for k, v in expected.items())]
        assert matches, (scenario["id"], expected, rows)
        for path, snippets in scenario.get("contains", {}).items():
            assert all(snippet in field(matches[0], path) for snippet in snippets)
    if "expected_gap_kind" in scenario:
        gaps = call(server, "chainsaw_analyse_gaps", {"paths": [scenario["path"]]})
        assert gaps["by_kind"].get(scenario["expected_gap_kind"], 0) > 0
        assert MANIFEST["mode"] == "curated-samples"
        assert scenario["gap_interpretation"].startswith("coverage-only:")
