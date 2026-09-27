"""Execute the real workflow in Node with a deterministic Workflow-runtime double."""

import json
import shutil
import subprocess

import pytest

from tests.conftest import REPO

pytestmark = pytest.mark.skipif(shutil.which("node") is None, reason="Node required")

HARNESS = r"""
const fs = require('node:fs');
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const source = fs.readFileSync('.claude/workflows/evtx-triage.js', 'utf8')
  .replace('export const meta', 'const meta');
const AsyncFunction = Object.getPrototypeOf(async function(){}).constructor;
const run = new AsyncFunction('args', 'phase', 'log', 'agent', 'pipeline', 'parallel', source);
const prompts = [];
const agent = async (prompt, options) => {
  prompts.push({prompt, options});
  if (options.phase === 'Hunt') {
    const batchText = prompt.split('explicit batches ')[1].split(' using the chainsaw')[0];
    const batches = JSON.parse(batchText);
    return {slice: 'untrusted label', findings: input.findings || [],
      completed_batches: input.incomplete ? [] : batches.map(b => b.id), limitations: []};
  }
  if (options.phase === 'Verify') return {refuted: false, reason: 'test runtime'};
  return 'test report';
};
const pipeline = async (slices, hunt, verify) =>
  Promise.all(slices.map(async s => verify(await hunt(s), s)));
run(input.args, () => {}, () => {}, agent, pipeline,
  tasks => Promise.all(tasks.map(task => task())))
  .then(result => console.log(JSON.stringify({result, prompts})))
  .catch(error => console.log(JSON.stringify({error: error.message, prompts})));
"""


def page(paths, offset=0, more=False, total=None):
    result = {
        "base": "/evidence",
        "pattern": "",
        "files": [{"path": p} for p in paths],
        "returned": len(paths),
        "offset": offset,
        "truncated": more,
        "next_offset": offset + len(paths) if more else None,
    }
    result["total"] = total if total is not None else offset + len(paths)
    return result


def execute(pages, max_slices=12, *, path=None, **extra):
    # Default test requests use the server-resolved scope, including live sample tests.
    root = (
        path if path is not None else (pages[0].get("base", "/evidence") if pages else "/evidence")
    )
    completed = subprocess.run(
        ["node", "-e", HARNESS],
        input=json.dumps(
            {"args": {"path": root, "inventoryPages": pages, "maxSlices": max_slices}, **extra}
        ),
        cwd=REPO,
        text=True,
        capture_output=True,
        check=True,
    )
    return json.loads(completed.stdout)


@pytest.mark.parametrize("workers", [1, 2, 12])
def test_complete_disjoint_batches_include_root_and_overflow(workers):
    paths = [f"/evidence/scenario-{i}/sample.evtx" for i in range(901)]
    paths += ["/evidence/UACME_59_Sysmon.evtx", "/evidence/readme.md"]
    pages = [
        page(paths[:500], more=True, total=len(paths)),
        page(paths[500:], 500, total=len(paths)),
    ]
    output = execute(pages, workers)
    assert "error" not in output
    slices = output["result"]["slices"]
    assert len(slices) <= workers
    batches = [batch for worker in slices for batch in worker["batches"]]
    assigned = [path for batch in batches for path in batch["paths"]]
    assert all(1 <= len(batch["paths"]) <= 64 for batch in batches)
    assert len(assigned) == len(set(assigned)) == len(paths) - 1
    assert set(assigned) == set(paths[:-1])
    assert output["result"]["incomplete_batches"] == []
    assert execute(pages, workers)["result"]["slices"] == slices


@pytest.mark.parametrize(
    "pages",
    [
        [],
        [page(["/evidence/a.evtx"], more=True)],
        [page(["/evidence/a.evtx", "/evidence/a.evtx"])],
        [page(["/evidence/a.evtx"], total=2)],
        [page(["/evidence/a.evtx"], more=True), page(["/evidence/b.evtx"], offset=2)],
        [{**page(["/evidence/a.evtx"]), "returned": 2}],
        [{**page(["/evidence/a.evtx"]), "pattern": "Security"}],
        [{**page(["/evidence/a.evtx"], more=True), "next_offset": None}],
    ],
)
def test_incomplete_inventories_fail_before_agents(pages):
    output = execute(pages)
    assert "error" in output
    assert output["prompts"] == []


@pytest.mark.parametrize("workers", [0, -1, 1.5, "2"])
def test_invalid_worker_limit(workers):
    assert "error" in execute([page(["/evidence/a.evtx"])], workers)


def test_empty_inventory():
    assert execute([page([])])["result"]["error"] == "no evidence slices found"


def test_dedup_retains_source_host_channel_and_scenario():
    paths = ["/evidence/one/a.evtx", "/evidence/two/a.evtx"]
    finding = {
        "source_file": paths[0],
        "scenario_id": paths[0],
        "host": "shared-lab-host",
        "channel": "Security",
        "record_id": 42,
        "rule": "test",
        "confidence": "high",
    }
    findings = [
        finding,
        finding.copy(),
        {**finding, "source_file": paths[1], "scenario_id": paths[1]},
        {**finding, "channel": "System"},
        {**finding, "host": "other"},
    ]
    output = execute([page(paths)], findings=findings)
    assert len(output["result"]["confirmed"]) == 4
    assert {f["scenario_id"] for f in output["result"]["confirmed"]} == set(paths)


def test_out_of_scope_finding_rejected():
    output = execute(
        [page(["/evidence/a.evtx"])],
        findings=[
            {
                "source_file": "/evidence/b.evtx",
                "scenario_id": "/evidence/b.evtx",
            }
        ],
    )
    assert output["error"] == "finding outside assigned scenario"


def test_unprocessed_batches_are_visible():
    output = execute([page(["/evidence/a.evtx"])], incomplete=True)
    assert output["result"]["incomplete_batches"] == ["batch-1"]
