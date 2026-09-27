# Multi-step workflows

Documented procedures an agent (or an analyst driving one) follows with chainsaw-mcp.
Each maps to a skill in `.agents/skills/` and, where fan-out helps, a Claude Code workflow
script in `.claude/workflows/`.

## 1. EVTX first-pass triage

Goal: from a directory of collected event logs to a defensible list of findings.

| Step | Tool | Read | Decide |
|---|---|---|---|
| Scope | `chainsaw_status`, `chainsaw_list_evidence` | all pages, root files, file count, sizes | explicit disjoint file batches; verify complete inventory, not just directories |
| Coverage | `chainsaw_analyse_evtx` | `by_channel`, `top_event_ids` | is Sysmon / PowerShell / Security auditing present? which mapping fits (legacy if no Sysmon) |
| Continuity | `chainsaw_analyse_gaps` | `by_kind`, paged gaps, parser diagnostics | gaps need continuity corroboration; 1102/104 confirm clearing, not malicious intent |
| Hunt | `chainsaw_hunt` | `summary.by_level`, `by_rule`, `by_computer`, `by_hour` | which rules to read in full vs. aggregate |
| Read | `chainsaw_result_page(where={"rule": …}, fields=[…])` | the actual events | true positive? note EventRecordID and file |
| Aggregate | `chainsaw_result_summary(group_by=[…])` | distinct users / processes / IPs | outliers among noisy detections |
| Unique events | `chainsaw_result_summary` counts, then `chainsaw_result_events(handle, offset, limit, fields)` | `unique_event_count` vs `detection_count`; one group per source event with every rule in `matches` | how many source events sit behind a pile of overlapping rule hits |
| Pivot | `chainsaw_search(tau=[…], from_time, to_time)` | neighbouring events | build the sequence |
| Explain | `chainsaw_search_rules`, `chainsaw_get_rule` | ATT&CK tags, references, false positives | wording for the report |
| Assess (optional) | `chainsaw_jev_triage(handle, offset, limit, fields)` | `classification`, `priority.score`, `uncertain` | which previewed rows to read first; requires `jev.enabled` and sends the fields off-host, see [jev.md](jev.md) |

Stopping rule: every critical/high detection has been either read or explicitly discarded
with a reason; every host in `by_computer` has been considered.
If a row budget or parse failure prevents this, stop with explicitly incomplete coverage,
not a clean bill of health. Curated samples and filtered exports cannot establish continuous
record sequences; consider filtering, rollover and clock changes before alleging tampering.
Clearing needs actor/maintenance context and independently corroborated suspicious activity.

Report skeleton: timeline (UTC), hosts and accounts, techniques with ATT&CK IDs,
confidence per finding, evidence pointers, discarded false positives, gaps in coverage,
next collections.

## 2. Indicator pivot

Input: one indicator (account, host, IP, process name, LogonId, GUID) and an evidence path.

1. `chainsaw_search(patterns=[indicator])` for a broad, case-insensitive sweep. Read the
   summary only.
2. `chainsaw_result_fields` on that handle to learn the field names present, then
   `chainsaw_result_summary(group_by=[co-occurring fields])`.
3. Narrow with tau expressions that name the field: `Event.EventData.TargetUserName: i<x>`,
   `Event.EventData.IpAddress: <x>`, `Event.EventData.SubjectLogonId: <x>`.
4. Bound with `from_time`/`to_time` around the active window, then re-run the search on
   that window **without** the indicator to see what else happened.
5. `chainsaw_hunt` the narrowed window and correlate detections with the indicator.

## 3. Rule authoring loop

Input: a described behaviour, ideally with a result handle showing an example event.

1. Read `chainsaw://docs/rule-format`; `chainsaw_search_rules(query)` for prior art.
2. `chainsaw_result_fields(handle)` to get exact paths and example values.
3. `chainsaw_save_rule(name, yaml_text)`; fix `lint.problems` and resave with
   `overwrite=true` until `lint.ok`.
4. Positive test: `chainsaw_hunt(paths=[positive], sigma=false, chainsaw_rules=false,
   extra_rules=["custom"])` must return ≥ 1.
5. Negative test: same against clean evidence must return 0 (or be explained).
6. Deliver YAML + ATT&CK mapping + both test results. Promote to a proper rules repo
   through review; the custom directory is a scratch space.

## 4. Coverage check for a technique

1. `chainsaw_search_rules(tag="t1003", kinds=["sigma"])` and again with `kinds=["chainsaw"]`.
2. `chainsaw_get_mapping()` with no name describes the effective provider-aware default
   (routing preconditions and translations); confirm the rule's `logsource` is mapped,
   because unmapped categories never fire.
3. `chainsaw_lint_rules(kind="sigma", path="rules/windows/<category>")` to see how many
   rules chainsaw cannot compile (unsupported modifiers).
4. Report: rules available, rules loaded, required log sources and whether the evidence
   contains them (`chainsaw_analyse_evtx`).

## 5. Large evidence sets (fan-out)

First collect complete, unfiltered `chainsaw_list_evidence` responses into `inventoryPages`.
Follow `next_offset` until `truncated=false`. A server without pagination supports only an
untruncated single response; truncated scope must fail closed, never silently skip files.
Pass `{path, inventoryPages, maxSlices: 12, mode: "curated-samples"}` to
`.claude/workflows/evtx-triage.js`. `path` is the absolute server-side `base` echoed by
every inventory page, not the relative alias used for discovery; pages with another `base`
or a non-empty `pattern` are rejected. The workflow validates page continuity and totals, sorts
all EVTX files including root files, and checks completeness/disjointness of explicit
`paths[]` batches of at most 64. Additional batches are distributed among the workers:
`maxSlices` limits workers, not coverage. No agent invents the partition.

Each worker performs workflow 1 per batch and identifies completed batches and limitations;
missing workers/batches remain visible in the report. Medium/high findings are verified
against their exact source, and expired-handle recovery hunts only that source file.
Deduplication requires scenario ID + full source file + host + channel + record ID + rule.
Use separate sample timelines: shared lab users/hosts and nearby times do not establish a
single incident. `filtered-export` also assumes no continuity; `incident` mode allows
cross-file relationships only with independent collection provenance and corroboration.
Per-file scenario IDs remain attached in every mode, including channel-less RPC ETW.

### Pinned regression scenarios

`tests/fixtures/scenario_manifest.json` pins EVTX-ATTACK-SAMPLES revision
`4ceed2f4706daf601c212a8f91c113dd85349a2c` and SHA-256 hashes for seven independent scenarios:
Security 4688, Sysmon process/network/file, PowerShell 4104, RPC ETW, Security/System log
clearing, and a mixed-channel filtered sample with record gaps. Integration tests search
exact records and assert concrete fields (including empty command lines and null channels),
not that every sample triggers a detection. Run:

```sh
uv run pytest tests/test_workflow_partition.py
uv run pytest tests/integration/test_scenario_manifest.py -m integration
```

Partition tests execute the real JavaScript in Node with a Workflow-runtime double;
integration tests use the real MCP server and Chainsaw binary. Updating the manifest
requires inspecting the new source records and hashes, not relaxing assertions to zero hits.

## 6. Result hygiene

Result handles hold log content. `chainsaw_result_list` shows what exists;
`chainsaw_result_delete` removes a handle. Handles expire after seven days: every read
refuses an expired handle, and the on-disk sweep runs when a new handle is minted or
`chainsaw_result_list` is called. Delete explicitly when the content is sensitive rather
than waiting for expiry.
