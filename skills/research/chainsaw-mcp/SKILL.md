---
name: chainsaw-mcp
description: "Hunt, search and triage Windows event logs and forensic artefacts through the chainsaw MCP server: pick the right tool, keep large outputs in result handles, author and validate custom detection rules, and report findings with record-level evidence."
version: 1.1.0
author: chainsaw-mcp contributors
license: MIT
platforms: [linux, macos]
metadata:
  tags: [dfir, forensics, windows, evtx, sigma, chainsaw, mcp, threat-hunting]
---

# Chainsaw MCP

Use this skill when an agent has the `chainsaw` MCP server connected and is asked to triage
Windows event logs (EVTX), hunt with Sigma or Chainsaw rules, search for indicators, analyse
Shimcache/SRUM artefacts, or write detection rules. The server wraps Chainsaw v2.16.5 and
exposes 26 tools, 5 resources and 3 prompts (MCP spec 2026-07-28).

## Ground rules

- **Evidence is sandboxed.** Paths are relative to the configured evidence roots. Start with
  `chainsaw_status` (shows roots, binary, rule counts) and `chainsaw_list_evidence` before
  hunting; never guess paths.
- **Large output never comes back inline.** `chainsaw_hunt`, `chainsaw_search`,
  `chainsaw_dump` and the analyse tools return a `handle` plus a summary and a short preview.
  Page with `chainsaw_result_page`, aggregate with `chainsaw_result_summary(group_by=...)`,
  discover fields with `chainsaw_result_fields`, and `chainsaw_result_export` for CSV/JSONL.
  Handles expire after seven days; `chainsaw_result_list` pages through what is still stored.
  Pages and exports are capped at 64 KiB of encoded JSON by default (128 KiB hard max);
  follow `next_offset` until it is null and read `truncated`/`truncation_reason`.
- **Do not page everything.** Read the summary first, aggregate by rule/level/host, then page
  only the rows you need with `fields` and `where` filters (text matches as a
  case-insensitive substring, numbers such as `event_id` exactly). Cap yourself at a few
  hundred rows per investigation. Read `chainsaw_messages` on hunts and searches: Chainsaw
  reports there which files or rules it could not load. It is a preview; when
  `diagnostics.messages_truncated` is true, page `diagnostics.handle` for the full stream.
- **Every reported finding needs evidence**: file path, `EventRecordID`, timestamp (UTC) and
  the key fields, plus the rule name and confidence. State what you discarded and why.
- **Write tools are safe but visible.** `chainsaw_save_rule` writes to `custom-rules/`;
  `chainsaw_delete_rule` and `chainsaw_result_delete` remove things. Nothing touches the
  evidence.

## Tool map

| Need | Tool |
|---|---|
| What can I see / is the server healthy | `chainsaw_status`, `chainsaw_list_evidence` |
| Which channels and event IDs exist, log clearing or time gaps | `chainsaw_analyse_evtx`, `chainsaw_analyse_gaps` |
| Rule-based detections (Sigma + Chainsaw) | `chainsaw_hunt` (filters: `levels`, `statuses`, `kinds`, `from_time`/`to_time`, `sigma_collections`, `extra_rules`) |
| Keyword / regex / tau expression search | `chainsaw_search` (`patterns`, `tau`, `ignore_case`, `timestamp_field` when time-bounding) |
| Raw events from a file | `chainsaw_dump` |
| Shimcache timeline, SRUM network/app usage | `chainsaw_analyse_shimcache`, `chainsaw_analyse_srum` |
| Find or read rules and mappings | `chainsaw_search_rules`, `chainsaw_get_rule`, `chainsaw_get_mapping`, `chainsaw_rule_stats` |
| Write and check custom rules | `chainsaw_save_rule` (lints on save), `chainsaw_lint_rules`, `chainsaw_delete_rule` |
| Work with stored output | `chainsaw_result_page`, `chainsaw_result_summary`, `chainsaw_result_fields`, `chainsaw_result_export`, `chainsaw_result_list`, `chainsaw_result_delete` |
| Unique events behind overlapping detections; one oversized row | `chainsaw_result_events` (groups hunt rows by source-qualified event identity, keeps every rule in `matches`), `chainsaw_result_chunk` (byte-range read of a stored row or file) |
| Parent/child process chain on one host | `chainsaw_process_lineage` (explicit evidence files + exact host; bounded hops and events) |
| Optional external second opinion on a few rows | `chainsaw_jev_triage` (sends selected fields to TypeSafe; only when `chainsaw_status` shows `jev.enabled`) |

Resources: `chainsaw://config`, `chainsaw://rules/{kind}/{path}`, `chainsaw://mappings/{name}`,
`chainsaw://docs/rule-format`, `chainsaw://results/{handle}`. Prompts: `triage_evtx`,
`pivot_on_indicator`, `author_rule`.

## Triage procedure (default)

1. `chainsaw_status`, then all unfiltered `chainsaw_list_evidence(path)` pages to fix scope.
   Follow `next_offset` until `truncated=false`. Include root-level files alongside directories;
   never silently omit overflow. Partition explicit file `paths[]` into disjoint batches of
   at most 64, checking their union equals the inventory. Stop if completeness cannot be proven.
2. `chainsaw_analyse_evtx(paths)` for channel/event-ID inventory; `chainsaw_analyse_gaps(paths)`
   for cleared logs and time gaps. Gaps are coverage observations until continuity within
   the same source/host/channel and independent corroboration rule out filtering, rollover,
   clock changes and parse errors. Security 1102 / System 104 confirm clearing, not intent;
   check actor and maintenance context before alleging anti-forensics.
3. `chainsaw_hunt(paths, preview=5)`. Read `summary` (by level, by rule, time range).
4. `chainsaw_result_summary(handle, group_by=["name","document.path"])` to see which rules
   fired where. Start with critical/high; treat noisy informational rules as context.
5. Page the interesting rules: `chainsaw_result_page(handle, where={"name": "..."},
   fields=["timestamp","name","Event.System.Computer","Event.EventData.SubjectUserName",...])`.
6. Pivot with `chainsaw_search(paths, patterns=[user, host, hash, tool name])` for events no
   rule covers; use `from_time`/`to_time` to bracket the incident window.
7. Choose `curated-samples` (default for public samples), `filtered-export`, or `incident` mode.
   Retain each full source path as a scenario ID. Shared lab hostnames, accounts and record IDs
   do not connect unrelated samples. Cross-file incident correlation requires independent
   provenance/corroboration. Deduplicate only scenario + full source file + host + channel +
   record ID + rule; preserve null channels in RPC ETW. Build per-scenario UTC timelines,
   map to ATT&CK IDs from the rule tags, and write the report:
   executive summary, timeline table, techniques, anti-forensics/coverage gaps, discarded
   detections, next steps. Unprocessed batches, parser failures and review-budget exhaustion
   must be named as incomplete coverage, not clean evidence or discarded detections.

## Rule authoring loop

1. Capture exact field paths from real events: `chainsaw_result_fields(handle)` on a search or
   hunt of the positive sample. Read `chainsaw://docs/rule-format`.
2. Check prior art with `chainsaw_search_rules(query, tag=...)`.
3. `chainsaw_save_rule(name, yaml_text)` and fix any `lint.problems`.
4. Positive test: `chainsaw_hunt(paths=[sample], sigma=false, chainsaw_rules=false,
   extra_rules=["custom"])` must match. Negative test on clean evidence must not.
5. Set `level` honestly (critical only for near-zero false positives), fill `fields` with what
   an analyst needs on screen, keep `status: experimental` until tested on more data.

## Common mistakes

- Passing comma-separated levels; use a list (`levels=["critical","high"]`).
- Time-bounding a `chainsaw_search` without `timestamp_field` (the tool defaults it to
  `Event.System.TimeCreated_attributes.SystemTime`, but say so in the report).
- Trusting a hit from a Sigma rule with documented `falsepositives` without checking them
  (`chainsaw_get_rule(kind="sigma", path=...)`).
- Reporting a detection whose event you never paged. Confirm the record exists.
- Treating a `chainsaw_jev_triage` classification as a finding. It is advisory; `likely_benign`
  never closes a detection and `uncertain` rows need a human read of the source row.

## Setup notes

Local use: `claude mcp add chainsaw -- uv --directory <repo> run chainsaw-mcp`. Bootstrap the
binary and rules with `uv run chainsaw-mcp-bootstrap`; check with `uv run chainsaw-mcp --check`.
For a shared service (streamable HTTP behind a private address) see the repository's
`docs/deployment.md`.
