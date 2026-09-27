---
name: chainsaw-triage
description: Triage Windows event logs and forensic artefacts with the chainsaw MCP tools. Use when asked to hunt, investigate, or timeline EVTX/Sysmon/PowerShell logs, check for log tampering, or pivot on an indicator across collected evidence.
---

# Chainsaw triage

You have the `chainsaw_*` MCP tools (server: chainsaw-mcp). They wrap the Chainsaw hunting
tool with Sigma and Chainsaw rules. Large outputs never come back inline: hunts, searches and
dumps return a `res_<hex>` handle plus a summary. Work from summaries and targeted pages,
never by dumping whole logs into context.

## Procedure

1. **Scope.** `chainsaw_status` for roots and rule counts. `chainsaw_list_evidence(path)` to
   inventory all files, including root-level EVTX next to directories. Follow `next_offset`
   until `truncated=false`; never treat a bounded first page as complete. Pass explicit
   `paths[]` batches of at most 64 files. Keep batches disjoint and check their union against
   the inventory. If pagination is unavailable and inventory is truncated, stop and report
   incomplete scope rather than selecting a subset.
2. **Coverage.** `chainsaw_analyse_evtx(paths)`. Note which channels exist (Security,
   Sysmon, PowerShell/Operational, System) and which are missing. No Sysmon means many Sigma
   process-creation rules cannot fire; say so in the report.
3. **Continuity.** `chainsaw_analyse_gaps(paths)`. Record/time gaps are coverage observations,
   not proof of tampering. Establish collection continuity within the same source, host and
   channel, excluding filtering, rollover, clock changes and parser failures. Curated samples
   and filtered exports are not continuous logs. Security 1102 / System 104 prove clearing,
   not malicious intent: inspect the actor, maintenance context and corroborating activity.
4. **Hunt.** `chainsaw_hunt(paths, preview=5)`. Read `summary.by_level`, `by_rule`,
   `by_computer`, `by_hour`, `by_tag`. Do not page all rows.
5. **Read the important ones.** For critical/high rules with few hits:
   `chainsaw_result_page(handle, where={"rule": "<name>"}, fields=["timestamp","computer",
   "event_id","record_id","Event.EventData.CommandLine", ...])`. Use
   `chainsaw_result_fields(handle)` when unsure which paths exist.
6. **Aggregate the noisy ones.** `chainsaw_result_summary(handle, group_by=[
   "Event.EventData.TargetUserName", "Event.EventData.IpAddress"], where={"rule": ...})`
   to find outliers instead of reading hundreds of rows. When several rules fire on the
   same events, compare `unique_event_count` with `detection_count` in the summary, then
   page `chainsaw_result_events(handle, offset, limit, fields)`: one group per source event
   with every matching rule listed in `matches`.
7. **Pivot.** `chainsaw_search(paths, tau=["Event.EventData.SubjectLogonId: 0x3e7"],
   from_time, to_time)` to reconstruct sequences around an interesting host, user, LogonId
   or process GUID. Tau syntax is in `references/tau-cheatsheet.md`. For a parent/child
   process chain on one known host, `chainsaw_process_lineage` walks explicitly named files
   with bounded hops and reports the limits it hit.
8. **Explain.** `chainsaw_search_rules(query=<rule name>)` then `chainsaw_get_rule` for
   ATT&CK tags, references and known false positives.
9. **Optional second opinion.** If `chainsaw_status` reports `jev.enabled`, you may send up
   to ten previewed rows with `chainsaw_jev_triage(handle, offset, limit, fields=[...])`.
   This ships the selected fields to an external API; choose fields deliberately and treat
   the returned classification and priority as advisory, never as a finding.
10. **Clean up.** `chainsaw_result_delete` handles you no longer need; they contain log data.

## Judgement rules

- A detection is a hypothesis. Confirm with the underlying event fields, adjacent events,
  and whether the host/user context makes sense before calling it a finding.
- `info`/`low` Sigma rules are enrichment, not findings, unless they cluster with higher
  ones on the same host and hour.
- Record the `document.path` and `EventRecordID` for every reported event so a human can
  verify it in the original log.
- Default sample collections to **curated-samples** mode and selected exports to
  **filtered-export** mode. Assign each file an immutable scenario ID (full source path).
  Do not connect unrelated samples by shared lab hostname, username, time or record ID.
  In **incident** mode require collection provenance plus corroborating evidence for
  cross-file relationships; retain scenario/source identities in each finding.
- Deduplicate only by scenario ID + full source path + host + channel + EventRecordID + rule.
  Basenames and record IDs are not globally unique; RPC ETW may have a null channel.
- Budget exhaustion, parser failures and unprocessed batches are explicit limitations,
  never discarded detections or evidence of a clean host.
- Times are UTC unless you passed `timezone`. State this in the report.

## Report format

1. Executive summary (three sentences).
2. Timeline table: time (UTC), host, account, event, detection, confidence, evidence pointer.
3. Techniques with ATT&CK IDs.
4. Anti-forensics / coverage gaps.
5. Discarded detections and why.
6. Recommended next collections or pivots.

See `references/evtx-cheatsheet.md` for event IDs worth knowing and
`references/tau-cheatsheet.md` for search expression syntax.
