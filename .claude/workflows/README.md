# Claude Code workflows

Saved workflow scripts for the `Workflow` tool. Run with `/workflows` or ask Claude Code to
"run the evtx-triage workflow with args {...}". Both need the chainsaw MCP server registered
in the session (`claude mcp add chainsaw -- uv --directory <repo> run chainsaw-mcp`).

| Script | Args | What it does |
|---|---|---|
| `evtx-triage.js` | `{path, inventoryPages, focus?, maxSlices?, mode?}` | Validates complete inventory, partitions explicit file paths into disjoint batches, verifies medium/high findings, reports separate scenarios. |
| `rule-authoring-loop.js` | `{behaviour, positive, negative?, handle?}` | Researches prior art and exact fields, drafts three rules from different angles, lints and hunt-tests each, judges and saves the winner as `final_<name>`. |

Both scripts return structured JSON in addition to Markdown so results can be chained into
further workflows. Agent counts: triage uses workers + verified findings + 1; rule
authoring uses 1 + 3 + 3 + 1.

## Triage inventory contract

Before invoking triage, call `chainsaw_status`, then `chainsaw_list_evidence(path, limit=1000)`
with no pattern. Keep each response **verbatim** in `inventoryPages`; if truncated, request
the next page using `offset=next_offset` until `truncated=false`. The server must expose
`pattern`, `offset`, `next_offset`, and `total`, even for an untruncated single page.
Upgrade older servers that omit this provenance; do not manufacture missing fields.
Do not manufacture responses or let an agent pick directories and call that complete.

Pass `args.path` as the requested scope's canonical absolute **server-side** path, exactly
matching the response `base` (for example `/data/evidence/case-1`, not `.` or a client-local
path). Discovery may use a relative alias, but verify its returned `base` is the intended
investigation root before invoking the workflow. Every page must have that same `base`
and an explicit empty-string `pattern`; filtered inventories are rejected.

The script sorts every `.evtx` path (including `UACME_59_Sysmon.evtx` at the sample root),
forms batches of at most 64 files, then assigns **all** batches round-robin to at most
`maxSlices` workers (default 12). Overflow adds batches, never drops files. It validates
page counts, contiguous offsets, a stable total, terminal completeness, duplicate paths
and partition equality. `path` is the enforced scope, not merely a report label.
Only include pages for that requested path, captured without changing the evidence.

`mode` defaults to `curated-samples`; `filtered-export` also disclaims continuity.
`incident` permits discussion of cross-file relationships only with collection provenance
and independent corroboration. Every finding retains its full source file as `scenario_id`.
Deduplication uses scenario + full source file + host + channel + record ID + rule. Shared
lab identities do not join samples into an attack chain. Gaps alone do not prove tampering.

Workers return `completed_batches` and `limitations`; the workflow exposes missing workers
and incomplete batches. These declarations are not a tool-execution audit: inspect the
underlying tool results before claiming complete analysis. The 200-row review budget never
licenses labelling unread detections clean or discarded.
