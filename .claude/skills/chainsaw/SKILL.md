---
name: chainsaw
description: Operator guide for the chainsaw MCP server in this repo. Use when triaging Windows EVTX with the chainsaw_* tools, authoring Chainsaw rules, or running the evtx-triage / rule-authoring-loop workflows.
---

# Chainsaw MCP operator guide

Tools are exposed by the `chainsaw` MCP server (load with ToolSearch "chainsaw"). Full
reference: `docs/tools.md`. Procedures: `docs/multi-step-workflows.md`.

Pick the depth:

- **Quick look at one file or directory**: follow `.agents/skills/chainsaw-triage/SKILL.md`
  inline (status → list → analyse → hunt → summary → page → pivot → report).
- **Many hosts or a large collection**: run the saved workflow `evtx-triage` with
  `args: {path: "<absolute server-side base>", inventoryPages: [...], focus?: "...", mode?: "..."}`.
  `path` must equal the `base` every `chainsaw_list_evidence` page returns; discovery may
  use a relative alias, but pages whose `base` differs are rejected. First collect verbatim,
  unfiltered `chainsaw_list_evidence(limit=1000)` responses through the final page
  (`next_offset`); the workflow validates completeness and deterministically assigns
  every EVTX path, including root files, to batches of at most 64. `maxSlices` limits
  workers, not files: overflow becomes additional batches. Missing inventory fails closed.
  It adversarially verifies each medium/high finding before reporting.
- **Turn a behaviour into a detection**: run `rule-authoring-loop` with
  `args: {behaviour, positive: "<evidence that must match>", negative?: "<clean evidence>"}`
  or follow `.agents/skills/chainsaw-rule-authoring/SKILL.md` by hand.
- **Prepare a formal report from findings**: follow
  `.agents/skills/chainsaw-reporting/SKILL.md` for evidence references, incident response
  formatting, an adaptable Markdown template and preservation of supporting exports.

Rules of the road:

1. Large outputs come back as handles. Summarise and filter before paging; never page more
   than a few hundred rows.
2. Every finding cites full source file + scenario ID + host + channel + EventRecordID +
   UTC time + rule + confidence. Deduplicate on the full identity, never basename/host/ID alone.
   Default `mode: "curated-samples"` keeps each sample separate, even when lab hosts or users
   match. `filtered-export` also makes no continuity assumption. Use `incident` only with
   collection provenance and independent corroboration before correlating files. Gaps alone
   do not prove tampering; clearing events need actor/maintenance context. Report unreviewed
   batches, parser errors and review-budget limits explicitly.
3. `chainsaw_save_rule` writes to `custom-rules/`; keep `status: experimental` until the rule
   passes a positive and a negative hunt.
4. Evidence is read-only and sandboxed to `CHAINSAW_EVIDENCE_ROOTS`; if a path is rejected,
   list the roots with `chainsaw_status` rather than guessing.
5. `chainsaw_jev_triage` is the only tool that leaves the host (TypeSafe Jev API). It is off
   unless `chainsaw_status` shows `jev.enabled`; preview the rows with `chainsaw_result_page`
   and pass an explicit `fields` list before sending. Scores are advisory. See `docs/jev.md`.

Dev loop for the server itself: `uv run pytest` (unit), `uv run pytest tests/integration
-m integration` (needs `vendor/chainsaw` and `evidence/EVTX-ATTACK-SAMPLES/`), `uv run ruff check .`,
regenerate the tool reference with `uv run python scripts/gen-tool-docs.py > docs/tools.md`
(it embeds `docs/_result-handles.md`; `scripts/check-tool-docs.py` is the CI drift check).
