export const meta = {
  name: 'evtx-triage',
  description: 'Partition a complete evidence inventory into explicit file batches, verify findings, report isolated scenarios',
  whenToUse: 'Pass {path, inventoryPages, focus?, maxSlices?, mode?}; inventoryPages must be verbatim complete chainsaw_list_evidence responses, not an agent-selected scope.',
  phases: [
    { title: 'Scope', detail: 'list evidence and pick slices' },
    { title: 'Hunt', detail: 'one agent per slice runs the chainsaw-triage procedure' },
    { title: 'Verify', detail: 'adversarial refutation of each high-confidence finding' },
    { title: 'Synthesise', detail: 'merge timelines and write the report' },
  ],
}

// Caller fetches chainsaw_status and ALL chainsaw_list_evidence pages before invoking.
// No LLM chooses paths. maxSlices bounds workers, not coverage; each worker may have
// several batches, each containing at most 64 explicit EVTX file paths.
const root = args && args.path
const focus = (args && args.focus) || 'credential access, lateral movement, persistence, defence evasion, anti-forensics'
const maxSlices = args.maxSlices ?? 12
const mode = args.mode ?? 'curated-samples'

function partitionEvidence(pages, workerLimit) {
  // Use the server's resolved POSIX base, never resolve relative paths on the client.
  if (typeof root !== 'string' || !root.startsWith('/') || root.includes('\u0000') ||
      (root !== '/' && root.slice(1).split('/').some((part) => !part || part === '.' || part === '..'))) {
    throw new Error('path must be the canonical absolute server evidence base')
  }
  if (!Number.isInteger(workerLimit) || workerLimit < 1) throw new Error('maxSlices must be a positive integer')
  if (!Array.isArray(pages) || !pages.length) throw new Error('complete inventoryPages required')
  let offset = 0
  const seen = new Set()
  const files = []
  const base = pages[0].base
  if (typeof base !== 'string' || !base) throw new Error('inventory base required')
  const total = pages[0].total
  if (!Number.isSafeInteger(total) || total < 0) throw new Error('inventory total required')
  for (let i = 0; i < pages.length; i++) {
    const page = pages[i]
    if (page.base !== root || page.base !== base || page.pattern !== '') throw new Error('inconsistent or filtered inventory')
    if (!Array.isArray(page.files) || page.returned !== page.files.length) throw new Error('inventory count mismatch')
    if (page.offset !== offset) throw new Error('missing or repeated inventory page')
    if (typeof page.truncated !== 'boolean') throw new Error('inventory completeness unknown')
    const more = page.truncated
    if (page.has_more !== undefined && page.has_more !== more) throw new Error('inconsistent inventory completeness')
    if (more !== (i < pages.length - 1)) throw new Error('incomplete inventory or extra pages')
    for (const file of page.files) {
      if (typeof file.path !== 'string' || !file.path || seen.has(file.path)) throw new Error('invalid or duplicate inventory path')
      seen.add(file.path)
      if (file.path.toLowerCase().endsWith('.evtx')) files.push(file.path)
    }
    offset += page.returned
    if (more && (!page.returned || page.next_offset !== offset)) throw new Error('inventory pagination unavailable or inconsistent')
    if (!more && page.next_offset !== null) throw new Error('terminal inventory must have null next_offset')
    if (page.total !== total || total < offset || (more ? total <= offset : total !== offset)) throw new Error('inventory total mismatch')
  }
  files.sort()
  const batches = []
  for (let i = 0; i < files.length; i += 64) {
    batches.push({ id: `batch-${batches.length + 1}`, paths: files.slice(i, i + 64) })
  }
  const slices = Array.from({ length: Math.min(workerLimit, batches.length) }, (_, i) => ({ id: `worker-${i + 1}`, batches: [] }))
  batches.forEach((batch, i) => slices[i % slices.length].batches.push(batch))
  const assigned = slices.flatMap((slice) => slice.batches.flatMap((batch) => batch.paths))
  if (assigned.length !== files.length || new Set(assigned).size !== files.length || files.some((path) => !assigned.includes(path))) throw new Error('partition is not complete and disjoint')
  return { slices, files, coverage_notes: `${files.length} EVTX files in ${batches.length} disjoint batches; ${offset - files.length} non-EVTX files excluded` }
}

const FINDINGS_SCHEMA = {
  type: 'object',
  properties: {
    slice: { type: 'string' },
    handle: { type: 'string' },
    completed_batches: { type: 'array', items: { type: 'string' } },
    limitations: { type: 'array', items: { type: 'string' } },
    total_detections: { type: 'number' },
    tampering: { type: 'string' },
    findings: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          title: { type: 'string' },
          rule: { type: 'string' },
          host: { type: 'string' },
          account: { type: 'string' },
          time_utc: { type: 'string' },
          attack_ids: { type: 'array', items: { type: 'string' } },
          confidence: { type: 'string', enum: ['high', 'medium', 'low'] },
          source_file: { type: 'string' },
          scenario_id: { type: 'string', description: 'Exact full source file path; do not merge sample scenarios' },
          channel: { type: ['string', 'null'] },
          record_id: { type: ['string', 'number'] },
          evidence: { type: 'string', description: 'file, EventRecordID, key fields' },
          reasoning: { type: 'string' },
        },
        required: ['title', 'rule', 'host', 'time_utc', 'confidence', 'evidence', 'reasoning', 'source_file', 'scenario_id', 'channel', 'record_id'],
      },
    },
    discarded: { type: 'array', items: { type: 'string' } },
  },
  required: ['slice', 'findings', 'completed_batches', 'limitations'],
}

const VERDICT_SCHEMA = {
  type: 'object',
  properties: {
    refuted: { type: 'boolean' },
    reason: { type: 'string' },
    adjusted_confidence: { type: 'string', enum: ['high', 'medium', 'low'] },
  },
  required: ['refuted', 'reason'],
}

function findingKey(finding) {
  return JSON.stringify([finding.scenario_id, finding.source_file, finding.host, finding.channel, finding.record_id, finding.rule])
}

phase('Scope')
if (!['curated-samples', 'filtered-export', 'incident'].includes(mode)) throw new Error('invalid mode')
const scope = partitionEvidence(args.inventoryPages, maxSlices)
if (!scope || !scope.slices.length) {
  return { error: 'no evidence slices found', scope }
}
log(`${scope.slices.length} slices; ${scope.coverage_notes || ''}`)
phase('Hunt')

const results = await pipeline(
  scope.slices,
  (slice) =>
    agent(
      `Follow the chainsaw-triage skill procedure (read .agents/skills/chainsaw-triage/SKILL.md
in this repository first) on these explicit batches ${JSON.stringify(slice.batches)} using the chainsaw MCP
tools (load with ToolSearch "chainsaw"). Focus: ${focus}.
Process EVERY batch, passing its exact paths[] to each tool; never substitute a directory,
truncate a batch, or widen a pivot. Call chainsaw_analyse_evtx for coverage first.
Keep one hunt handle per batch in your reasoning; report findings from every batch.
Return completed_batches containing only batch IDs actually analysed and hunted, and
limitations listing incomplete analysis, parser errors, skipped files or review budget exhaustion.
Mode: ${mode}. Each file is a separate scenario_id equal to its exact full source path.
Do not correlate different files merely because hosts, usernames, record IDs or times match.
Only in incident mode may you discuss cross-file relationships with independently corroborated
collection provenance, while retaining each source's scenario_id. Gaps alone do not establish
tampering: require continuity/collection corroboration; curated samples and filtered exports
are not continuous logs. Clearing events require actor and operational context.
Steps per batch: chainsaw_analyse_gaps -> chainsaw_hunt(preview=5) -> read the summary -> page or
aggregate the critical/high rules -> pivot with chainsaw_search where needed. Do not page
more than 200 rows in total; explicitly list unreviewed rules/rows as coverage limitations,
not as discarded or clean. Report every finding with full file + host + channel + EventRecordID evidence and
list what you discarded and why. Return the hunt result handle so later stages can reuse it.`,
      { label: `hunt:${slice.id}`, phase: 'Hunt', schema: FINDINGS_SCHEMA },
    ),
  (report, slice) => {
    if (!report) return null
    const allowed = new Set(slice.batches.flatMap((batch) => batch.paths))
    for (const finding of report.findings) {
      if (!allowed.has(finding.source_file) || finding.scenario_id !== finding.source_file) throw new Error('finding outside assigned scenario')
    }
    report.slice = slice.id
    const expected = slice.batches.map((batch) => batch.id)
    report.incomplete_batches = expected.filter((id) => !report.completed_batches.includes(id))
    if (report.completed_batches.some((id) => !expected.includes(id))) throw new Error('unknown completed batch')
    const strong = report.findings.filter((f) => f.confidence !== 'low')
    if (!strong.length) return { ...report, verified: [] }
    return parallel(
      strong.map((f) => () =>
        agent(
          `Try to REFUTE this forensic finding using the chainsaw MCP tools (ToolSearch
"chainsaw"). Finding: ${JSON.stringify(f)}. Result handle from the hunt: ${report.handle || 'n/a'}
(use chainsaw_result_page with full source_file, host, channel and record_id filters; if
the handle is absent, wrong or expired, re-run chainsaw_hunt(paths=${JSON.stringify([f.source_file])})).
Never widen to another scenario. Check: does the referenced event exist with those fields? Is there a benign
explanation (admin tooling, scheduled job, known-good parent)? Does the rule have documented
false positives (chainsaw_get_rule) that match? Default to refuted=true if you cannot
confirm the event exists. Suggest an adjusted confidence.`,
          { label: `verify:${f.rule}@${f.host}`, phase: 'Verify', schema: VERDICT_SCHEMA },
        ).then((v) => ({ finding: f, verdict: v })),
      ),
    ).then((verdicts) => ({ ...report, verified: verdicts.filter(Boolean) }))
  },
)

const reports = results.filter(Boolean)
const confirmedRows = reports.flatMap((r) =>
  r.verified
    .filter((v) => v.verdict && !v.verdict.refuted)
    .map((v) => ({ ...v.finding, slice: r.slice, confidence: v.verdict.adjusted_confidence || v.finding.confidence })),
)
const confirmed = [...new Map(confirmedRows.map((finding) => [findingKey(finding), finding])).values()]
const refuted = reports.flatMap((r) =>
  r.verified.filter((v) => v.verdict && v.verdict.refuted).map((v) => ({ ...v.finding, slice: r.slice, why: v.verdict.reason })),
)
log(`${confirmed.length} findings confirmed, ${refuted.length} refuted across ${reports.length} slices`)

phase('Synthesise')
const report = await agent(
  `Write the final triage report in Markdown for evidence root "${root}" (focus: ${focus}).
Inputs (JSON): confirmed findings ${JSON.stringify(confirmed)}; refuted findings
${JSON.stringify(refuted)}; per-slice tampering notes
${JSON.stringify(reports.map((r) => ({ slice: r.slice, tampering: r.tampering, total: r.total_detections, discarded: r.discarded, limitations: r.limitations, incomplete_batches: r.incomplete_batches })))};
Missing workers: ${JSON.stringify(scope.slices.filter((s) => !reports.some((r) => r.slice === s.id)).map((s) => s.id))}.
Never describe missing workers, incomplete batches, parser failures or unreviewed detections as clean.
coverage notes: ${scope.coverage_notes || 'none'}.
Sections: Executive summary; Timeline (UTC) as a table sorted by time with host, account,
event, detection, confidence, evidence pointer; Techniques (ATT&CK IDs); Anti-forensics and
coverage gaps; Discarded/refuted detections with reasons; Recommended next steps. Merge
duplicates ONLY with identical scenario_id + full source_file + host + channel + record_id + rule.
Mode: ${mode}. Present separate scenario timelines, never a single attack chain across unrelated
samples; shared host/user names or time proximity are not corroboration. Gaps alone are
coverage observations, not anti-forensics findings; require continuity evidence and context.
Do not invent events that are not in
the inputs. Return only the Markdown.`,
  { label: 'synthesise', phase: 'Synthesise' },
)

return { report, confirmed, refuted, slices: scope.slices, coverage: scope.coverage_notes,
  incomplete_batches: reports.flatMap((r) => r.incomplete_batches),
  limitations: reports.flatMap((r) => r.limitations),
  incomplete_workers: scope.slices.filter((s) => !reports.some((r) => r.slice === s.id)).map((s) => s.id) }
