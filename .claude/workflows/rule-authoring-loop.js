export const meta = {
  name: 'rule-authoring-loop',
  description: 'Draft competing Chainsaw rules for a behaviour, lint and test each, judge, and deliver the best',
  whenToUse: 'Turning an observed behaviour into a validated Chainsaw detection rule. Pass {behaviour, positive, negative?, handle?} as args.',
  phases: [
    { title: 'Research', detail: 'prior art, exact field names' },
    { title: 'Draft', detail: 'independent rule drafts from different angles' },
    { title: 'Validate', detail: 'lint + positive/negative hunts per draft' },
    { title: 'Judge', detail: 'pick and polish the winner' },
  ],
}

// args: { behaviour: "...", positive: "evidence/path that must match", negative: "evidence/path that must not", handle?: "res_..." }
if (!args || !args.behaviour || !args.positive) {
  return { error: 'args.behaviour and args.positive are required' }
}
const { behaviour, positive, negative, handle } = args

const RESEARCH_SCHEMA = {
  type: 'object',
  properties: {
    existing_rules: { type: 'array', items: { type: 'string' } },
    field_paths: { type: 'array', items: { type: 'object', properties: { path: { type: 'string' }, example: { type: 'string' } }, required: ['path'] } },
    attack_ids: { type: 'array', items: { type: 'string' } },
    log_source: { type: 'string' },
    notes: { type: 'string' },
  },
  required: ['field_paths', 'log_source'],
}
const DRAFT_SCHEMA = {
  type: 'object',
  properties: {
    name: { type: 'string', description: 'file name without extension, snake_case' },
    yaml: { type: 'string' },
    rationale: { type: 'string' },
  },
  required: ['name', 'yaml', 'rationale'],
}
const VALIDATION_SCHEMA = {
  type: 'object',
  properties: {
    name: { type: 'string' },
    lint_ok: { type: 'boolean' },
    lint_problems: { type: 'array', items: { type: 'string' } },
    positive_total: { type: 'number' },
    negative_total: { type: 'number' },
    final_yaml: { type: 'string' },
    iterations: { type: 'number' },
    notes: { type: 'string' },
  },
  required: ['name', 'lint_ok', 'positive_total', 'final_yaml', 'iterations'],
}
const JUDGE_SCHEMA = {
  type: 'object',
  properties: {
    winner: { type: 'string' },
    final_yaml: { type: 'string' },
    level_justification: { type: 'string' },
    false_positives: { type: 'array', items: { type: 'string' } },
    attack_ids: { type: 'array', items: { type: 'string' } },
    summary: { type: 'string' },
  },
  required: ['winner', 'final_yaml', 'summary'],
}

phase('Research')
const research = await agent(
  `Research for a Chainsaw detection rule. Behaviour: ${behaviour}. Use the chainsaw MCP tools
(ToolSearch "chainsaw"). 1) chainsaw_search_rules with several queries and ATT&CK tags to list
existing Sigma/Chainsaw rules that already cover this. 2) ${handle
    ? `chainsaw_result_fields("${handle}") and chainsaw_result_page("${handle}", limit=3) to capture exact field paths and example values.`
    : `chainsaw_search(paths=["${positive}"], patterns=[relevant keywords]) then chainsaw_result_fields on the handle to capture exact field paths and example values.`}
3) Read the resource chainsaw://docs/rule-format. Return the field paths with examples,
ATT&CK IDs, and the required log source.`,
  { label: 'research', phase: 'Research', schema: RESEARCH_SCHEMA },
)
if (!research) return { error: 'research failed' }
log(`prior art: ${research.existing_rules?.length || 0} rules; ${research.field_paths.length} field paths`)

const ANGLES = [
  { key: 'narrow', hint: 'Be as specific as possible: several ANDed keys, exact event IDs, allowlist obvious benign parents. Optimise for zero false positives.' },
  { key: 'broad', hint: 'Favour recall: catch variants (renamed binaries, encoded arguments, alternate event sources). Optimise for not missing the behaviour.' },
  { key: 'analyst', hint: 'Optimise the fields[] table and description for an analyst reading hunt output; balanced precision/recall; mirror bundled rule style.' },
]

const validated = await pipeline(
  ANGLES,
  (angle) =>
    agent(
      `Draft ONE Chainsaw rule (YAML) for: ${behaviour}. Angle: ${angle.hint}
Use ONLY these verified field paths/examples: ${JSON.stringify(research.field_paths)}.
Log source: ${research.log_source}. ATT&CK: ${JSON.stringify(research.attack_ids || [])}.
Existing rules to avoid duplicating: ${JSON.stringify(research.existing_rules || [])}.
Follow the schema in .agents/skills/chainsaw-rule-authoring/references/rule-template.yml
(title, group, description, authors, kind: evtx, level, status: experimental, timestamp,
fields, filter with condition). Name the file ${angle.key}_<snake_case>. Return the YAML.`,
      { label: `draft:${angle.key}`, phase: 'Draft', schema: DRAFT_SCHEMA },
    ),
  (draft, angle) => {
    if (!draft) return null
    return agent(
      `Validate and fix a Chainsaw rule with the chainsaw MCP tools (ToolSearch "chainsaw").
Rule name: ${draft.name}. YAML:\n${draft.yaml}\n
Loop (max 4 iterations): chainsaw_save_rule(name, yaml_text, overwrite=true) -> if
lint.problems, fix the YAML and save again. Then positive test:
chainsaw_hunt(paths=["${positive}"], sigma=false, chainsaw_rules=false, extra_rules=["custom"])
must give total >= 1 (inspect the preview to confirm the right events matched).
${negative ? `Negative test: same hunt on paths=["${negative}"] should give total == 0; if not, tighten the filter without breaking the positive test.` : 'No negative evidence supplied; note that.'}
Leave the final rule saved. Return the final YAML, totals, and how many save iterations you needed.`,
      { label: `validate:${angle.key}`, phase: 'Validate', schema: VALIDATION_SCHEMA },
    )
  },
)

const candidates = validated.filter(Boolean)
log(`${candidates.length}/${ANGLES.length} drafts validated: ${candidates.map((c) => `${c.name} lint=${c.lint_ok} +${c.positive_total} -${c.negative_total ?? '?'}`).join('; ')}`)
if (!candidates.length) return { error: 'no draft survived validation', research }

phase('Judge')
const verdict = await agent(
  `Judge these validated Chainsaw rule candidates for "${behaviour}" and produce the final rule.
Candidates: ${JSON.stringify(candidates)}. Criteria: lint_ok, positive_total >= 1,
negative_total == 0 (when present), specificity of the filter, quality of fields[] for an
analyst, correct level (critical only for near-zero false positives), clear description.
You may merge the best parts. Use chainsaw_save_rule(name="final_<snake_case>",
yaml_text, overwrite=true) to save the winner and confirm lint.ok, then
chainsaw_delete_rule for the losing candidate names (${candidates.map((c) => c.name).join(', ')})
so only the final rule remains. Return the final YAML, ATT&CK IDs, expected false positives
and a one-paragraph summary.`,
  { label: 'judge', phase: 'Judge', schema: JUDGE_SCHEMA },
)

return { verdict, candidates: candidates.map((c) => ({ name: c.name, lint_ok: c.lint_ok, positive: c.positive_total, negative: c.negative_total })), research }
