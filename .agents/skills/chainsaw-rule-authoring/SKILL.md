---
name: chainsaw-rule-authoring
description: Write, lint and test Chainsaw detection rules with the chainsaw MCP tools. Use when asked to create a detection for observed behaviour, convert a finding into a reusable rule, or check rule coverage for an ATT&CK technique.
---

# Chainsaw rule authoring

Turn an observed behaviour into a Chainsaw-format rule, validate it with `chainsaw lint`,
and prove it with positive and negative hunts. Custom rules live in the server's
`custom-rules/` directory and are hunted with `extra_rules=["custom"]`.

## Procedure

1. **Check prior art.** `chainsaw_search_rules(query=..., tag=...)` across sigma and
   chainsaw kinds. If a Sigma rule already covers it, report that instead of duplicating.
   If it exists but is not firing, `chainsaw_get_mapping()` to see whether its logsource is
   mapped, and `chainsaw_lint_rules(kind="sigma", path=...)` for unsupported modifiers.
2. **Get exact fields.** With a result handle containing an example event:
   `chainsaw_result_fields(handle)` then `chainsaw_result_page(handle, limit=1)` to copy
   real field names and values. Never guess `EventData` names.
3. **Read the format.** Resource `chainsaw://docs/rule-format`, or
   `references/rule-template.yml` here.
4. **Write and save.** `chainsaw_save_rule(name, yaml_text)`. The response includes the lint
   result; fix every `problems[]` entry and resave with `overwrite=true` until `lint.ok`.
5. **Positive test.** `chainsaw_hunt(paths=[evidence that must match], sigma=false,
   chainsaw_rules=false, extra_rules=["custom"])`. Expect `total >= 1`; read the preview to
   confirm it matched the intended events, not everything.
6. **Negative test.** Same hunt on evidence that must not match. Expect `total == 0` or
   explain the hits and tighten the filter.
7. **Deliver.** Final YAML, ATT&CK technique(s), both hunt totals, known false positives,
   required log source (e.g. "Sysmon EID 1 with command-line") and the `uri`.

## Quality bar

- `level` reflects confidence *and* impact: `critical` only for near-zero false positives.
- `status: experimental` until validated on more than one dataset.
- Prefer several narrow `filter` keys combined in `condition` over one broad wildcard.
- Use `i` prefix for case-insensitive matches on paths and user names; Windows is
  case-insensitive but logs are not normalised.
- `fields` should list what an analyst needs at a glance: time, host, user, process,
  command line, target.
- Keep `group` consistent with the bundled groups so hunt output stays tidy.

## Cleaning up

`chainsaw_delete_rule(name)` removes a scratch rule. Promote finished rules through code
review into a proper rules repository; the custom directory is not version-controlled by
the server.
