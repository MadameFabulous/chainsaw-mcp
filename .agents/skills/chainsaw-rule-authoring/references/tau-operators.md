# Tau operators (Chainsaw rule filter syntax)

Values in `filter` blocks are matched against the document field named by the key.

| Syntax | Meaning |
|---|---|
| `value` | exact string match (numbers compare as strings unless prefixed) |
| `*abc*` | wildcard contains; `?` single character |
| `iABC` | case-insensitive match (combine: `i*abc*`) |
| `=5`, `>5`, `<5`, `>=5`, `<=5` | numeric comparison |
| `- a` / `- b` list | any-of for that key |
| `key: not ...` | negate a key inside a condition via `condition: a and not b` |
| `all of x*` / `1 of x*` | quantifiers over keys with a common prefix |
| `condition:` | boolean expression over key names: `and`, `or`, `not`, parentheses |

Escape backslashes in Windows paths as `\\`. Field paths are dotted:
`Event.EventData.TargetUserName`. Chainsaw flattens EVTX attributes with `_attributes`
(e.g. `Event.System.Provider_attributes.Name`).

Lint locally with `chainsaw_lint_rules(kind="custom", path="<name>.yml", tau=true)` to see
the compiled logic.
