# Contributing

Thanks for helping improve chainsaw-mcp. Bug reports, detection-quality feedback and
pull requests are all welcome.

## Development setup

```bash
uv sync                          # dev group: pytest, ruff, mypy, hatchling
uv run chainsaw-mcp-bootstrap    # pinned Chainsaw bundle into vendor/chainsaw (checksummed)
uv run chainsaw-mcp --check      # confirms the binary, rules and evidence roots
```

Unit tests need no binary. The integration tier needs `vendor/chainsaw` and the pinned
`evidence/EVTX-ATTACK-SAMPLES` checkout; `scripts/integration-check.sh` fetches both.
`tests/test_workflow_partition.py` runs the real workflow JavaScript and is skipped when
`node` is not on `PATH`.

## Before opening a pull request

```bash
bash scripts/quality-check.sh        # ruff, mypy, unit tests with coverage, docs drift, bash -n, build
bash scripts/integration-check.sh    # real Chainsaw against the pinned sample set
```

Both scripts are exactly what CI runs. The unit gate fails below 70 % branch coverage and
when `docs/tools.md` no longer matches the live tool schema. After changing a tool
signature, docstring, resource, prompt or `docs/_result-handles.md`, regenerate the
reference:

```bash
uv run python scripts/gen-tool-docs.py > docs/tools.md
```

## Ground rules for changes

- Evidence is read-only. Nothing under an evidence root may ever be written, and every
  client-supplied path must go through `paths.resolve_under`.
- Chainsaw is invoked as an argument list, never through a shell. Keep it that way.
- Large output goes into result handles, never inline. New tools that can return
  unbounded data must use the `ResultStore` and the byte budgets in `result_budget.py`.
- Public tool names, parameters and response keys are a contract for agents and skills.
  Add fields rather than renaming them; note removals in `CHANGELOG.md`.
- Keep the server free of outbound network calls apart from the bootstrap download and
  the explicitly enabled Jev tool.
- Match the existing style: ruff with a 100-column limit, type hints checked by mypy,
  British spelling in prose ("artefact", "analyse") because Chainsaw uses it.

## Reporting security issues

See [SECURITY.md](SECURITY.md).
