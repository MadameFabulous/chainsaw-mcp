# chainsaw-mcp

An [MCP](https://modelcontextprotocol.io/specification/2026-07-28) server that wraps
[Chainsaw](https://github.com/WithSecureLabs/chainsaw), the Windows forensic artefact
hunting tool, so an agent can triage EVTX event logs, hunt with Sigma and Chainsaw rules,
detect log tampering, and author new detection rules without ever pulling raw logs into
its context.

Chainsaw release pinned: **v2.16.5**. MCP spec: **2026-07-28**. Python `mcp` SDK 2.x.

## What you get

| Area | Tools |
|---|---|
| Scope | `chainsaw_status`, `chainsaw_list_evidence`, `chainsaw_analyse_evtx` |
| Hunt | `chainsaw_hunt`, `chainsaw_search`, `chainsaw_dump` |
| Process pivots | `chainsaw_process_lineage` (explicit scenario files and host; bounded traversal) |
| Anti-forensics / timelines | `chainsaw_analyse_gaps`, `chainsaw_analyse_shimcache`, `chainsaw_analyse_srum` |
| Results (server-minted handles) | `chainsaw_result_page`, `chainsaw_result_summary`, `chainsaw_result_fields`, `chainsaw_result_export`, `chainsaw_result_list`, `chainsaw_result_delete` |
| Event grouping / oversized rows | `chainsaw_result_events`, `chainsaw_result_chunk` |
| Rules | `chainsaw_rule_stats`, `chainsaw_search_rules`, `chainsaw_get_rule`, `chainsaw_get_mapping`, `chainsaw_lint_rules`, `chainsaw_save_rule`, `chainsaw_delete_rule` |
| Optional Jev assessment | `chainsaw_jev_triage` (external API; explicitly enabled) |

Resources: `chainsaw://rules/{kind}/{path}`, `chainsaw://mappings/{name}`,
`chainsaw://results/{handle}`, `chainsaw://docs/rule-format`, `chainsaw://config`.
Prompts: `triage_evtx`, `pivot_on_indicator`, `author_rule`.

Hunts, searches and dumps write JSONL to `CHAINSAW_OUTPUT_DIR` and return a
`res_<hex16>` handle plus an aggregate summary and a small preview. Everything else is
paged or grouped through that handle, which keeps the server stateless in the MCP sense
while letting the agent work on tens of thousands of detections.

Pages and exports enforce encoded-JSON byte budgets with resumable offsets; previews
are projected rather than full records. EVTX coverage and gap details are handle-backed.
Summaries distinguish rule matches from unique source events. See
[result delivery and continuation](docs/_result-handles.md).

The implicit default mapping repairs Security 4688 `Image` translation to
`NewProcessName` while preserving Sysmon behavior. It derives a private cached mapping
only for the recognized pinned upstream mapping (SHA-256 checked); explicit/custom mapping
selections remain unchanged. The derived file lives under `CHAINSAW_OUTPUT_DIR/.mappings/`,
is content-addressed and is never swept with expired results. `chainsaw_get_mapping`
reports routing preconditions and translations.

## Quick start

```bash
uv sync                                   # creates .venv with mcp, httpx, pyyaml, dev tools
uv run chainsaw-mcp-bootstrap             # downloads v2.16.5 bundle, verifies sha256,
                                          # installs vendor/chainsaw/{chainsaw,rules,sigma,mappings}
mkdir -p evidence && cp -r /path/to/evtx evidence/
uv run chainsaw-mcp --check               # prints status JSON
uv run chainsaw-mcp                       # stdio transport
uv run chainsaw-mcp --transport streamable-http --host 127.0.0.1 --port 18098 --path /mcp
```

Claude Code registration (stdio):

```bash
claude mcp add chainsaw -- uv --directory /path/to/chainsaw-mcp run chainsaw-mcp
```

Configuration is by environment variables; see `.env.example`. Evidence paths passed to
tools must resolve inside `CHAINSAW_EVIDENCE_ROOTS` (default `./evidence`). Nothing under an evidence root is ever written.

Transport security: streamable HTTP always runs with DNS-rebinding protection. The bind
host, `localhost` and `127.0.0.1` are accepted as `Host` headers; add more with
`MCP_ALLOWED_HOSTS` (comma-separated, `host` or `host:*`) and browser origins with
`MCP_ALLOWED_ORIGINS`. The endpoint has no authentication of its own, so bind it to a
loopback or private overlay address and let network reachability be the access control;
see [SECURITY.md](SECURITY.md) and [docs/deployment.md](docs/deployment.md).
The server makes no outbound network calls except the bootstrap download and, when
explicitly enabled, `chainsaw_jev_triage`.

## Jev result triage

`chainsaw_jev_triage` classifies and prioritizes selected result rows using
[TypeSafe Jev](https://docs.typesafe.ai/introduction). It returns source row indexes,
probabilities and confidence, flags uncertain assessments, and preserves the evidence.
The feature is disabled by default. Enable it with `CHAINSAW_JEV_ENABLED=true` and either
`CHAINSAW_JEV_BWS_SECRET_ID` or an injected `TYPESAFE_API_KEY`. BWS lookup reads the key
only when the tool is called; credentials never appear in status or result output.

Preview a small page with `chainsaw_result_page`, then call `chainsaw_jev_triage` with
the same handle, offset, limit and fields. Selected fields are sent to TypeSafe; omitting
`fields` sends complete selected rows, including the server-side evidence file path. The
tool makes one request for up to 10 rows,
returns advisory scores, and does not automatically run after hunts. See
[Jev setup and workflow](docs/jev.md) for configuration, limits and examples.

## Deployment

For a long-lived service, run the streamable HTTP transport as a hardened systemd user unit
bound to a private address (a Tailscale IP is the default). `deploy/deploy-node.sh` ships
a clean, committed tree to a host named by `CHAINSAW_DEPLOY_NODE` and
`CHAINSAW_DEPLOY_USER`, syncs the venv, bootstraps Chainsaw if missing, renders the unit
for that host, health-checks the endpoint and rolls back automatically on failure. The
unit is sandboxed and capped at 4 GiB of memory (`MCP_MEMORY_MAX`) and 512 tasks. The
manual procedure, the unit's sandboxing and the Jev enablement steps are in
[docs/deployment.md](docs/deployment.md).

## Layout

```
src/chainsaw_mcp/   server, tools/, rules catalog, mapping repair, result store + byte budgets, bootstrap, CLI
tests/              unit tests (no binary needed; the workflow partition test needs Node), integration/ (needs vendor + samples), fixtures/ (pinned scenario manifest)
docs/               tool reference (generated), result-handle contract, multi-step workflows, Jev setup, deployment
scripts/            quality-check.sh, integration-check.sh, gen-tool-docs.py, check-tool-docs.py, check-package.py, mcp-health.py (endpoint probe)
deploy/             deploy-node.sh (ship over ssh), install-node.sh (target-side install + rollback), render-unit.sh, reference unit
.agents/skills/     agent skills: chainsaw-triage, chainsaw-rule-authoring
.claude/workflows/  Claude Code workflow scripts (evtx-triage, rule-authoring-loop)
.claude/skills/     Claude Code operator skill (/chainsaw)
skills/research/    portable agent skill (frontmatter + markdown), ready to copy into any skills directory
custom-rules/       analyst-authored Chainsaw rules saved by chainsaw_save_rule
```

## Development

```bash
bash scripts/quality-check.sh       # the CI unit gate: locked sync, ruff, mypy, pytest with coverage, docs drift, bash -n, build
bash scripts/integration-check.sh   # the CI integration gate: bootstraps Chainsaw, pins evidence/EVTX-ATTACK-SAMPLES, runs -m integration
uv run pytest                       # unit tests only
uv run ruff check . && uv run ruff format --check .
uv run mypy                         # src/chainsaw_mcp, check_untyped_defs
uv run python scripts/gen-tool-docs.py > docs/tools.md   # after changing a tool signature, docstring, resource or docs/_result-handles.md
uv run python scripts/check-tool-docs.py                 # the drift check CI runs
```

`.github/workflows/quality.yml` runs
both scripts on every push and pull request with pinned action revisions. `quality-check.sh` fails below 70 % branch coverage and when
`docs/tools.md` drifts from the live tool schema. `docs/tools.md` is generated and embeds
`docs/_result-handles.md`, so edit those sources rather than the generated file.
`integration-check.sh` fails if any integration test is skipped, so a missing binary or
sample tree can never pass silently. `tests/test_workflow_partition.py` executes the real
`evtx-triage.js` in Node and is skipped when `node` is not on `PATH`.

Sample evidence lives under `evidence/` (gitignored), one directory per public set:

| Directory | Source | Contents |
|---|---|---|
| `evidence/EVTX-ATTACK-SAMPLES` | `git clone https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES` | 278 attack-technique files; the integration tests pin this set |
| `evidence/EVTX-to-MITRE-Attack` | `git clone https://github.com/mdecrevoisier/EVTX-to-MITRE-Attack` | 293 attack files grouped by ATT&CK tactic and technique |
| `evidence/evtx-baseline/<os>` | per-OS `.tgz` assets from [NextronSystems/evtx-baseline releases](https://github.com/NextronSystems/evtx-baseline/releases) | benign goodware logs for false-positive and negative testing |

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) for the development workflow and
[SECURITY.md](SECURITY.md) for the threat model and how to report a vulnerability.

## Licence

This server is [MIT](LICENSE). Chainsaw itself is GPL-3.0 and is downloaded at bootstrap
time, not redistributed here. Sigma rules are DRL 1.1.
