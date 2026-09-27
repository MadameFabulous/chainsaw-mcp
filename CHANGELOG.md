# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Jev assessments list `uncertain_reasons`: insufficient context, low classification
  confidence, low priority confidence or validation failure. The existing `uncertain`
  boolean and default `min_confidence=0.8` are preserved, with threshold guidance.
- `chainsaw_jev_triage` reports exact `request_bytes` on success (zero for an empty page).
  Oversized-request errors include `request_bytes`, `max_request_bytes` and the largest
  fitting row prefix as `suggested_limit`, or narrowing advice when no row fits.
- `chainsaw_result_list` accepts `max_bytes` and returns byte counts and truncation
  metadata, fitting complete entries before advancing `next_offset`.
- Jev validation reports named checks and generated question keys in sanitised errors
  and logs. Failed assessment rows expose `error` and `question`; the response includes
  a `failed` count.
- MIT `LICENSE`, `CONTRIBUTING.md`, `SECURITY.md` and a GitHub Actions quality workflow.
- Package metadata (authors, keywords, classifiers, project URLs).
- `chainsaw_result_list` pages with `offset`, `limit` and `next_offset`.
- `chainsaw_get_mapping` serves the derived `sigma-event-logs-provider-aware.yml` by name
  and lists it while the bundled mapping is unmodified.
- `chainsaw_jev_triage` returns the resolved `model`, the API's token `usage`, the
  echoed `fields`, and page `truncated`/`truncation_reason`; `chainsaw_status` and
  `chainsaw-mcp --check` report `jev.credential_source`.
- Hunts and searches return `chainsaw_messages`, a bounded preview of Chainsaw's own load
  warnings with server paths redacted, and a `diagnostics` handle that stores the
  complete message stream; a noisy evidence set no longer fails a completed hunt.
- The systemd unit sets `MemoryMax` (override `MCP_MEMORY_MAX`) and `TasksMax`.
- Tests for the live Jev response shape (legend, usage, two-decimal rounding), aggregate
  rows, BWS subprocess isolation, credential precedence, time-window validation,
  aggregate-row filtering and summaries, rule validation, and the lineage query cap.
- Jev rubric evaluation reports, aggregate measurements and synthetic boundary cases.
  Both proposed prompt revisions remain experimental; runtime questions are unchanged.

### Changed
- Jev answer failures, including missing expected answers, fail only their source row
  with both scores null and `uncertain: true`. Valid rows are retained and sorted before
  failures. Invalid response containers and unknown question keys still reject the batch.
- `where` filters accept string, integer, float and boolean operands; numbers and
  booleans match exactly and text as a case-insensitive substring. On aggregate hunt
  rows every `document.*` predicate must match the same document.
- Chainsaw is never run with `-q`, so skipped files and unloadable rules are reported
  instead of silenced; the subprocess receives a minimal allow-listed environment.
- `--regex` and `--tau` values are passed as single `--flag=value` arguments.
- `from_time`/`to_time` windows are rejected when inverted for hunt, search and gap
  analysis.
- `chainsaw_save_rule` requires the full Chainsaw rule key set, rejects YAML anchors and
  aliases and rules above 64 KiB, and is annotated as destructive because it overwrites.
- `chainsaw_jev_triage` is annotated as not read-only because evidence leaves the host.
- `chainsaw_process_lineage` compares the host case-insensitively and enforces
  `max_queries` before issuing a query.
- `chainsaw-mcp-bootstrap` refuses to replace a populated vendor directory without
  `--force` and only removes it after the checksum has been verified.
- CLI help names the environment variable behind each transport option.
- The `bws` subprocess runs with a minimal environment and no stdin.
- Deployment scripts take the target host and user from `CHAINSAW_DEPLOY_NODE` and
  `CHAINSAW_DEPLOY_USER` instead of built-in defaults, and accept `MCP_HOST`,
  `MCP_PORT`, `MCP_PATH`, `MCP_TS_FQDN` and `MCP_MEMORY_MAX` overrides end to end.
- `chainsaw_lint_rules` reports problem file paths relative to the linted rule root.
- `chainsaw_process_lineage` records root-relative evidence paths in result metadata,
  like every other evidence tool.

### Fixed
- Exact numeric filters preserve large integer precision, including decimal-string
  operands; neighbouring 64-bit values are no longer selected together.
- Candidate deployment health probes bracket IPv6 addresses, as rollback probes do.
- Jev output enforces the encoded response budget, limits model identifiers to 200
  characters, and only returns non-negative `input_tokens`/`output_tokens` usage counters.
- The bootstrap installer rejects absolute archive member names as well as `..`
  segments before extracting a bundle.
- Jev answers were rejected when the API's two-decimal rounding put the score more than
  one millionth away from the probability-weighted mean (found in live testing); the
  validator now allows a 0.05 tolerance for the score and the probability sum.
- `chainsaw_analyse_srum` raises a clear error instead of storing an empty result when
  Chainsaw produces no output.
- `chainsaw_lint_rules` parses problem lines that carry no file name.
- `analysis_diagnostics` and hunt messages no longer expose server-absolute paths.
- Automatic rollback probes the listener declared by the restored unit instead of the
  failed candidate's, so a deployment that changed the bind address, port or path
  reports the previous release's health correctly.

### Removed
- Public result metadata no longer includes `argv`, which can contain server-absolute
  paths. The original command remains in the private metadata sidecar.
- Undocumented Jev usage fields are no longer passed through to clients.

## [0.1.0] - 2026-09-26

Initial release: MCP server (spec 2026-07-28) wrapping Chainsaw v2.16.5 with hunt,
search, dump, analysis, result-handle, rule-catalog and optional Jev triage tools;
agent skills and Claude Code workflows; hardened systemd deployment with rollback.
