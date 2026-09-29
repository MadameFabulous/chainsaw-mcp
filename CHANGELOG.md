# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Opt-in `redact_paths` replay/plan exports label rebased paths and require explicit input
  roots; default exports retain verbatim provenance. Legacy EVTX overview replay exports
  report machine-readable partial status per handle and in the response/manifest header.
- Digest pins for Python, uv and the Dockerfile frontend, with a documented refresh process.
  The container gate supports Docker-capable CI runners; build networking is configurable
  and checks use unique, automatically removed image tags.
- `chainsaw_evidence_manifest` and `chainsaw_evidence_validate` create signed full-directory
  inventories and validation receipts for chain-of-custody activities. They include hidden
  files, portable relative paths, custody declarations, independent signer trust and explicit
  mismatch/incomplete outcomes. See `docs/custody.md` for preservation and provenance limits.
- Native HTTPS with certificate-verified clients and health probes; remote listeners require
  TLS certificates and bearer authentication, including behind gateways.
- Trusted Ed25519 upload signatures, `chainsaw_result_manifest` for signed downloads,
  atomic verified client downloads with signature receipts, and `chainsaw-mcp-transfer`
  key generation/offline verification. Existing HTTP and unsigned upload clients must migrate;
  see `docs/secure-transfers.md`. Existing published evidence is preserved.
- Self-contained non-root Docker image and Compose deployment with authenticated remote
  MCP, read-only host/NFS/SMB evidence mounts, persistent state and endpoint health checks.
- Resumable remote uploads with declared size/SHA-256 verification, storage quotas and
  atomic publication; a remote client uploads evidence and downloads result artefacts.
- `chainsaw_reproduce` exports recorded native invocations, mapping snapshots and an
  export-time checksum manifest; `chainsaw_plan` validates unexecuted investigation steps
  using the same argument construction as live tools. Both provide downloadable scripts.
- Multi-command histories for current lineage and EVTX overview result handles.
- Real native replay tests and a GitHub container build/remote workflow gate.
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
- Signature verification requires an expected purpose: upload, download and custody
  consumers reject signatures made for another purpose, and `chainsaw-mcp-transfer verify`
  takes `--purpose` (default `download`; custody records need `evidence-manifest` or
  `evidence-validation`).
- The server refuses an `MCP_AUTH_TOKEN_FILE` with any group or other permission bits; the
  health probe warns instead. Docs make container secrets owned by UID 10001 with mode 0400.
- Validation receipts record unreadable directories and files as `unreadable` rows and
  continue (status `incomplete`), report `mismatches_found` and `truncated`, and may grow to
  four times the manifest cap, with headroom so a truncated receipt is still signed.
- Replay scripts set `NO_COLOR=1`, run commands with stdin from `/dev/null`, and name the
  failing binary or input on stderr when a digest check fails.
- An unreadable upload reservation record blocks new uploads with an error naming the
  record, instead of being counted as zero. The quota-exceeded error states that the quota
  counts retained uploaded evidence plus incomplete reservations.
- Remote HTTP always requires a bearer token. `MCP_REQUIRE_AUTH` is deprecated and ignored
  (a warning is logged if set) and is removed from the image and `.env.example`.
- The TLS context uvicorn serves with enforces a TLS 1.2 minimum through
  `ssl_context_factory`; the minimum supported uvicorn is 0.47.
- SECURITY.md and the `chainsaw_reproduce`/`chainsaw_plan` descriptions state that replay
  exports and plans deliberately contain server-absolute paths for provenance.
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
- Reproduction manifests list each replay expression once and hash each input file once,
  but check every distinct expression the commands use, so overlapping evidence roots
  cannot bypass a checksum check through an independently relocated root.
- Upload reservation metadata is written atomically, cleaned up on failure, and stores only
  the signature envelope fields.
- Validation receipt counters (`matched_files`, `metadata_changed`, status counts) describe
  only rows actually written, so a truncated matched-directory row no longer yields
  negative counts.
- Host-side upload/download examples use the `secrets/mcp_token.client` copy.
- Deployment rollback to a plain-HTTP release warns loudly that it is unauthenticated and
  exits non-zero.
- `scripts/container-check.sh` prints container logs on failure, tolerates cleanup errors
  and preserves the exit status; it mounts a UID 10001-owned, mode-0400 token.
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
