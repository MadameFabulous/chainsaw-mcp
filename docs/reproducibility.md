# Investigation command exports

`chainsaw_reproduce` exports the native commands behind actual investigation result handles.
`chainsaw_plan` constructs commands before an investigation runs, using the same validation
and argument construction as the execution tools. Neither tool executes the exported
investigation. Both return a script handle and a JSONL manifest handle, downloadable
entirely over MCP.

## Document an investigation

```json
{"handles": ["res_<hunt>", "res_<pivot>", "res_<gaps>"], "hash_inputs": true}
```

Call `chainsaw_reproduce` with handles in the desired replay order. Duplicate handles are
removed. Native arguments retain patterns, tau expressions, time windows, rule selections,
mapping choice, parse-error handling, and thread settings. Output paths are rewritten to
a new directory so replay cannot overwrite the original result files.

The manifest contains export time, wrapper version, bundled Chainsaw release, current
binary SHA-256, recorded argument lists, original tool inputs, result counts and hashes,
and an input-file inventory. Evidence and rule hashes are enabled by default; this reads
the selected files, including directory trees on network mounts. `hash_inputs=false`
omits evidence/rule hashing; binary and mapping hashes are always included.

**Input hashes describe export time.** The server did not hash those inputs when the old
command ran. Changes between the investigation and export cannot be reconstructed from
the handle. Preserve acquisition hashes, immutable evidence snapshots, custom rules and
the built image digest alongside the export. This tool documents reproducibility; it
does not assert chain of custody or that every input parsed successfully.

## Plan an investigation

Call `chainsaw_plan` with an ordered set of steps:

```json
{
  "steps": [
    {"tool": "chainsaw_hunt", "arguments": {"paths": ["case42"], "levels": ["high", "critical"]}},
    {"tool": "chainsaw_search", "arguments": {"paths": ["case42"], "tau": ["Event.System.EventID: =4104"]}}
  ],
  "hash_inputs": false
}
```

Inputs must already be mounted or uploaded so the normal path and rule validation can
run. Plans support hunt, search, dump, EVTX overview, gaps, shimcache and SRUM. Plans are
labelled `planned`, with `executed=false`; they never claim observed results. Planning an
EVTX overview emits the native overview command. Add an explicit dump step if you also
want the underlying events. Process lineage needs observed events to choose subsequent
queries and can be exported after it runs.

## Share an export with labelled paths

Set `redact_paths=true` on either export tool to produce a rebased/redacted derivative.
The response and manifest header report `path_mode="redacted"`; the default remains
`"verbatim"` and preserves the recorded provenance. For example:

```json
{"handles": ["res_<hunt>"], "hash_inputs": true, "redact_paths": true}
```

The derivative replaces configured binary, evidence, rule and result-store paths with
labels such as `${CHAINSAW_BIN}`, `${EVIDENCE_1}` and `${RESULTS}`. Commands contain
`rebased_argv` instead of `recorded_argv` or `planned_argv`; generated output and mapping
paths use `${OUTPUT_DIR}`. Original result metadata is unchanged. Supply every input-root
variable listed in the manifest before replay: redacted scripts have no server-root defaults
and fail with a named missing-variable error when a root is absent. Binary and input
checksum validation still applies after relocation.
Absolute aliases in path-valued tool inputs are resolved before labelling, so a symlink
outside an evidence root cannot expose its server path through the derivative metadata.

This mode hides the configured server layout, not evidence names or investigation content.
Relative file names, filters and mapping contents remain sensitive. If a literal filter
argument or embedded mapping contains a configured server path, the export refuses it
instead of silently changing its meaning or retaining the path. Use a sanitised input or
keep the original export private.

## Download and replay

Fetch both handles with `chainsaw_result_chunk`, concatenating `content` in order and
following `next_byte_offset` until null. Small exports can use `chainsaw_result_export`;
check its truncation flag. The supplied remote client downloads all chunks:

```sh
uv run python scripts/remote-client.py https://forensics.example/mcp \
  --token-file /private/mcp_token download res_<script> reproduce.sh \
  --trusted-key /private/server-signing.pem
uv run python scripts/remote-client.py https://forensics.example/mcp \
  --token-file /private/mcp_token download res_<manifest> manifest.jsonl \
  --trusted-key /private/server-signing.pem
```

The client verifies each file against `chainsaw_result_manifest` using the pinned server
key and saves a `.signature.json` receipt. Add `--ca-file` before `download` for private
certificate authorities. See [secure transfers](secure-transfers.md) for setup and offline
verification. The signature authenticates current export bytes, not acquisition provenance.

The script uses POSIX sh with GNU-style `sha256sum` and `base64 -d` (coreutils; stock
macOS lacks `sha256sum` and uses a different `base64` syntax). Run with the same Chainsaw
binary and input files, either in the image or on a forensic workstation. For relocated
files:

```sh
CHAINSAW_BIN=/opt/chainsaw/chainsaw \
EVIDENCE_1=/cases/original-mount \
CHAINSAW_RULES=/opt/chainsaw/rules \
SIGMA_RULES=/opt/chainsaw/sigma \
CUSTOM_RULES=/cases/custom-rules \
OUTPUT_PARENT=/cases/replays sh reproduce.sh
```

Only variables actually used by the script need overriding. `EVIDENCE_2`, etc. refer to
additional roots in the manifest (the container's upload root follows mounted roots).
The script creates a fresh private subdirectory under `OUTPUT_PARENT` (default `/tmp`)
and prints its location. It checks the binary digest and exported hashes before running
any investigation command; a mismatch names the failing binary or input on stderr and
exits with status 1. Commands run with `NO_COLOR=1` and stdin from `/dev/null`, like live
runs, and stdout/stderr are saved for every command. Overlapping inputs (a directory and
files inside it) are inventoried and checked once. Directory inventories check listed
files; they cannot detect new files added to a directory after export. Use immutable
snapshots for directory-based replay. Chainsaw-generated detection IDs and result ordering
can vary, so compare evidence identities and fields rather than expecting byte-identical
JSONL output.

Mapping YAML, including the repaired default mapping, is embedded in the script and
restored under its output directory. Rule trees and evidence are referenced and hashed,
not embedded; preserve them separately. Missing or changed dependencies must be resolved
before replay. Commands and manifests contain investigation paths and filters; protect
them like the evidence. Export handles have the usual seven-day result lifetime.

## Native output and MCP processing

The script produces Chainsaw output. MCP summaries, provider/channel aggregation,
lineage host/GUID filtering, deduplication and traversal limits are Python processing
and are documented in tool inputs and this distinction, rather than claimed as native
Chainsaw behaviour. Current lineage results retain every native search; older lineage
handles with only the last command are rejected and must be rerun. Current EVTX overview
handles retain the overview and coverage dump passes. Older handles can only document
the commands they actually retained. The response and manifest header report `partial=true`
and `partial_handles` entries with `reason="legacy_evtx_command_history_missing"` for these
older EVTX overview handles. Each manifest result row has its own `partial` and
`partial_reason` fields. Other selected handles remain independently labelled. Re-run the
overview to obtain a complete command history; a partial replay cannot reconstruct its
missing coverage pass. `partial=false` only means that no known legacy command-history gap
was found; it does not establish evidence or parse completeness. Plans report `partial=false`
and remain explicitly unexecuted.

Use primary result handles. Diagnostic handles may contain the same native invocation
as a primary result and would replay it again. Jev assessments and arbitrary derived
results without a native Chainsaw invocation cannot be exported as Chainsaw commands.
