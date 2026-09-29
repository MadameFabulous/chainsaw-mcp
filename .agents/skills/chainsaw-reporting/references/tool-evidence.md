# Chainsaw evidence for reports

Use the connected server's tool schema for available parameters. These notes capture
reporting implications of this repository's result contract; reporting can also proceed
from saved exports when the server is unavailable, with verification limits stated.

## Establish scope and counts

| Reporting need | Tool/result | Interpretation |
|---|---|---|
| Case inventory | `chainsaw_list_evidence` | Follow `next_offset` to null for the selected scope; record its filters. Keep the evidence tree stable while paging. |
| Available telemetry | `chainsaw_analyse_evtx` | The inline `per_file` array is a preview. Page `handle` for file details and `coverage_handle` for provider/channel/event-ID coverage. |
| Parse/load problems | `chainsaw_messages`, `diagnostics.handle` | Inspect saved diagnostics when the preview is truncated. Unknown skipped counts remain unknown; successful exit is not parse completeness. |
| Rule matches and source events | `chainsaw_result_summary` | Label `detection_count`, `unique_event_count` and `unidentifiable_count` separately. They are not numbers of confirmed findings or affected assets. |
| Several rules on one event | `chainsaw_result_events` | Each event group retains `matches`. Offsets refer to groups, not stored detection rows. |
| Findings and key fields | `chainsaw_result_fields`, `chainsaw_result_page` | Discover fields, then inspect focused records. Field discovery samples rows; a missing sampled field does not establish absence throughout the evidence. |
| Investigation inputs | `chainsaw_result_list` | Page metadata to identify relevant tools/inputs/handles. Exclude other cases' handles. |

Summary `by_*` lists show top values, not necessarily all values. A hunt summary's time
range describes matching rows; obtain evidence coverage bounds from the source inventory
and analysis. Overlapping hunts cannot be summed into a unique case-wide event count.
Record per-handle counts and scope unless a justified source-level deduplication is done.
Unidentifiable records remain distinct; their count is not an exact unique-event total.

## Construct evidence pointers

For every cited Windows event retain scenario ID, full source path, host, channel,
provider, Event ID, EventRecordID, source timestamp and relevant field values. Preserve
null/missing metadata as such. A rule association also records rule name/ID, level and
tags. Keep event identity separate from its multiple rule associations; neither a file
basename nor EventRecordID is globally unique.

Hunt rows usually wrap `document.path` and `document.data.Event`; aggregate detections
contain `documents[]`. Raw search/dump rows use `Event.*` and may lack a per-record source
path. A multi-file query input does not identify which file produced a particular raw
record: obtain the source from a corresponding hunt record or a scoped single-file query
when authorised; otherwise mark source attribution unresolved. Never guess it.

Record the handle and lookup details (`where`, `fields`, offset/view) as secondary pointers.
A filtered-page offset is not a source-row index, and event-group offsets cannot be used
as detection-row offsets. Use only a known source `row_offset` with `chainsaw_result_chunk`.
The primary durable pointer is the original event identity plus the saved attachment.

Text `where` values match case-insensitive substrings: verify exact host/account/rule values
in the returned evidence. An aggregate detection selected by a host filter retains all its
documents, and its summary may include other hosts. Inspect the individual documents or
event groups before attributing their fields or counts to a particular host.

Use `Event.System.TimeCreated_attributes.SystemTime` when reporting Windows event occurrence
time. Hunt `timestamp` follows rule configuration and may represent a different time field.
For Shimcache/SRUM or other artefacts, state the artefact's time semantics; do not equate a
cache timestamp with proven process execution.

## Preserve attachments and reproducibility

- When documenting evidence integrity or handoffs, use existing signed
  `chainsaw_evidence_manifest` and `chainsaw_evidence_validate` artefacts, or create them
  within the authorised investigation. Preserve each record and its detached signature;
  cite scope, digest, trusted signer, observation times and validation status. Treat
  `incomplete` as unverified and describe mismatches. A content match can include separately
  reported mtime differences. Operator/handoff fields are declarations, and current hashes
  do not prove acquisition provenance or an uninterrupted custody chain. Read the
  [custody workflow](../../../../docs/custody.md) for configuration, limits and preservation.
- Transfer files over certificate-verified HTTPS. For a signed download, obtain
  `chainsaw_result_manifest`, verify it against the independently trusted server public
  key, then verify the complete downloaded bytes against its size/SHA-256. Prefer the
  supplied remote client, which saves a `.signature.json` receipt alongside the file.
  The signed attachment must be the complete stored file fetched with
  `chainsaw_result_chunk` by `byte_offset` (no `row_offset`). Preserve receipts with
  attachments; record missing signatures or unavailable trust as verification limits. A
  checksum alone is not a signature, and format conversion or redaction produces a
  derivative that the original signature does not authenticate.
- CSV/JSONL exports from `chainsaw_result_export` are unsigned derivatives: record their own
  attachment SHA-256 and label them as exports, not as the signed file. For JSONL handles
  follow every `next_offset` until null; for non-JSONL (stored text) handles export
  delegates to chunking, so follow `next_byte_offset` instead. CSV pages repeat their
  headers; keep one header when combining pages. JSONL retains nested evidence that a
  projected CSV may omit. The export tool has no `where` parameter: use filtered pages for
  an excerpt and explicitly label it as selected evidence.
- Use `chainsaw_result_chunk` for complete stored files or a known oversized row, joining
  `content` in order through `next_byte_offset == null` before parsing. Chunks may split
  records. A `chainsaw://results/{handle}` resource read is capped and does not prove a
  complete download. Verify saved attachment size/hash where available and record failures.
- For a reproducibility appendix, use `chainsaw_reproduce(handles=[...], hash_inputs=true)`
  on relevant primary investigation handles when available. Save both `script_handle` and
  `manifest_handle` through complete chunk downloads. Preserve the reported versions,
  arguments, rules/mapping selection, time filters, parser options and export time.
- Hashing reads current evidence and rule trees, potentially on network storage. For large
  collections, use known acquisition hashes or `hash_inputs=false` when appropriate and
  document what was omitted. Export-time hashes are not acquisition-time hashes and cannot
  prove historical input identity or chain of custody. Preserve custody/collection records
  separately; record a newly computed attachment hash as such.
- Reproduction exports native commands. MCP aggregation, deduplication, host filtering
  and lineage limits also affect the report and must be documented. Rules/evidence remain
  external dependencies. If reproduction is unavailable or rejects older/derived handles,
  record known parameters and the limitation; do not invent a replay record.
- `chainsaw_plan` returns unexecuted plans. Keep them as proposed work, never as observed
  results. Jev assessments are advisory and are not native Chainsaw replay results; report
  preparation alone does not require sending evidence to Jev.

Handles normally expire after seven days. Save the relevant results, metadata, diagnostics
and report attachments in the case store before expiry or cleanup. Local saved-file paths
and checksums establish what was delivered; handles alone cannot serve as an archive.
