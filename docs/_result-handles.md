## Result handles

`chainsaw_hunt`, `chainsaw_search`, `chainsaw_dump`, `chainsaw_analyse_shimcache` and
`chainsaw_analyse_srum` store their full output under `CHAINSAW_OUTPUT_DIR/<handle>.<fmt>`
with a sidecar `<handle>.meta.json`. Handles look like `res_0123456789abcdef`, expire after
seven days, and are the only cross-call state the server keeps. This matches the 2026-07-28
guidance that servers stay stateless per request and mint opaque handles for anything large.

### Bounded delivery and continuation

Pages, exports and projected previews default to 65,536 encoded JSON bytes, with a
131,072-byte hard maximum. Budgets include the response JSON envelope and escaping,
not transport-level MCP framing. `returned_bytes`, `truncated`, `truncation_reason`
and `next_offset` describe each page/export. Follow offsets until null. Each CSV
export page repeats its header; JSONL exports preserve complete records.

For a single oversized row, select fewer `fields` or use `chainsaw_result_chunk`.
Its `row_offset` refers to the original source row, even when the error came from a
filtered page. Alternatively omit `row_offset` to stream the stored file. Follow
`next_byte_offset`; UTF-8 characters are never split. Chunk `returned_bytes` counts
content bytes, while `response_bytes` counts the encoded envelope. Individual chunks
are text fragments, not independently valid JSON/CSV records.

`chainsaw_result_events` groups hunt rows by source-qualified event identity and
retains every rule association in `matches`. Its offsets are event-group offsets,
not detection-row offsets. Summaries separate `detection_count`, `unique_event_count`
and `unidentifiable_count`; missing identities are not collapsed together.
`process_guid`, `parent_guid`, `image`, `command` and `user` are additional
projection shorthands (see below). `chainsaw_process_lineage` queries explicitly
selected original evidence files and an exact host, including unmatched
process/network/file events. It reports hop, event and query limits; keep unrelated
sample scenarios separate.

`chainsaw_analyse_evtx` returns handles for per-file details, provider/channel/event-ID
coverage and diagnostics. The inline `per_file` list is a bounded preview, not the
complete file inventory. Gap details are also pageable. Missing metadata is not
parser corruption; parse completeness remains unknown unless observed errors establish
incompleteness. `chainsaw_list_evidence` has offset pagination and returns its filter
provenance. Keep the evidence tree unchanged while collecting inventory pages.

### Filters, aggregate rows and messages

`where` maps field paths or shorthands to values and every entry must match. Operands may
be strings, integers, floats or booleans. Text values match as case-insensitive
substrings; numbers and booleans match exactly, so `{"event_id": "4624"}` and
`{"event_id": 4624}` both select event 4624 and nothing else, and `true` is distinct
from `1`. Chainsaw aggregate rules (`aggregate:` with a count) emit detections that carry
a `documents` list instead of one `document`. For such a row every `document.*` predicate
must match the same document, so `{"computer": "DC01", "event_id": 4624}` describes one
source event rather than two unrelated ones. Filtering selects whole detection rows: a
projected field yields one value per document, summaries count every document of each
selected row (a host filter does not restrict a selected aggregate's summary to that
host), and `chainsaw_result_events` expands the row into separate events.

Hunts and searches return `chainsaw_messages`, a bounded preview of Chainsaw's own
warnings about rules or evidence files it could not load, with server paths replaced by
`<placeholders>` and evidence-root names. The complete stream is stored under
`diagnostics.handle` (tool `chainsaw_hunt_diagnostics` or `chainsaw_search_diagnostics`,
one `message` row per line); `diagnostics.message_count`, `warning_count` and
`messages_truncated` say whether the preview is complete. `chainsaw_result_list` pages
with `offset`/`limit`/`next_offset` like every other listing, fitting complete metadata
entries to `max_bytes`. Its delivery metadata includes `returned_bytes`, `truncated`
and `truncation_reason`. An individual entry that cannot fit raises an error naming its
handle and offset; increase the budget or explicitly skip that entry to continue listing.

### Shorthand field names

Hunt rows (detections):

| Shorthand | Path |
|---|---|
| rule | name |
| level | level |
| status | status |
| source | source |
| group | group |
| timestamp | timestamp |
| path | document.path |
| computer | document.data.Event.System.Computer |
| channel | document.data.Event.System.Channel |
| event_id | document.data.Event.System.EventID |
| provider | document.data.Event.System.Provider_attributes.Name |
| record_id | document.data.Event.System.EventRecordID |
| tags | tags |
| process_guid | document.data.Event.EventData.ProcessGuid |
| parent_guid | document.data.Event.EventData.ParentProcessGuid |
| image | document.data.Event.EventData.Image |
| command | document.data.Event.EventData.CommandLine |
| user | document.data.Event.EventData.User |

Any `Event.…` path given against a hunt result is automatically prefixed with
`document.data.`. Search and dump rows are raw documents, so use `Event.System.EventID`,
`Event.EventData.TargetUserName`, and so on directly. For non-hunt handles `timestamp`,
`computer`, `channel`, `event_id`, `provider`, `record_id` and the five process
shorthands resolve to the same `Event.…` paths without the prefix; `timestamp` there
means `Event.System.TimeCreated_attributes.SystemTime`. `chainsaw_result_fields`
returns the shorthand table that applies to a handle.
