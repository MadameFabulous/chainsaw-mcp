# Tool reference

Generated from the live server schema by `scripts/gen-tool-docs.py`. All tools return a JSON text block; errors come back as `isError` results with a readable message.

| Tool | Read-only | Destructive | Purpose |
|---|---|---|---|
| `chainsaw_analyse_evtx` | no | no | Summarise EVTX channel, provider and event-ID coverage, including missing metadata. |
| `chainsaw_analyse_gaps` | no | no | Detect chronological or EventRecordID discontinuities for investigation. |
| `chainsaw_analyse_shimcache` | no | no | Build an execution timeline from the shimcache with optional Amcache enrichment. |
| `chainsaw_analyse_srum` | no | no | Analyse the System Resource Usage Monitor (SRUM) database. |
| `chainsaw_delete_rule` | no | yes | Delete a custom rule. Bundled Chainsaw and Sigma rules cannot be deleted. |
| `chainsaw_dump` | no | no | Convert every record in the evidence to JSON under a result handle. |
| `chainsaw_get_mapping` | yes | no | Describe a Sigma-to-event-log mapping file: groups, filters, field translations. |
| `chainsaw_get_rule` | yes | no | Read one rule's YAML and parsed summary, or list a rule directory. |
| `chainsaw_hunt` | no | no | Hunt evidence with Sigma and Chainsaw detection rules. |
| `chainsaw_jev_triage` | no | no | Send selected result rows to TypeSafe Jev for advisory classification and priority. |
| `chainsaw_lint_rules` | yes | no | Validate rules with `chainsaw lint` and report which files fail to load and why. |
| `chainsaw_list_evidence` | yes | no | List artefact files below an evidence path with sizes and types. |
| `chainsaw_process_lineage` | no | no | Pivot process GUIDs in explicitly scoped original evidence, including unmatched events. |
| `chainsaw_result_chunk` | yes | no | Read UTF-8 text chunks of a file or oversized JSON row. Resume next_byte_offset. |
| `chainsaw_result_delete` | no | yes | Delete a stored result and its metadata. Evidence files are never touched. |
| `chainsaw_result_events` | yes | no | Page unique source-qualified events, retaining every associated rule match. |
| `chainsaw_result_export` | yes | no | Render a stored result as CSV or JSONL text for reports or other tools. |
| `chainsaw_result_fields` | yes | no | Discover the field paths present in a result so you can project or group on them. |
| `chainsaw_result_list` | yes | no | List stored result handles, newest first, with tool, inputs and row counts. |
| `chainsaw_result_page` | yes | no | Read a page of rows from a stored result, optionally projected and filtered. |
| `chainsaw_result_summary` | yes | no | Aggregate a stored result without paging through it. |
| `chainsaw_rule_stats` | yes | no | Count installed Chainsaw, Sigma and custom rules by level and status, plus mappings. |
| `chainsaw_save_rule` | no | yes | Save an analyst-authored Chainsaw rule into the custom rules directory. |
| `chainsaw_search` | no | no | Search evidence for keywords, regular expressions, or tau field expressions. |
| `chainsaw_search_rules` | yes | no | Find detection rules by keyword, ATT&CK tag, level, status or logsource. |
| `chainsaw_status` | yes | no | Report server configuration, chainsaw version, rule counts and evidence roots. |

## `chainsaw_analyse_evtx`

Summarise EVTX channel, provider and event-ID coverage, including missing metadata.

        Runs native analysis and a streamed dump pass. The inline per_file list is a
        bounded preview; page handle for full files, coverage_handle for identity counts,
        and diagnostics.handle for all runner messages. Missing Channel in ETW is not
        evidence of corruption, and successful exit does not establish complete parsing.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `paths` | string[] | required | EVTX files or directories under an allowed root. |
| `skip_errors` | boolean | true | Continue past unreadable files. |

## `chainsaw_analyse_gaps`

Detect chronological or EventRecordID discontinuities for investigation.

        Curated or filtered samples naturally contain gaps; these are not proof of
        deletion. Correlate with acquisition history and Security 1102 / System 104.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `paths` | string[] | required | EVTX files or directories under an allowed root. |
| `min_time_gap_minutes` | integer | 30 | Flag time gaps at least this long. (maximum=10080, minimum=1) |
| `record_id_gaps` | boolean | true | Detect EventRecordID gaps. |
| `time_gaps` | boolean | true | Detect chronological gaps. |
| `from_time` | string or null | null | Analyse from YYYY-MM-DDTHH:MM:SS. |
| `to_time` | string or null | null | Analyse up to YYYY-MM-DDTHH:MM:SS. |
| `timezone` | string or null | null | IANA timezone for output. |
| `skip_errors` | boolean | true | Continue past unreadable files. |
| `limit` | integer | 200 | Maximum gaps to return. (maximum=2000, minimum=1) |

## `chainsaw_analyse_shimcache`

Build an execution timeline from the shimcache with optional Amcache enrichment.

        Wraps `chainsaw analyse shimcache`. Output is CSV stored under a result handle;
        the preview holds the first rows. Use chainsaw_result_export for the full file.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `system_hive` | string | required | SYSTEM registry hive under an allowed evidence root. |
| `amcache_hive` | string or null | null | Optional Amcache.hve for timeline enrichment. |
| `patterns` | array[] or null | null | Regexes identifying entries whose shimcache timestamp equals their insertion time (e.g. known-good installer paths). Default: bundled list if present, otherwise none. |
| `timestamp_pairs` | boolean | false | Enable near-timestamp pair detection with Amcache. |
| `preview` | integer | 50 | Rows to include inline. (maximum=200, minimum=0) |

## `chainsaw_analyse_srum`

Analyse the System Resource Usage Monitor (SRUM) database.

        Wraps `chainsaw analyse srum`. Output is stored under a result handle; use
        chainsaw_result_export for the complete text.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `srum_db` | string | required | SRUDB.dat under an allowed evidence root. |
| `software_hive` | string | required | SOFTWARE registry hive under an allowed evidence root. |
| `stats_only` | boolean | false | Only report table statistics, not the full extraction. |
| `preview_bytes` | integer | 12000 | Bytes of output to include inline. (maximum=12000, minimum=0) |

## `chainsaw_delete_rule`

Delete a custom rule. Bundled Chainsaw and Sigma rules cannot be deleted.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `name` | string | required | Custom rule file name. |

## `chainsaw_dump`

Convert every record in the evidence to JSON under a result handle.

        Wraps `chainsaw dump`. Use it when a hunt or search has narrowed the scope to one
        or two files and you need the complete record stream; page through the handle.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `paths` | string[] | required | Evidence files or directories under an allowed root. |
| `extension` | string or null | null | Only dump this extension. |
| `load_unknown` | boolean | false | Try to parse unidentified files. |
| `skip_errors` | boolean | true | Continue past unreadable files. |
| `preview` | integer | 10 | Records to include inline. (maximum=100, minimum=0) |
| `fields` | array[] or null | null | Dotted paths or shorthand names to project in the inline preview; see chainsaw_result_fields. Omit for the standard shorthand columns. |

## `chainsaw_get_mapping`

Describe a Sigma-to-event-log mapping file: groups, filters, field translations.

        Mappings decide which Sigma logsources apply to which Windows events. Read this
        when a Sigma rule you expect is not firing.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `name` | string or null | null | Mapping file name. Omit for the effective hunt default. |
| `include_yaml` | boolean | false | Include the full YAML text. |

## `chainsaw_get_rule`

Read one rule's YAML and parsed summary, or list a rule directory.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `kind` | string | required | chainsaw, sigma or custom. |
| `path` | string | required | Rule path relative to that kind's root, e.g. rules/windows/process_creation/proc_creation_win_lsass_dump.yml or evtx/credential_access. Directories return their children. |

## `chainsaw_hunt`

Hunt evidence with Sigma and Chainsaw detection rules.

        Runs `chainsaw hunt` over the given paths, stores every detection as JSONL under a
        server-minted result handle, and returns aggregate counts (by rule, level, host,
        channel, event ID, hour) with a small preview. Prefer this over reading raw events.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `paths` | string[] | required | Evidence files or directories, relative to an allowed evidence root or absolute inside one. Directories are searched recursively. |
| `sigma` | boolean | true | Apply the bundled Sigma rules through the mapping file. |
| `sigma_collections` | array[] or null | null | Sigma collections or sub-trees to load, e.g. ['rules'], ['rules', 'rules-threat-hunting'] or ['rules/windows/process_creation']. Default: ['rules']. Use chainsaw_rule_stats to see what is installed. |
| `mapping` | string or null | null | Mapping file name inside the mappings directory. Default sigma-event-logs-all.yml; sigma-event-logs-legacy.yml for pre-Sysmon logs. |
| `chainsaw_rules` | boolean | true | Apply the bundled Chainsaw rules (rules/ directory). |
| `extra_rules` | array[] or null | null | Additional Chainsaw-format rule directories: 'custom' for analyst-saved rules, or 'chainsaw/<subdir>' such as 'chainsaw/evtx/lateral_movement'. |
| `levels` | array[] or null | null | Restrict rules to these levels: critical, high, medium, low, info. |
| `statuses` | array[] or null | null | Restrict loaded rules to these statuses: stable, experimental. |
| `kinds` | array[] or null | null | Restrict loaded rules to these kinds: chainsaw, sigma. |
| `from_time` | string or null | null | Drop documents older than this, format YYYY-MM-DDTHH:MM:SS. |
| `to_time` | string or null | null | Drop documents newer than this, format YYYY-MM-DDTHH:MM:SS. |
| `timezone` | string or null | null | Render timestamps in this IANA timezone (default UTC). |
| `extension` | string or null | null | Only load files with this extension, e.g. evtx. |
| `load_unknown` | boolean | false | Let chainsaw try to parse files it cannot identify. |
| `skip_errors` | boolean | true | Continue past unreadable files instead of failing the hunt. |
| `preview` | integer | 20 | Detections to include inline (0-100). (maximum=100, minimum=0) |
| `fields` | array[] or null | null | Dotted paths or shorthand names to project in the inline preview; see chainsaw_result_fields. Omit for the standard shorthand columns. |

## `chainsaw_jev_triage`

Send selected result rows to TypeSafe Jev for advisory classification and priority.

        EXTERNAL DATA TRANSFER: sends the selected evidence fields to api.typesafe.ai.
        Requires CHAINSAW_JEV_ENABLED=true and credentials. One bounded API request per
        call, no retries. Returns source row indexes, probabilities and confidence;
        invalid answers fail only their source row, with both scores null and a named
        error; invalid response containers reject the batch. Each assessment lists all
        uncertain_reasons: insufficient_context, low_classification_confidence,
        low_priority_confidence or validation_failed. uncertain is true when reasons exist.
        Scores are model judgments, not confirmed findings.
        Review the original evidence before acting. Evidence and stored results are unchanged.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `handle` | string | required | Source JSONL result handle to assess. |
| `offset` | integer | 0 | First source row index. (minimum=0) |
| `limit` | integer | 5 | Maximum rows sent to Jev. (maximum=10, minimum=1) |
| `fields` | array[] or null | null | Dotted paths or result-field shorthand to send. Omit to send whole selected rows, including their evidence file path. Use chainsaw_result_page with these fields to preview exactly what would be disclosed. |
| `min_confidence` | number | 0.8 | Below this confidence, flag uncertainty. (maximum=1, minimum=0) |

## `chainsaw_lint_rules`

Validate rules with `chainsaw lint` and report which files fail to load and why.

        Run it after chainsaw_save_rule, or on a Sigma sub-tree to see unsupported modifiers.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `kind` | string | "custom" | chainsaw, sigma or custom. |
| `path` | string | "." | File or directory relative to the kind's root; '.' for all. |
| `tau` | boolean | false | Show the compiled tau logic per rule. |

## `chainsaw_list_evidence`

List artefact files below an evidence path with sizes and types.

        Use it to scope a hunt: pick directories or individual .evtx files instead of
        hunting an entire mount. Follow next_offset until null for a complete inventory;
        the evidence tree must remain unchanged between pages.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `path` | string | "." | Directory or file under an allowed evidence root; '.' for the first root. Use chainsaw_status to see the roots. |
| `pattern` | string | "" | Case-insensitive substring filter on the full path. |
| `limit` | integer | 200 | Maximum files to return. (maximum=1000, minimum=1) |
| `offset` | integer | 0 | Next offset from the preceding page. (minimum=0) |

## `chainsaw_process_lineage`

Pivot process GUIDs in explicitly scoped original evidence, including unmatched events.

        Supply files from one investigation (not a shared evidence root) and an exact host.
        Each hop queries process/parent GUIDs; output is capped and reports incomplete traversal.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `paths` | string[] | required | Explicit evidence files from one investigation. Directories and shared roots are rejected so unrelated scenarios stay separate. |
| `process_guid` | string | required | Starting Sysmon ProcessGuid, canonical GUID with or without braces. |
| `computer` | string | required | Computer value of the host, compared case-insensitively; other hosts are ignored. |
| `max_hops` | integer | 2 | Parent/child hops to traverse (0-5). |
| `max_events` | integer | 500 | Total events to collect across all hops (1-5000). |
| `max_queries` | integer | 64 | Searches allowed before traversal stops as incomplete (1-256). |
| `preview` | integer | 20 | Events to include inline (0-100). |

## `chainsaw_result_chunk`

Read UTF-8 text chunks of a file or oversized JSON row. Resume next_byte_offset.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `handle` | string | required | Result handle returned by a hunt, search, dump or analysis tool. |
| `row_offset` | integer or null | null | Source row index of one oversized JSON row to stream (the row_offset an oversized error reports). Omit to stream the stored file itself. |
| `byte_offset` | integer | 0 | Byte position to resume from; pass next_byte_offset from the previous chunk. |
| `max_bytes` | integer | 65536 | Content byte budget per chunk (256-131072); UTF-8 characters are never split. |

## `chainsaw_result_delete`

Delete a stored result and its metadata. Evidence files are never touched.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `handle` | string | required | Result handle returned by a hunt, search, dump or analysis tool. |

## `chainsaw_result_events`

Page unique source-qualified events, retaining every associated rule match.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `handle` | string | required | Result handle returned by a hunt, search, dump or analysis tool. |
| `offset` | integer | 0 | First event-group offset to return (not a detection-row offset). |
| `limit` | integer | 50 | Event groups to return. |
| `fields` | array[] or null | null | Dotted paths or shorthand names to project inside each group's event. Omit for whole events. |
| `max_bytes` | integer | 65536 | Encoded response byte budget (256-131072). |

## `chainsaw_result_export`

Render a stored result as CSV or JSONL text for reports or other tools.

        Large results are capped by rows and encoded response bytes; resume next_offset.
        CSV pages repeat their header. For stored text files resume next_byte_offset;
        those UTF-8 chunks may split records and must be concatenated before parsing.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `handle` | string | required | Result handle returned by a hunt, search, dump or analysis tool. |
| `format` | string | "csv" | csv, jsonl, or text (an alias of csv). CSV flattens the standard columns of hunts and searches; analysis handles use their sampled top-level keys. |
| `fields` | array[] or null | null | Columns for CSV (dotted paths or shorthand). Default overview set. |
| `max_rows` | integer | 5000 | Row cap for the export. (maximum=20000, minimum=1) |
| `offset` | integer | 0 |  (minimum=0) |
| `byte_offset` | integer | 0 |  (minimum=0) |
| `max_bytes` | integer | 65536 | Encoded response byte budget. (maximum=131072, minimum=256) |

## `chainsaw_result_fields`

Discover the field paths present in a result so you can project or group on them.

        Returns each dotted path with how many sampled rows carry it and an example value.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `handle` | string | required | Result handle returned by a hunt, search, dump or analysis tool. |
| `sample` | integer | 200 | Rows to sample. (maximum=2000, minimum=1) |

## `chainsaw_result_list`

List stored result handles, newest first, with tool, inputs and row counts.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `offset` | integer | 0 | First entry to return. (minimum=0) |
| `limit` | integer | 50 | Entries per page. (maximum=200, minimum=1) |
| `max_bytes` | integer | 65536 | Encoded JSON byte budget, including metadata. (maximum=131072, minimum=256) |

## `chainsaw_result_page`

Read a page of rows from a stored result, optionally projected and filtered.

        Rows are chainsaw detections (hunt) or raw documents (search, dump). Iterate with
        next_offset until it is null.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `handle` | string | required | Result handle returned by a hunt, search, dump or analysis tool. |
| `offset` | integer | 0 | First row index to return. (minimum=0) |
| `limit` | integer | 50 | Rows to return. (maximum=500, minimum=1) |
| `fields` | array[] or null | null | Dotted paths to project, e.g. ['name', 'level', 'document.data.Event.EventData.CommandLine']. Shorthand names from chainsaw_result_fields also work. Omit for whole rows. |
| `where` | object or null | null | Filters, field path or shorthand -> value; all must match. Text matches as a case-insensitive substring, numbers and booleans exactly (event_id: '4624' matches 4624 only). An aggregate hunt row matches when any of its documents matches. Example: {'level': 'critical', 'computer': 'DC01'}. |
| `max_bytes` | integer | 65536 | Encoded response byte budget. (maximum=131072, minimum=256) |

## `chainsaw_result_summary`

Aggregate a stored result without paging through it.

        Use the default overview to understand a hunt, then group by specific event fields
        (users, processes, source IPs, logon IDs) to build pivots for chainsaw_search.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `handle` | string | required | Result handle returned by a hunt, search, dump or analysis tool. |
| `group_by` | array[] or null | null | Field paths or shorthand names to count by, e.g. ['rule', 'computer'] or ['document.data.Event.EventData.TargetUserName']. Omit for the standard overview (rules, levels, hosts, channels, event IDs, hours). |
| `top` | integer | 25 | Values per grouping. (maximum=200, minimum=1) |
| `where` | object or null | null | Filters applied before counting; same matching rules as chainsaw_result_page's where. |

## `chainsaw_rule_stats`

Count installed Chainsaw, Sigma and custom rules by level and status, plus mappings.

        Also lists the Sigma collections present; pass those names to chainsaw_hunt's
        sigma_collections when you want threat-hunting or emerging-threat rules included.

No parameters.

## `chainsaw_save_rule`

Save an analyst-authored Chainsaw rule into the custom rules directory.

        Saved rules are hunted with extra_rules=['custom']. The file is linted before the
        result is returned; a failing lint still leaves the file in place so it can be fixed
        with another save using overwrite=true.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `name` | string | required | File name without directories, e.g. suspicious_rdp_from_workstation |
| `yaml_text` | string | required | Complete Chainsaw rule YAML with title, group, description, authors, kind, level, status, timestamp, fields and filter. See the chainsaw://docs/rule-format resource. |
| `overwrite` | boolean | false | Replace an existing custom rule. |
| `lint` | boolean | true | Run chainsaw lint on the saved file. |

## `chainsaw_search`

Search evidence for keywords, regular expressions, or tau field expressions.

        Runs `chainsaw search`; each matching document is stored under a result handle and
        summarised by host, channel, event ID and hour. Use tau expressions to pivot on a
        specific field (for example a LogonId, process GUID, or user) after a hunt.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `paths` | string[] | required | Evidence files or directories under an allowed root. |
| `patterns` | array[] or null | null | String or regular-expression patterns matched against the whole document. All must match unless match_any is true. |
| `tau` | array[] or null | null | Tau field expressions such as 'Event.System.EventID: =4104' or 'Event.EventData.Image: i*mimikatz*'. Combined with AND unless match_any. |
| `ignore_case` | boolean | true | Case-insensitive pattern matching. |
| `match_any` | boolean | false | Match a document when any one of the patterns matches (and, separately, any one of the tau expressions) instead of requiring all of them. Patterns and tau expressions are always combined with AND. |
| `from_time` | string or null | null | Drop documents older than YYYY-MM-DDTHH:MM:SS. |
| `to_time` | string or null | null | Drop documents newer than YYYY-MM-DDTHH:MM:SS. |
| `timestamp_field` | string or null | null | Field holding the timestamp when from_time/to_time are set. Default for EVTX: Event.System.TimeCreated_attributes.SystemTime. |
| `timezone` | string or null | null | IANA timezone for output. |
| `extension` | string or null | null | Only load this extension. |
| `load_unknown` | boolean | false | Try to parse unidentified files. |
| `skip_errors` | boolean | true | Continue past unreadable files. |
| `preview` | integer | 20 | Events to include inline. (maximum=100, minimum=0) |
| `fields` | array[] or null | null | Dotted paths or shorthand names to project in the inline preview; see chainsaw_result_fields. Omit for the standard shorthand columns. |

## `chainsaw_search_rules`

Find detection rules by keyword, ATT&CK tag, level, status or logsource.

        Use it to explain a detection name from a hunt, to check coverage for a technique,
        or to pick a sub-tree for a focused hunt. Returns rule URIs readable as resources.

| Parameter | Type | Default | Description |
|---|---|---|---|
| `query` | string | "" | Words matched against title, description, tags, path, id. |
| `kinds` | array[] or null | null | Restrict to rule kinds: chainsaw, sigma, custom. Default all. |
| `level` | string or null | null | critical, high, medium, low or info. |
| `status` | string or null | null | stable, experimental, test or deprecated. |
| `tag` | string or null | null | Substring of an ATT&CK tag, e.g. t1003 or credential |
| `logsource` | string or null | null | Substring of Sigma logsource values, e.g. process_creation. |
| `path_prefix` | string or null | null | Rule path prefix, e.g. rules/windows/powershell or evtx/persistence |
| `limit` | integer | 50 | Rules per page. (maximum=200, minimum=1) |
| `offset` | integer | 0 | Page start. (minimum=0) |

## `chainsaw_status`

Report server configuration, chainsaw version, rule counts and evidence roots.

        Call this first to learn which evidence roots and rule sets are available, and
        whether the chainsaw binary is installed.

No parameters.

## Resources

- `chainsaw://docs/rule-format`: How to write a Chainsaw detection rule (tau syntax, fields, kinds).
- `chainsaw://config`: Effective server configuration (paths, limits, Jev settings).
- `chainsaw://rules/{kind}/{+path}`: Detection rule YAML by kind (chainsaw|sigma|custom) and relative path; directory paths list their children as JSON.
- `chainsaw://mappings/{name}`: Sigma-to-event-log mapping YAML (e.g. sigma-event-logs-all.yml).
- `chainsaw://results/{handle}`: Raw stored result (JSONL/CSV/text) for a handle from a hunt or analysis. Capped at 2 MB; chainsaw_result_export reports bytes and truncation.

## Prompts

- `triage_evtx`(`path`, `focus` (optional)): Structured first-pass triage of Windows event logs with Chainsaw.
- `pivot_on_indicator`(`indicator`, `path`): Investigate one indicator (user, host, IP, process, LogonId) across evidence.
- `author_rule`(`behaviour`, `sample_handle` (optional)): Write, save and validate a Chainsaw detection rule from an observed pattern.

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
