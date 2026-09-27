# Jev result triage

`chainsaw_jev_triage` adds an explicit remote assessment step to the existing local
Chainsaw workflow. [Jev](https://docs.typesafe.ai/introduction) evaluates typed questions
against a state. This integration uses Choice for classification and Score for urgency;
both return probabilities and confidence through the
[System One API](https://docs.typesafe.ai/api).

Retain both the code revision and resolved model when comparing assessments.

## Configuration

Export these variables for stdio, or set them in the service's `.env` (loaded by systemd):

```dotenv
CHAINSAW_JEV_ENABLED=true
CHAINSAW_JEV_BWS_SECRET_ID=<UUID of the jev-api-key secret>
BWS_BINARY=/absolute/path/to/bws
BWS_TOKEN_FILE=/absolute/path/to/private/bws-token
JEV_MODEL=jev-latest
CHAINSAW_JEV_TIMEOUT=30
```

The token file must be a private regular file (0600) readable by the server user.
`BWS_ACCESS_TOKEN` can replace the token file. The machine account must have read access
to the selected secret. The CLI fetches that secret by ID at call time; neither its key
nor the BWS token is written by the server. BWS errors never expose CLI output.

Alternatively, inject `TYPESAFE_API_KEY` in the server environment; it takes precedence
over BWS. Do not put API keys in tool arguments. A `.env` is not automatically loaded
for CLI/stdio invocations; export variables in the launcher environment. The existing
systemd unit already reads its checkout's `.env` and preserves it across deployments.
Use paths for the deployment host and service user, not paths copied from the dev host.

`chainsaw_status`, `chainsaw://config` and `chainsaw-mcp --check` report enablement, model,
endpoint, timeout, and the credential source (`env` for `TYPESAFE_API_KEY`, `bws` for a
secret ID, `null` when neither is set). They do not fetch secrets or validate API access.
The endpoint is fixed to `https://api.typesafe.ai/v1/systemone` and redirects are disabled.

## Workflow

1. Hunt or search evidence to obtain a result handle.
2. Inspect `chainsaw_result_fields` and preview a small page. Select only useful fields.
3. Call `chainsaw_jev_triage` with the same handle, offset, limit and field projection.
4. Review the original source rows for highly ranked or uncertain assessments and pivot
   with local tools to corroborate them.

Example tool arguments (replace the illustrative handle with a real returned handle):

```json
{
  "handle": "res_0123456789abcdef",
  "offset": 0,
  "limit": 5,
  "fields": [
    "rule",
    "level",
    "event_id",
    "document.data.Event.EventData.CommandLine",
    "document.data.Event.EventData.ParentImage"
  ],
  "min_confidence": 0.8
}
```

The tool sends selected values to TypeSafe. It performs no automatic redaction; omitting
`fields` sends whole selected rows, including the evidence file path stored in
`document.path` (server-side path). Aggregate hunt rows carry `documents`, and a
projected field yields one value per document. Field selection trades detail for reduced
disclosure.
Treat returned classifications and scores as model judgments, not verified incident facts.
`likely_benign` must not automatically suppress or close a detection.

Each row gets two independent questions scoped to that row, evaluated in one request:

| Output | Meaning |
|---|---|
| `classification.choice` | `suspicious`, `likely_benign`, or `insufficient_context` |
| `priority.score` | Continuous 0–3 urgency score; returned `priority_levels` defines the rubric |
| `confidence` | Jev's summary of how concentrated each answer's probability distribution is; not the probability that the answer is correct |
| `uncertain` | `true` exactly when this assessment's `uncertain_reasons` is non-empty |
| `uncertain_reasons` | All applicable reasons listed below; `[]` when none apply |
| `source_row_index` | Zero-based row in the original handle; use it as `chainsaw_result_page.offset` |
| `model`, `usage` | Model version the API resolved and its non-negative integer `input_tokens`/`output_tokens` counts; other usage metadata is omitted |
| `request_sent` | `false` when the page was empty and no API call was made |
| `request_bytes` | Exact encoded request size, including questions; zero for an empty page |
| `failed` | Number of selected rows whose answers failed validation (zero on an empty page) |
| `error`, `question` | On failed rows, the check name and generated question key; both `classification` and `priority` are null |

The API returns probabilities and scores rounded to two decimals; the server accepts a
score within 0.05 of the probability-weighted mean and a probability sum within 0.05 of 1.
The score answer's `legend` text is not returned; `priority_levels` is the rubric that was
asked for. `truncated` and `truncation_reason` describe the selected page (`limit` when
more source rows remain), not the request body.

Successful assessments are sorted by descending priority **within the selected page**;
failed rows follow in source order. This does not rank the entire stored result.
`returned` includes failed rows; `next_offset` advances past every selected row in original
source order. Use a failed row's `source_row_index` as the offset for an explicit retry.
Pages without rows make no API request. No records are removed, rewritten or hidden. The
response carries the resolved model returned by the API; `jev-latest` may change over
time, so set `JEV_MODEL` to a supported pinned version when reproducibility matters.

## Uncertainty and threshold selection

`min_confidence` defaults to **0.8**. Successful assessments list every applicable reason,
in the order below. Confidence equal to the threshold is accepted: the comparison is
strictly `<`. Failed rows carry only `validation_failed`, since neither answer is accepted.

| Reason | Meaning |
|---|---|
| `insufficient_context` | The selected classification is `insufficient_context`, regardless of confidence or threshold. |
| `low_classification_confidence` | Classification confidence is below `min_confidence`. |
| `low_priority_confidence` | Priority confidence is below `min_confidence`. |
| `validation_failed` | Missing or invalid answers prevented a usable assessment; inspect `error` and `question`. |

Even at `min_confidence=0`, insufficient context and validation failures remain uncertain.
These reasons distinguish missing evidence, ambiguity in each answer and invalid output;
they are computed by the server, not explanations generated by Jev.

TypeSafe derives [confidence](https://docs.typesafe.ai/confidence) from the probability
distribution: a split between neighbouring urgency levels can yield a useful score with
low confidence. A confident `insufficient_context` answer still calls for more evidence.
Inspect both distributions and the reasons before changing a threshold.

To choose a threshold for your workflow:

1. Preview the exact projected fields with `chainsaw_result_page`. Confirm that the
   event-specific activity is populated, using `chainsaw_result_fields` and the original
   row to investigate missing fields. Rule metadata alone may omit decisive evidence.
2. Compare against reviewed examples of benign and suspicious activity. Hold rows,
   projection, model version and prompt revision fixed when assessing a threshold; vary
   one factor at a time for other comparisons.
3. Choose based on missed findings, incorrect escalations and the action being gated.
   Do not lower the threshold merely to obtain a smaller flagged percentage. Callers can
   use the two confidence values separately when their review policies differ.

No threshold automatically validates findings or authorises suppression.

## Bounds and failure behavior

- Default 5 rows, maximum 10; at most 40 projected field paths of up to 200 characters
  each. This limits path names, not field values: command lines and scripts are sent whole.
- JSONL handles only; CSV/text analyses are rejected.
- Maximum encoded request 64,000 bytes, including questions; oversized requests fail
  without truncating evidence or resolving credentials. The error reports `request_bytes`,
  `max_request_bytes` and `suggested_limit`, the largest prefix of the selected rows that
  fits. Retry at the same offset with that limit; zero means even the first row needs
  narrower fields. Question text consumes roughly 1.3 KB for one row or 12.5 KB for ten
  rows, before record values. Command-line-heavy pages may need only 2–5 rows per request.
- Maximum decoded response 256,000 bytes; HTTP operations use `CHAINSAW_JEV_TIMEOUT`.
  BWS uses that timeout separately. HTTP timeout applies to network operations, not a
  total wall-clock deadline.
- Returned JSON also enforces the 65,536-byte inline budget. Provider model identifiers
  must contain 1–200 characters; oversized or invalid identifiers fail validation.
- No automatic retries or caching. Repeated calls incur new API usage. This tool is
  marked open-world and non-idempotent in MCP annotations.
- Invalid, missing, out-of-range or non-finite answers fail their source row as a unit:
  both answers are null, `uncertain` is true, `uncertain_reasons` is `["validation_failed"]`,
  and `error`/`question` identify the check.
  Other valid rows are retained. This includes missing expected question keys.
- Invalid top-level objects, model identifiers or `answers` containers, and unknown
  question keys, reject the batch. Validation errors/logs contain only check names and
  generated question keys, never evidence, criteria text or provider response bodies.
- Provider HTTP errors expose only the status code; connection and timeout failures
  expose sanitised messages, never response bodies, credentials or submitted evidence.
- No retry is automatic, including when every selected row fails validation. Tolerances
  for probability sums and weighted scores are unchanged.
- Jev is never invoked automatically by hunts, prompts, status checks or startup.

Normal tests use a mock HTTP transport. A live check should use synthetic records,
load the credential in memory from BWS, and avoid printing credentials or request bodies.
