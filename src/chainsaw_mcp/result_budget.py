"""Budgets count the actual JSON text returned by MCP, including escaping."""

from __future__ import annotations

import json
from typing import Any

DEFAULT_MAX_BYTES = 65_536
HARD_MAX_BYTES = 131_072


class ResultError(ValueError):
    """Invalid result request or a result that cannot fit the requested budget."""


def budget(value: int) -> int:
    if value < 256:
        raise ResultError("max_bytes must be >= 256 (the response envelope also counts)")
    return min(value, HARD_MAX_BYTES)


def encoded_size(value: Any) -> int:
    return len(json.dumps(value, indent=2, default=str).encode("utf-8"))


def annotate_delivery(
    out: dict[str, Any],
    *,
    truncated: bool = False,
    reason: str | None = None,
    byte_field: str = "returned_bytes",
) -> dict[str, Any]:
    """Mutate/return an envelope with its exact self-inclusive encoded JSON size.

    Call before fitting, and again after any mutation. Chunks use response_bytes
    because their existing returned_bytes measures content bytes for continuation.
    """
    out["truncated"] = truncated
    out["truncation_reason"] = reason if truncated else None
    out[byte_field] = 0
    while (size := encoded_size(out)) != out[byte_field]:
        out[byte_field] = size
    return out


def bounded_dumps(value: Any, max_bytes: int = DEFAULT_MAX_BYTES) -> str:
    text = json.dumps(value, indent=2, default=str)
    if len(text.encode("utf-8")) > budget(max_bytes):
        raise ResultError(
            "Response exceeds max_bytes; narrow fields, filters, sample or top. "
            "No metadata was truncated."
        )
    return text


def oversized(handle: str, offset: int) -> ResultError:
    return ResultError(
        f"Row at offset {offset} in {handle} exceeds max_bytes; retry with narrower fields "
        f"or use chainsaw_result_chunk with row_offset={offset} (original source row index) "
        "to read its JSON text."
    )
