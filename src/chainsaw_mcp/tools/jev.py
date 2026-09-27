"""Explicit, bounded remote assessments of stored forensic results."""

from __future__ import annotations

from typing import Annotated

from pydantic import Field

from .. import jev
from ..result_budget import ResultError
from ..result_budget import bounded_dumps as dumps
from ._common import ToolContext


class JevTools:
    def __init__(self, ctx: ToolContext) -> None:
        self.ctx = ctx

    def chainsaw_jev_triage(
        self,
        handle: Annotated[str, Field(description="Source JSONL result handle to assess.")],
        offset: Annotated[int, Field(ge=0, description="First source row index.")] = 0,
        limit: Annotated[int, Field(ge=1, le=10, description="Maximum rows sent to Jev.")] = 5,
        fields: Annotated[
            list[Annotated[str, Field(min_length=1, max_length=200)]] | None,
            Field(
                min_length=1,
                max_length=40,
                description=(
                    "Dotted paths or result-field shorthand to send. Omit to send whole selected "
                    "rows, including their evidence file path. Use chainsaw_result_page with "
                    "these fields to preview exactly what would be disclosed."
                ),
            ),
        ] = None,
        min_confidence: Annotated[
            float, Field(ge=0, le=1, description="Below this confidence, flag uncertainty.")
        ] = 0.8,
    ) -> str:
        """Send selected result rows to TypeSafe Jev for advisory classification and priority.

        EXTERNAL DATA TRANSFER: sends the selected evidence fields to api.typesafe.ai.
        Requires CHAINSAW_JEV_ENABLED=true and credentials. One bounded API request per
        call, no retries. Returns source row indexes, probabilities and confidence;
        invalid answers fail only their source row, with both scores null and a named
        error; invalid response containers reject the batch. Each assessment lists all
        uncertain_reasons: insufficient_context, low_classification_confidence,
        low_priority_confidence or validation_failed. uncertain is true when reasons exist.
        Scores are model judgments, not confirmed findings.
        Review the original evidence before acting. Evidence and stored results are unchanged.
        """
        settings = self.ctx.settings
        if not settings.jev_enabled:
            raise jev.JevError(
                "Jev is disabled. Set CHAINSAW_JEV_ENABLED=true to allow TypeSafe API calls."
            )
        if offset < 0 or not 1 <= limit <= 10 or not 0 <= min_confidence <= 1:
            raise ValueError("Invalid offset, limit or min_confidence.")
        if fields is not None and (
            not 1 <= len(fields) <= 40 or any(not 1 <= len(f) <= 200 for f in fields)
        ):
            raise ValueError("fields must contain 1 to 40 field paths of 1 to 200 characters.")
        # The store owns projection and shorthand expansion; this tool only sends rows.
        page = self.ctx.store.page(handle, offset=offset, limit=limit, fields=fields)
        rows = page["rows"]
        records = {f"row_{offset + index}": row for index, row in enumerate(rows)}
        out = {
            "source_handle": handle,
            "source_tool": page["tool"],
            "total": page["total"],
            "offset": offset,
            "returned": len(rows),
            "next_offset": page["next_offset"],
            "truncated": page.get("truncated", False),
            "truncation_reason": page.get("truncation_reason"),
            "fields": fields,
            "advisory": True,
            "min_confidence": min_confidence,
            "priority_levels": dict(enumerate(jev.PRIORITIES)),
            "assessments": [],
            "failed": 0,
            "request_sent": False,
            "request_bytes": 0,
        }
        if not rows:
            return dumps(out)
        response = jev.evaluate(settings, records)
        assessments = []
        for index, row_id in enumerate(records):
            if failure := response["errors"].get(row_id):
                assessments.append(
                    {
                        "source_row_index": offset + index,
                        "classification": None,
                        "priority": None,
                        "error": failure["check"],
                        "question": failure["question"],
                        "uncertain": True,
                        "uncertain_reasons": ["validation_failed"],
                    }
                )
                continue
            classification = response["answers"][f"{row_id}_classification"]
            priority = response["answers"][f"{row_id}_priority"]
            reasons = []
            if classification["choice"] == "insufficient_context":
                reasons.append("insufficient_context")
            if classification["confidence"] < min_confidence:
                reasons.append("low_classification_confidence")
            if priority["confidence"] < min_confidence:
                reasons.append("low_priority_confidence")
            assessments.append(
                {
                    "source_row_index": offset + index,
                    "classification": classification,
                    "priority": priority,
                    "uncertain": bool(reasons),
                    "uncertain_reasons": reasons,
                }
            )
        assessments.sort(
            key=lambda a: (
                a["priority"] is None,
                -a["priority"]["score"] if a["priority"] is not None else 0,
                a["source_row_index"],
            )
        )
        out.update(
            model=response["model"],
            usage=response["usage"],
            assessments=assessments,
            failed=len(response["errors"]),
            request_sent=True,
            request_bytes=response["request_bytes"],
        )
        try:
            return dumps(out)
        except ResultError:
            raise jev.JevError(
                "Jev response exceeds the inline budget; reduce limit. "
                "The API request was sent; no automatic retry was made."
            ) from None

    TOOLS = ("chainsaw_jev_triage",)
