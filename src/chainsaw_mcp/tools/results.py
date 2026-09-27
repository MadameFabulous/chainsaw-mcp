"""Paging and aggregation over stored result handles.

Every view is delegated to :class:`chainsaw_mcp.results.ResultStore`, which owns the
result lifecycle: private storage, expiry, formats, filtering, paging and export. This
module only shapes MCP parameters and applies server-side limits.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import Field

from ..result_budget import DEFAULT_MAX_BYTES
from ..result_budget import bounded_dumps as dumps
from ._common import ToolContext

_HANDLE_DESC = "Result handle returned by a hunt, search, dump or analysis tool."


class ResultTools:
    def __init__(self, ctx: ToolContext) -> None:
        self.ctx = ctx

    def chainsaw_result_page(
        self,
        handle: Annotated[str, Field(description=_HANDLE_DESC)],
        offset: Annotated[int, Field(ge=0, description="First row index to return.")] = 0,
        limit: Annotated[int, Field(ge=1, le=500, description="Rows to return.")] = 50,
        fields: Annotated[
            list[str] | None,
            Field(
                description=(
                    "Dotted paths to project, e.g. ['name', 'level', 'document.data.Event."
                    "EventData.CommandLine']. Shorthand names from chainsaw_result_fields also "
                    "work. Omit for whole rows."
                )
            ),
        ] = None,
        where: Annotated[
            dict[str, str | int | float | bool] | None,
            Field(
                description=(
                    "Filters, field path or shorthand -> value; all must match. Text matches "
                    "as a case-insensitive substring, numbers and booleans exactly (event_id: "
                    "'4624' matches 4624 only). An aggregate hunt row matches when any of its "
                    "documents matches. Example: {'level': 'critical', 'computer': 'DC01'}."
                )
            ),
        ] = None,
        max_bytes: Annotated[
            int, Field(ge=256, le=131072, description="Encoded response byte budget.")
        ] = DEFAULT_MAX_BYTES,
    ) -> str:
        """Read a page of rows from a stored result, optionally projected and filtered.

        Rows are chainsaw detections (hunt) or raw documents (search, dump). Iterate with
        next_offset until it is null.
        """
        limit = min(limit, self.ctx.settings.max_page)
        return dumps(
            self.ctx.store.page(
                handle, offset=offset, limit=limit, fields=fields, where=where, max_bytes=max_bytes
            ),
            max_bytes,
        )

    def chainsaw_result_summary(
        self,
        handle: Annotated[str, Field(description=_HANDLE_DESC)],
        group_by: Annotated[
            list[str] | None,
            Field(
                description=(
                    "Field paths or shorthand names to count by, e.g. ['rule', 'computer'] or "
                    "['document.data.Event.EventData.TargetUserName']. Omit for the standard "
                    "overview (rules, levels, hosts, channels, event IDs, hours)."
                )
            ),
        ] = None,
        top: Annotated[int, Field(ge=1, le=200, description="Values per grouping.")] = 25,
        where: Annotated[
            dict[str, str | int | float | bool] | None,
            Field(
                description=(
                    "Filters applied before counting; same matching rules as "
                    "chainsaw_result_page's where."
                )
            ),
        ] = None,
    ) -> str:
        """Aggregate a stored result without paging through it.

        Use the default overview to understand a hunt, then group by specific event fields
        (users, processes, source IPs, logon IDs) to build pivots for chainsaw_search.
        """
        return dumps(self.ctx.store.summary(handle, group_by=group_by, top=top, where=where))

    def chainsaw_result_fields(
        self,
        handle: Annotated[str, Field(description=_HANDLE_DESC)],
        sample: Annotated[int, Field(ge=1, le=2000, description="Rows to sample.")] = 200,
    ) -> str:
        """Discover the field paths present in a result so you can project or group on them.

        Returns each dotted path with how many sampled rows carry it and an example value.
        """
        return dumps(self.ctx.store.fields(handle, sample=sample))

    def chainsaw_result_export(
        self,
        handle: Annotated[str, Field(description=_HANDLE_DESC)],
        format: Annotated[
            str,
            Field(
                description=(
                    "csv, jsonl, or text (an alias of csv). CSV flattens the standard columns "
                    "of hunts and searches; analysis handles use their sampled top-level keys."
                )
            ),
        ] = "csv",
        fields: Annotated[
            list[str] | None,
            Field(description="Columns for CSV (dotted paths or shorthand). Default overview set."),
        ] = None,
        max_rows: Annotated[
            int, Field(ge=1, le=20_000, description="Row cap for the export.")
        ] = 5000,
        offset: Annotated[int, Field(ge=0)] = 0,
        byte_offset: Annotated[int, Field(ge=0)] = 0,
        max_bytes: Annotated[
            int, Field(ge=256, le=131072, description="Encoded response byte budget.")
        ] = DEFAULT_MAX_BYTES,
    ) -> str:
        """Render a stored result as CSV or JSONL text for reports or other tools.

        Large results are capped by rows and encoded response bytes; resume next_offset.
        CSV pages repeat their header. For stored text files resume next_byte_offset;
        those UTF-8 chunks may split records and must be concatenated before parsing.
        """
        return dumps(
            self.ctx.store.export(
                handle,
                format=format,
                fields=fields,
                max_rows=max_rows,
                offset=offset,
                byte_offset=byte_offset,
                max_bytes=max_bytes,
            ),
            max_bytes,
        )

    def chainsaw_result_chunk(
        self,
        handle: Annotated[str, Field(description=_HANDLE_DESC)],
        row_offset: Annotated[
            int | None,
            Field(
                description=(
                    "Source row index of one oversized JSON row to stream (the row_offset an "
                    "oversized error reports). Omit to stream the stored file itself."
                )
            ),
        ] = None,
        byte_offset: Annotated[
            int,
            Field(
                description=(
                    "Byte position to resume from; pass next_byte_offset from the previous chunk."
                )
            ),
        ] = 0,
        max_bytes: Annotated[
            int,
            Field(
                description=(
                    "Content byte budget per chunk (256-131072); UTF-8 characters are never split."
                )
            ),
        ] = DEFAULT_MAX_BYTES,
    ) -> str:
        """Read UTF-8 text chunks of a file or oversized JSON row. Resume next_byte_offset."""
        return dumps(
            self.ctx.store.chunk(
                handle, row_offset=row_offset, byte_offset=byte_offset, max_bytes=max_bytes
            ),
            max_bytes,
        )

    def chainsaw_result_events(
        self,
        handle: Annotated[str, Field(description=_HANDLE_DESC)],
        offset: Annotated[
            int,
            Field(description="First event-group offset to return (not a detection-row offset)."),
        ] = 0,
        limit: Annotated[int, Field(description="Event groups to return.")] = 50,
        fields: Annotated[
            list[str] | None,
            Field(
                description=(
                    "Dotted paths or shorthand names to project inside each group's event. "
                    "Omit for whole events."
                )
            ),
        ] = None,
        max_bytes: Annotated[
            int, Field(description="Encoded response byte budget (256-131072).")
        ] = DEFAULT_MAX_BYTES,
    ) -> str:
        """Page unique source-qualified events, retaining every associated rule match."""
        return dumps(
            self.ctx.store.events(
                handle,
                offset=offset,
                limit=min(limit, self.ctx.settings.max_page),
                fields=fields,
                max_bytes=max_bytes,
            ),
            max_bytes,
        )

    def chainsaw_result_list(
        self,
        offset: Annotated[int, Field(ge=0, description="First entry to return.")] = 0,
        limit: Annotated[int, Field(ge=1, le=200, description="Entries per page.")] = 50,
        max_bytes: Annotated[
            int,
            Field(ge=256, le=131_072, description="Encoded JSON byte budget, including metadata."),
        ] = DEFAULT_MAX_BYTES,
    ) -> str:
        """List stored result handles, newest first, with tool, inputs and row counts."""
        return dumps(
            self.ctx.store.list_page(offset=offset, limit=limit, max_bytes=max_bytes), max_bytes
        )

    def chainsaw_result_delete(
        self, handle: Annotated[str, Field(description=_HANDLE_DESC)]
    ) -> str:
        """Delete a stored result and its metadata. Evidence files are never touched."""
        removed = self.ctx.store.delete(handle)
        return dumps({"handle": handle, "deleted": removed})

    TOOLS = (
        "chainsaw_result_chunk",
        "chainsaw_result_events",
        "chainsaw_result_page",
        "chainsaw_result_summary",
        "chainsaw_result_fields",
        "chainsaw_result_export",
        "chainsaw_result_list",
        "chainsaw_result_delete",
    )
