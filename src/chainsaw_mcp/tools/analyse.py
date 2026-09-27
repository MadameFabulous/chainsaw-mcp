"""Timeline and anti-forensics analyses: log gaps, shimcache, SRUM."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated

from pydantic import Field

from ..runner import ChainsawError
from ._common import ToolContext, check_timestamp, check_timezone, check_window, dumps
from .evidence import analysis_diagnostics, bounded_analysis_response, save_analysis_rows


class AnalyseTools:
    def __init__(self, ctx: ToolContext) -> None:
        self.ctx = ctx

    def chainsaw_analyse_gaps(
        self,
        paths: Annotated[
            list[str],
            Field(description="EVTX files or directories under an allowed root.", min_length=1),
        ],
        min_time_gap_minutes: Annotated[
            int, Field(ge=1, le=10_080, description="Flag time gaps at least this long.")
        ] = 30,
        record_id_gaps: Annotated[bool, Field(description="Detect EventRecordID gaps.")] = True,
        time_gaps: Annotated[bool, Field(description="Detect chronological gaps.")] = True,
        from_time: Annotated[
            str | None, Field(description="Analyse from YYYY-MM-DDTHH:MM:SS.")
        ] = None,
        to_time: Annotated[
            str | None, Field(description="Analyse up to YYYY-MM-DDTHH:MM:SS.")
        ] = None,
        timezone: Annotated[str | None, Field(description="IANA timezone for output.")] = None,
        skip_errors: Annotated[bool, Field(description="Continue past unreadable files.")] = True,
        limit: Annotated[int, Field(ge=1, le=2000, description="Maximum gaps to return.")] = 200,
    ) -> str:
        """Detect chronological or EventRecordID discontinuities for investigation.

        Curated or filtered samples naturally contain gaps; these are not proof of
        deletion. Correlate with acquisition history and Security 1102 / System 104.
        """
        ctx = self.ctx
        if not record_id_gaps and not time_gaps:
            raise ValueError("Enable record_id_gaps or time_gaps")
        evidence = ctx.evidence_paths(paths)
        args = ["analyse", "gaps", "--json", "--min-time-gap-minutes", str(min_time_gap_minutes)]
        if not record_id_gaps:
            args.append("--no-record-id-gaps")
        if not time_gaps:
            args.append("--no-time-gaps")
        if start := check_timestamp(from_time, "from_time"):
            args += ["--from", start]
        if end := check_timestamp(to_time, "to_time"):
            args += ["--to", end]
        check_window(start, end)
        if tz := check_timezone(timezone):
            args += ["--timezone", tz]
        if skip_errors:
            args.append("--skip-errors")
        result = ctx.runner.run(args + ["--"] + evidence)
        gaps = json.loads(result.stdout or "[]")
        by_kind: dict[str, int] = {}
        by_file: dict[str, int] = {}
        for gap in gaps:
            by_kind[gap.get("kind", "?")] = by_kind.get(gap.get("kind", "?"), 0) + 1
            name = str(gap.get("path", "?")).rsplit("/", 1)[-1]
            by_file[name] = by_file.get(name, 0) + 1
        handle = save_analysis_rows(ctx, gaps, "chainsaw_analyse_gaps", result.argv)
        diagnostics = analysis_diagnostics(
            ctx, result.messages, result.argv, "chainsaw_analyse_gaps"
        )
        return bounded_analysis_response(
            {
                "handle": handle,
                "total": len(gaps),
                "by_kind": by_kind,
                "by_file": dict(sorted(by_file.items(), key=lambda kv: -kv[1])[:50]),
                "gaps": gaps[:limit],
                "diagnostics": diagnostics,
                "chainsaw_messages": diagnostics.pop("messages"),
                "interpretation": (
                    "Curated or filtered samples, retention, collection boundaries and quiet "
                    "periods can produce gaps. Gaps alone are not proof of deletion or tampering."
                ),
                "duration_seconds": result.duration_seconds,
            },
            "gaps",
            len(gaps),
        )

    def chainsaw_analyse_shimcache(
        self,
        system_hive: Annotated[
            str, Field(description="SYSTEM registry hive under an allowed evidence root.")
        ],
        amcache_hive: Annotated[
            str | None, Field(description="Optional Amcache.hve for timeline enrichment.")
        ] = None,
        patterns: Annotated[
            list[str] | None,
            Field(
                description=(
                    "Regexes identifying entries whose shimcache timestamp equals their "
                    "insertion time (e.g. known-good installer paths). Default: bundled list "
                    "if present, otherwise none."
                )
            ),
        ] = None,
        timestamp_pairs: Annotated[
            bool, Field(description="Enable near-timestamp pair detection with Amcache.")
        ] = False,
        preview: Annotated[int, Field(ge=0, le=200, description="Rows to include inline.")] = 50,
    ) -> str:
        """Build an execution timeline from the shimcache with optional Amcache enrichment.

        Wraps `chainsaw analyse shimcache`. Output is CSV stored under a result handle;
        the preview holds the first rows. Use chainsaw_result_export for the full file.
        """
        ctx = self.ctx
        system = ctx.evidence(system_hive)
        args = ["analyse", "shimcache"]
        for pattern in patterns or []:
            if not pattern:
                raise ValueError("patterns must be non-empty")
            args.append(f"--regex={pattern}")
        if amcache_hive:
            args += ["--amcache", ctx.evidence(amcache_hive)]
            if timestamp_pairs:
                args.append("--tspair")
        elif timestamp_pairs:
            raise ValueError("timestamp_pairs requires amcache_hive")
        handle, out_path = ctx.store.reserve(".csv")
        try:
            args += ["--output", str(out_path), "--", system]
            result = ctx.runner.run(args)
            meta = ctx.store.commit(
                handle,
                tool="chainsaw_analyse_shimcache",
                argv=result.argv,
                inputs={"system_hive": ctx.shown(system), "amcache_hive": amcache_hive},
                fmt="csv",
            )
        finally:
            ctx.store.abort(handle)
        diagnostics = analysis_diagnostics(
            ctx, result.messages, result.argv, "chainsaw_analyse_shimcache"
        )
        return dumps(
            {
                "handle": meta.handle,
                "format": "csv",
                "diagnostics": diagnostics,
                "chainsaw_messages": diagnostics.pop("messages"),
                "preview": _csv_preview(ctx.store.data_path(meta.handle, ".csv"), preview),
                "duration_seconds": result.duration_seconds,
            }
        )

    def chainsaw_analyse_srum(
        self,
        srum_db: Annotated[str, Field(description="SRUDB.dat under an allowed evidence root.")],
        software_hive: Annotated[
            str, Field(description="SOFTWARE registry hive under an allowed evidence root.")
        ],
        stats_only: Annotated[
            bool, Field(description="Only report table statistics, not the full extraction.")
        ] = False,
        preview_bytes: Annotated[
            int, Field(ge=0, le=12_000, description="Bytes of output to include inline.")
        ] = 12_000,
    ) -> str:
        """Analyse the System Resource Usage Monitor (SRUM) database.

        Wraps `chainsaw analyse srum`. Output is stored under a result handle; use
        chainsaw_result_export for the complete text.
        """
        ctx = self.ctx
        srum = ctx.evidence(srum_db)
        software = ctx.evidence(software_hive)
        args = ["analyse", "srum", "--software", software]
        if stats_only:
            args.append("--stats-only")
        handle, out_path = ctx.store.reserve(".txt")
        try:
            args += ["--output", str(out_path), "--", srum]
            result = ctx.runner.run(args)
            if not out_path.exists() or not out_path.stat().st_size:
                if not result.stdout.strip():
                    raise ChainsawError(
                        "chainsaw analyse srum produced no output; check that srum_db is a "
                        "SRUDB.dat and software_hive its matching SOFTWARE hive"
                    )
                out_path.write_text(result.stdout)
            meta = ctx.store.commit(
                handle,
                tool="chainsaw_analyse_srum",
                argv=result.argv,
                inputs={"srum_db": ctx.shown(srum), "software_hive": ctx.shown(software)},
                fmt="txt",
            )
        finally:
            ctx.store.abort(handle)
        published = ctx.store.data_path(meta.handle, ".txt")
        with published.open("rb") as fh:
            text = fh.read(preview_bytes).decode("utf-8", errors="ignore")
        diagnostics = analysis_diagnostics(
            ctx, result.messages, result.argv, "chainsaw_analyse_srum"
        )
        return dumps(
            {
                "handle": meta.handle,
                "format": "txt",
                "bytes": published.stat().st_size,
                "diagnostics": diagnostics,
                "chainsaw_messages": diagnostics.pop("messages"),
                "preview": text,
                "truncated": published.stat().st_size > len(text.encode("utf-8")),
                "duration_seconds": result.duration_seconds,
            }
        )

    TOOLS = ("chainsaw_analyse_gaps", "chainsaw_analyse_shimcache", "chainsaw_analyse_srum")


def _csv_preview(path: Path, rows: int) -> dict[str, object]:
    # Stream physical CSV lines with a byte cap, including pathological long lines.
    header = None
    body: list[str] = []
    total_rows = 0
    budget = 12_000
    with path.open("rb") as fh:
        first = True
        while True:
            chunk = fh.readline(budget + 1 if budget else 1)
            if not chunk:
                break
            complete = chunk.endswith(b"\n")
            captured = chunk[:budget]
            while not complete:
                rest = fh.readline(65536)
                if not rest:
                    break
                complete = rest.endswith(b"\n")
            if first:
                header = captured.decode("utf-8", errors="ignore").rstrip("\r\n")
                budget -= len(captured)
                first = False
            else:
                total_rows += 1
                if len(body) < rows and budget:
                    body.append(captured.decode("utf-8", errors="ignore").rstrip("\r\n"))
                    budget -= len(captured)
    return {
        "header": header,
        "rows": body,
        "total_rows": total_rows,
        "truncated": total_rows > len(body) or budget == 0,
    }
