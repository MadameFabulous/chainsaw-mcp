"""Detection hunting and keyword searching. Results become server-minted handles."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Annotated, Any

from pydantic import Field

from ..result_budget import (
    DEFAULT_MAX_BYTES,
    ResultError,
    annotate_delivery,
    bounded_dumps,
    encoded_size,
)
from ..results import EVENT_FIELDS, HUNT_FIELDS, get_path, summarize
from ..rules import LEVELS
from ._common import (
    ToolContext,
    check_choices,
    check_extension,
    check_timestamp,
    check_timezone,
    check_window,
    clamp,
)
from .evidence import analysis_diagnostics

HUNT_STATUSES = ("stable", "experimental")
HUNT_KINDS = ("chainsaw", "sigma")


def _fit_preview(out: dict[str, Any]) -> str:
    """Account for nested metadata and the complete outer envelope when trimming."""
    preview = out["preview"]
    reason = preview.get("truncation_reason") or "limit"
    while True:
        annotate_delivery(preview, truncated=preview["next_offset"] is not None, reason=reason)
        annotate_delivery(out, truncated=preview["truncated"], reason=reason)
        if encoded_size(out) <= DEFAULT_MAX_BYTES or not preview["rows"]:
            return bounded_dumps(out)
        preview["rows"].pop()
        preview["returned"] = len(preview["rows"])
        preview["next_offset"] = preview["returned"]
        reason = "max_bytes"


class HuntTools:
    def __init__(self, ctx: ToolContext) -> None:
        self.ctx = ctx

    def _finish(
        self,
        *,
        tool: str,
        handle: str,
        argv: list[str],
        inputs: dict[str, Any],
        messages: list[str],
        duration: float,
        preview: int,
        fields: list[str] | None = None,
        commands: list[list[str]] | None = None,
    ) -> str:
        store = self.ctx.store
        try:
            meta = store.commit(handle, tool=tool, argv=argv, inputs=inputs, commands=commands)
        finally:
            store.abort(handle)
        summary = summarize(store.rows(handle))
        selected = (
            fields
            if fields is not None
            else list(HUNT_FIELDS if tool == "chainsaw_hunt" else EVENT_FIELDS)
        )
        preview_data: dict[str, Any] = {
            "returned": 0,
            "next_offset": 0 if meta.count else None,
            "rows": [],
        }
        if preview:
            try:
                preview_data = store.page(handle, limit=preview, fields=selected)
            except ResultError as exc:
                preview_data["error"] = str(exc)
                preview_data["truncation_reason"] = "max_bytes"
        # Messages are redacted and stored whole under their own handle; the envelope only
        # carries a bounded preview, so a noisy evidence set cannot fail a completed hunt.
        diagnostics = analysis_diagnostics(self.ctx, messages, argv, tool)
        out = {
            "handle": meta.handle,
            "total": meta.count,
            "duration_seconds": duration,
            "chainsaw_messages": diagnostics.pop("messages"),
            "diagnostics": diagnostics,
            "summary": summary,
            "preview": preview_data,
            "next": (
                "Use chainsaw_result_page, chainsaw_result_events, "
                "chainsaw_result_summary or chainsaw_result_export with this handle. "
                "chainsaw_messages is a preview; page diagnostics.handle for every message."
            ),
        }
        try:
            return _fit_preview(out)
        except ResultError as exc:
            raise ResultError(
                f"Result saved as {handle}; summary exceeds response budget. "
                f"Retrieve projected pages or summary with smaller top. {exc}"
            ) from exc

    def chainsaw_hunt(
        self,
        paths: Annotated[
            list[str],
            Field(
                description=(
                    "Evidence files or directories, relative to an allowed evidence root or "
                    "absolute inside one. Directories are searched recursively."
                ),
                min_length=1,
                max_length=64,
            ),
        ],
        sigma: Annotated[
            bool, Field(description="Apply the bundled Sigma rules through the mapping file.")
        ] = True,
        sigma_collections: Annotated[
            list[str] | None,
            Field(
                description=(
                    "Sigma collections or sub-trees to load, e.g. ['rules'], "
                    "['rules', 'rules-threat-hunting'] or ['rules/windows/process_creation']. "
                    "Default: ['rules']. Use chainsaw_rule_stats to see what is installed."
                )
            ),
        ] = None,
        mapping: Annotated[
            str | None,
            Field(
                description=(
                    "Mapping file name inside the mappings directory. Default "
                    "sigma-event-logs-all.yml; sigma-event-logs-legacy.yml for pre-Sysmon logs."
                )
            ),
        ] = None,
        chainsaw_rules: Annotated[
            bool, Field(description="Apply the bundled Chainsaw rules (rules/ directory).")
        ] = True,
        extra_rules: Annotated[
            list[str] | None,
            Field(
                description=(
                    "Additional Chainsaw-format rule directories: 'custom' for analyst-saved "
                    "rules, or 'chainsaw/<subdir>' such as 'chainsaw/evtx/lateral_movement'."
                )
            ),
        ] = None,
        levels: Annotated[
            list[str] | None,
            Field(description="Restrict rules to these levels: critical, high, medium, low, info."),
        ] = None,
        statuses: Annotated[
            list[str] | None,
            Field(description="Restrict loaded rules to these statuses: stable, experimental."),
        ] = None,
        kinds: Annotated[
            list[str] | None,
            Field(description="Restrict loaded rules to these kinds: chainsaw, sigma."),
        ] = None,
        from_time: Annotated[
            str | None,
            Field(description="Drop documents older than this, format YYYY-MM-DDTHH:MM:SS."),
        ] = None,
        to_time: Annotated[
            str | None,
            Field(description="Drop documents newer than this, format YYYY-MM-DDTHH:MM:SS."),
        ] = None,
        timezone: Annotated[
            str | None, Field(description="Render timestamps in this IANA timezone (default UTC).")
        ] = None,
        extension: Annotated[
            str | None, Field(description="Only load files with this extension, e.g. evtx.")
        ] = None,
        load_unknown: Annotated[
            bool, Field(description="Let chainsaw try to parse files it cannot identify.")
        ] = False,
        skip_errors: Annotated[
            bool, Field(description="Continue past unreadable files instead of failing the hunt.")
        ] = True,
        preview: Annotated[
            int, Field(description="Detections to include inline (0-100).", ge=0, le=100)
        ] = 20,
        fields: Annotated[
            list[str] | None,
            Field(
                description=(
                    "Dotted paths or shorthand names to project in the inline preview; see "
                    "chainsaw_result_fields. Omit for the standard shorthand columns."
                )
            ),
        ] = None,
    ) -> str:
        """Hunt evidence with Sigma and Chainsaw detection rules.

        Runs `chainsaw hunt` over the given paths, stores every detection as JSONL under a
        server-minted result handle, and returns aggregate counts (by rule, level, host,
        channel, event ID, hour) with a small preview. Prefer this over reading raw events.
        """
        ctx = self.ctx
        if not sigma and not chainsaw_rules and not extra_rules:
            raise ValueError("Enable sigma, chainsaw_rules, or supply extra_rules")
        evidence = ctx.evidence_paths(paths)
        args: list[str] = ["hunt", "--jsonl"]
        if sigma:
            for directory in ctx.catalog.sigma_dirs(sigma_collections):
                args += ["--sigma", str(directory)]
            args += ["--mapping", str(ctx.catalog.mapping(mapping))]
        rule_dirs = []
        if chainsaw_rules:
            if not ctx.settings.rules_dir.is_dir():
                raise ValueError(
                    f"Chainsaw rules directory {ctx.settings.rules_dir} is not installed"
                )
            rule_dirs.append(ctx.settings.rules_dir)
        rule_dirs += ctx.catalog.rule_dirs_for_hunt(extra_rules or [])
        for directory in rule_dirs:
            args += ["--rule", str(directory)]
        for level in check_choices(levels, LEVELS, "levels"):
            args += ["--level", level]
        for status in check_choices(statuses, HUNT_STATUSES, "statuses"):
            args += ["--status", status]
        for kind in check_choices(kinds, HUNT_KINDS, "kinds"):
            args += ["--kind", kind]
        if start := check_timestamp(from_time, "from_time"):
            args += ["--from", start]
        if end := check_timestamp(to_time, "to_time"):
            args += ["--to", end]
        check_window(start, end)
        if tz := check_timezone(timezone):
            args += ["--timezone", tz]
        if ext := check_extension(extension):
            args += ["--extension", ext]
        if load_unknown:
            args.append("--load-unknown")
        if skip_errors:
            args.append("--skip-errors")
        preview = clamp(preview, low=0, high=100, name="preview")
        handle, out_path = ctx.store.reserve(".jsonl")
        args += ["--output", str(out_path), "--"] + evidence
        try:
            result = ctx.runner.run(args)
        except BaseException:
            ctx.store.abort(handle)
            raise
        return self._finish(
            tool="chainsaw_hunt",
            handle=handle,
            argv=result.argv,
            inputs={
                "paths": [ctx.shown(p) for p in evidence],
                "sigma": sigma,
                "sigma_collections": sigma_collections,
                "mapping": mapping,
                "chainsaw_rules": chainsaw_rules,
                "extra_rules": extra_rules,
                "levels": levels,
                "statuses": statuses,
                "kinds": kinds,
                "from_time": from_time,
                "to_time": to_time,
                "timezone": timezone,
            },
            messages=result.messages,
            duration=result.duration_seconds,
            preview=preview,
            fields=fields,
        )

    def chainsaw_search(
        self,
        paths: Annotated[
            list[str],
            Field(description="Evidence files or directories under an allowed root.", min_length=1),
        ],
        patterns: Annotated[
            list[str] | None,
            Field(
                description=(
                    "String or regular-expression patterns matched against the whole document. "
                    "All must match unless match_any is true."
                )
            ),
        ] = None,
        tau: Annotated[
            list[str] | None,
            Field(
                description=(
                    "Tau field expressions such as 'Event.System.EventID: =4104' or "
                    "'Event.EventData.Image: i*mimikatz*'. Combined with AND unless match_any."
                )
            ),
        ] = None,
        ignore_case: Annotated[
            bool, Field(description="Case-insensitive pattern matching.")
        ] = True,
        match_any: Annotated[
            bool,
            Field(
                description=(
                    "Match a document when any one of the patterns matches (and, separately, "
                    "any one of the tau expressions) instead of requiring all of them. "
                    "Patterns and tau expressions are always combined with AND."
                )
            ),
        ] = False,
        from_time: Annotated[
            str | None, Field(description="Drop documents older than YYYY-MM-DDTHH:MM:SS.")
        ] = None,
        to_time: Annotated[
            str | None, Field(description="Drop documents newer than YYYY-MM-DDTHH:MM:SS.")
        ] = None,
        timestamp_field: Annotated[
            str | None,
            Field(
                description=(
                    "Field holding the timestamp when from_time/to_time are set. Default for "
                    "EVTX: Event.System.TimeCreated_attributes.SystemTime."
                )
            ),
        ] = None,
        timezone: Annotated[str | None, Field(description="IANA timezone for output.")] = None,
        extension: Annotated[str | None, Field(description="Only load this extension.")] = None,
        load_unknown: Annotated[
            bool, Field(description="Try to parse unidentified files.")
        ] = False,
        skip_errors: Annotated[bool, Field(description="Continue past unreadable files.")] = True,
        preview: Annotated[int, Field(ge=0, le=100, description="Events to include inline.")] = 20,
        fields: Annotated[
            list[str] | None,
            Field(
                description=(
                    "Dotted paths or shorthand names to project in the inline preview; see "
                    "chainsaw_result_fields. Omit for the standard shorthand columns."
                )
            ),
        ] = None,
    ) -> str:
        """Search evidence for keywords, regular expressions, or tau field expressions.

        Runs `chainsaw search`; each matching document is stored under a result handle and
        summarised by host, channel, event ID and hour. Use tau expressions to pivot on a
        specific field (for example a LogonId, process GUID, or user) after a hunt.
        """
        ctx = self.ctx
        if not patterns and not tau:
            raise ValueError("Provide at least one of patterns or tau")
        if len(patterns or []) + len(tau or []) > 32:
            raise ValueError("At most 32 patterns and tau expressions per call")
        evidence = ctx.evidence_paths(paths)
        args: list[str] = ["search", "--jsonl"]
        for pattern in patterns or []:
            if not pattern:
                raise ValueError("patterns must be non-empty strings")
            # --regex=VALUE keeps a pattern starting with '-' from being read as a flag.
            args.append(f"--regex={pattern}")
        for expr in tau or []:
            if ":" not in expr:
                raise ValueError(f"tau expression {expr!r} needs the form 'Field.Path: op value'")
            args.append(f"--tau={expr}")
        if ignore_case:
            args.append("--ignore-case")
        if match_any:
            args.append("--match-any")
        start = check_timestamp(from_time, "from_time")
        end = check_timestamp(to_time, "to_time")
        check_window(start, end)
        if start or end:
            field = timestamp_field or "Event.System.TimeCreated_attributes.SystemTime"
            if not all(ch.isalnum() or ch in "._-" for ch in field):
                raise ValueError("timestamp_field must be a dotted field path")
            args += ["--timestamp", field]
            if start:
                args += ["--from", start]
            if end:
                args += ["--to", end]
        if tz := check_timezone(timezone):
            args += ["--timezone", tz]
        if ext := check_extension(extension):
            args += ["--extension", ext]
        if load_unknown:
            args.append("--load-unknown")
        if skip_errors:
            args.append("--skip-errors")
        preview = clamp(preview, low=0, high=100, name="preview")
        handle, out_path = ctx.store.reserve(".jsonl")
        args += ["--output", str(out_path), "--"] + evidence
        try:
            result = ctx.runner.run(args)
        except BaseException:
            ctx.store.abort(handle)
            raise
        return self._finish(
            tool="chainsaw_search",
            handle=handle,
            argv=result.argv,
            inputs={
                "paths": [ctx.shown(p) for p in evidence],
                "patterns": patterns,
                "tau": tau,
                "ignore_case": ignore_case,
                "match_any": match_any,
                "from_time": from_time,
                "to_time": to_time,
                "timezone": timezone,
            },
            messages=result.messages,
            duration=result.duration_seconds,
            preview=preview,
            fields=fields,
        )

    def chainsaw_dump(
        self,
        paths: Annotated[
            list[str],
            Field(description="Evidence files or directories under an allowed root.", min_length=1),
        ],
        extension: Annotated[str | None, Field(description="Only dump this extension.")] = None,
        load_unknown: Annotated[
            bool, Field(description="Try to parse unidentified files.")
        ] = False,
        skip_errors: Annotated[bool, Field(description="Continue past unreadable files.")] = True,
        preview: Annotated[int, Field(ge=0, le=100, description="Records to include inline.")] = 10,
        fields: Annotated[
            list[str] | None,
            Field(
                description=(
                    "Dotted paths or shorthand names to project in the inline preview; see "
                    "chainsaw_result_fields. Omit for the standard shorthand columns."
                )
            ),
        ] = None,
    ) -> str:
        """Convert every record in the evidence to JSON under a result handle.

        Wraps `chainsaw dump`. Use it when a hunt or search has narrowed the scope to one
        or two files and you need the complete record stream; page through the handle.
        """
        ctx = self.ctx
        evidence = ctx.evidence_paths(paths)
        args: list[str] = ["dump", "--jsonl"]
        if ext := check_extension(extension):
            args += ["--extension", ext]
        if load_unknown:
            args.append("--load-unknown")
        if skip_errors:
            args.append("--skip-errors")
        preview = clamp(preview, low=0, high=100, name="preview")
        handle, out_path = ctx.store.reserve(".jsonl")
        args += ["--output", str(out_path), "--"] + evidence
        try:
            result = ctx.runner.run(args)
        except BaseException:
            ctx.store.abort(handle)
            raise
        return self._finish(
            tool="chainsaw_dump",
            handle=handle,
            argv=result.argv,
            inputs={"paths": [ctx.shown(p) for p in evidence], "extension": extension},
            messages=result.messages,
            duration=result.duration_seconds,
            preview=preview,
            fields=fields,
        )

    def chainsaw_process_lineage(
        self,
        paths: Annotated[
            list[str],
            Field(
                description=(
                    "Explicit evidence files from one investigation. Directories and shared "
                    "roots are rejected so unrelated scenarios stay separate."
                )
            ),
        ],
        process_guid: Annotated[
            str,
            Field(
                description="Starting Sysmon ProcessGuid, canonical GUID with or without braces."
            ),
        ],
        computer: Annotated[
            str,
            Field(
                description=(
                    "Computer value of the host, compared case-insensitively; other hosts are "
                    "ignored."
                )
            ),
        ],
        max_hops: Annotated[int, Field(description="Parent/child hops to traverse (0-5).")] = 2,
        max_events: Annotated[
            int, Field(description="Total events to collect across all hops (1-5000).")
        ] = 500,
        max_queries: Annotated[
            int, Field(description="Searches allowed before traversal stops as incomplete (1-256).")
        ] = 64,
        preview: Annotated[int, Field(description="Events to include inline (0-100).")] = 20,
    ) -> str:
        """Pivot process GUIDs in explicitly scoped original evidence, including unmatched events.

        Supply files from one investigation (not a shared evidence root) and an exact host.
        Each hop queries process/parent GUIDs; output is capped and reports incomplete traversal.
        """
        guid_re = re.compile(
            r"(?:\{[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}|[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12})"
        )
        if not guid_re.fullmatch(process_guid):
            raise ValueError("process_guid must be a canonical GUID, optionally braced")
        if not computer or not 0 <= max_hops <= 5 or not 1 <= max_events <= 5000:
            raise ValueError("Require computer, max_hops 0..5 and max_events 1..5000")
        if not 1 <= max_queries <= 256:
            raise ValueError("max_queries must be 1..256")
        preview = clamp(preview, low=0, high=100, name="preview")
        evidence = self.ctx.evidence_paths(paths)
        if any(not Path(p).is_file() for p in evidence):
            raise ValueError(
                "Lineage paths must be explicit evidence files to isolate investigations"
            )

        def normalize(value):
            return str(value).strip("{}").lower()

        frontier = {normalize(process_guid)}
        queried: set[str] = set()
        seen = set()
        rows: list[dict[str, Any]] = []
        capped = query_capped = False
        query_count = 0
        argv = []
        commands = []
        messages = []
        duration = 0.0
        hop = 0
        for hop_index in range(max_hops + 1):
            hop = hop_index
            next_guids: set[str] = set()
            for guid in sorted(frontier - queried):
                if query_count >= max_queries:
                    query_capped = True
                    break
                queried.add(guid)
                for source in evidence:
                    if query_count >= max_queries:
                        query_capped = True
                        break
                    query_count += 1
                    temporary, path = self.ctx.store.reserve()
                    args = [
                        "search",
                        "--jsonl",
                        "--ignore-case",
                        f"--regex={guid}",
                        "--output",
                        str(path),
                        "--",
                        source,
                    ]
                    try:
                        run = self.ctx.runner.run(args)
                        argv = run.argv
                        commands.append(run.argv)
                        messages.extend(run.messages)
                        duration += run.duration_seconds
                        with path.open(encoding="utf-8") as fh:
                            for line in fh:
                                if not line.strip():
                                    continue
                                row = json.loads(line)
                                host = get_path(row, "Event.System.Computer")
                                if str(host or "").lower() != computer.lower():
                                    continue
                                pg = normalize(get_path(row, EVENT_FIELDS["process_guid"]))
                                parent = normalize(get_path(row, EVENT_FIELDS["parent_guid"]))
                                if guid not in (pg, parent):
                                    continue
                                key = (source, json.dumps(row, sort_keys=True))
                                if key in seen:
                                    continue
                                if len(rows) >= max_events:
                                    capped = True
                                    break
                                seen.add(key)
                                row["path"] = source
                                rows.append(row)
                                next_guids.update(v for v in (pg, parent) if guid_re.fullmatch(v))
                    finally:
                        self.ctx.store.abort(temporary)
                    if capped:
                        break
                if capped or query_capped:
                    break
            frontier = next_guids - queried
            if capped or query_capped or not frontier:
                break
        handle, output = self.ctx.store.reserve()
        try:
            output.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
            response = self._finish(
                tool="chainsaw_process_lineage",
                handle=handle,
                argv=argv,
                commands=commands,
                inputs={
                    "paths": [self.ctx.shown(p) for p in evidence],
                    "computer": computer,
                    "process_guid": process_guid,
                    "max_hops": max_hops,
                    "max_events": max_events,
                    "max_queries": max_queries,
                },
                messages=messages,
                duration=duration,
                preview=preview,
            )
        finally:
            self.ctx.store.abort(handle)
        result = json.loads(response)
        result["lineage"] = {
            "queried_guids": len(queried),
            "hops_completed": hop,
            "event_limit_reached": capped,
            "hop_limit_reached": bool(frontier) and not capped and not query_capped,
            "query_limit_reached": query_capped,
            "queries": query_count,
            "complete": not capped and not query_capped and not frontier,
        }
        return _fit_preview(result)

    TOOLS = ("chainsaw_hunt", "chainsaw_search", "chainsaw_dump", "chainsaw_process_lineage")
