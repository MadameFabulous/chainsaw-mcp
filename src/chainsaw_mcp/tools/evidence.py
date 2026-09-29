"""Evidence discovery and server status."""

from __future__ import annotations

import json
import re
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from typing import Annotated, Any

from pydantic import Field

from .. import CHAINSAW_RELEASE, __version__
from ..paths import iter_artefacts
from ..result_budget import DEFAULT_MAX_BYTES, annotate_delivery, bounded_dumps, encoded_size
from ..runner import ChainsawError
from ._common import ToolContext, dumps


class EvidenceTools:
    def __init__(self, ctx: ToolContext) -> None:
        self.ctx = ctx

    def chainsaw_status(self) -> str:
        """Report server configuration, chainsaw version, rule counts and evidence roots.

        Call this first to learn which evidence roots and rule sets are available, and
        whether the chainsaw binary is installed.
        """
        ctx = self.ctx
        try:
            version = ctx.runner.version()
            binary_error = None
        except ChainsawError as exc:
            version, binary_error = None, str(exc)
        roots = []
        for root in ctx.settings.evidence_roots:
            entries = [p for p in root.iterdir()] if root.is_dir() else []
            roots.append(
                {
                    "path": str(root),
                    "exists": root.is_dir(),
                    "top_level": sorted(p.name for p in entries)[:50],
                    "top_level_total": len(entries),
                }
            )
        return dumps(
            {
                "server": {"name": "chainsaw-mcp", "version": __version__},
                "chainsaw": {
                    "version": version,
                    "tested_release": CHAINSAW_RELEASE,
                    "error": binary_error,
                },
                "config": ctx.settings.describe(),
                "rules": ctx.catalog.stats(),
                "evidence_roots": roots,
                "results_stored": len(ctx.store.list()),
            }
        )

    def chainsaw_list_evidence(
        self,
        path: Annotated[
            str,
            Field(
                description=(
                    "Directory or file under an allowed evidence root; '.' for the first root. "
                    "Use chainsaw_status to see the roots."
                )
            ),
        ] = ".",
        pattern: Annotated[
            str, Field(description="Case-insensitive substring filter on the full path.")
        ] = "",
        limit: Annotated[int, Field(ge=1, le=1000, description="Maximum files to return.")] = 200,
        offset: Annotated[int, Field(ge=0, description="Next offset from the preceding page.")] = 0,
    ) -> str:
        """List artefact files below an evidence path with sizes and types.

        Use it to scope a hunt: pick directories or individual .evtx files instead of
        hunting an entire mount. Follow next_offset until null for a complete inventory;
        the evidence tree must remain unchanged between pages.
        """
        ctx = self.ctx
        base = Path(ctx.evidence(path))
        if offset < 0 or limit < 1:
            raise ValueError("offset must be >= 0 and limit >= 1")
        inventory = iter_artefacts(base, pattern=pattern, limit=None)
        files = inventory[offset : offset + min(limit, 1000)]
        dirs = sorted(p.name for p in base.iterdir() if p.is_dir()) if base.is_dir() else []
        response: dict[str, Any] = {
            "base": str(base),
            "shown_as": ctx.shown(str(base)),
            "subdirectories": dirs[:200],
            "files": files,
            "offset": offset,
            "total": len(inventory),
            "inventory_consistency": "Requires unchanged evidence tree between pages",
            "pattern": pattern,
        }
        while True:
            response.update(
                returned=len(files),
                next_offset=offset + len(files) if offset + len(files) < len(inventory) else None,
                truncated=offset + len(files) < len(inventory),
            )
            if encoded_size(response) <= DEFAULT_MAX_BYTES - 4096:
                break
            if not files:
                raise ValueError("Inventory metadata exceeds byte budget; narrow path")
            files.pop()
        if not files and offset < len(inventory):
            raise ValueError("Inventory entry exceeds byte budget; narrow path")
        by_suffix: dict[str, int] = {}
        total_bytes = 0
        for f in files:
            by_suffix[str(f["suffix"])] = by_suffix.get(str(f["suffix"]), 0) + 1
            size = f["bytes"]
            total_bytes += size if isinstance(size, int) else 0
        response.update(bytes=total_bytes, by_suffix=by_suffix)
        annotate_delivery(
            response,
            truncated=response["truncated"],
            reason="page_limit" if response["truncated"] else None,
        )
        return bounded_dumps(response)

    def chainsaw_analyse_evtx(
        self,
        paths: Annotated[
            list[str],
            Field(description="EVTX files or directories under an allowed root.", min_length=1),
        ],
        skip_errors: Annotated[bool, Field(description="Continue past unreadable files.")] = True,
    ) -> str:
        """Summarise EVTX channel, provider and event-ID coverage, including missing metadata.

        Runs native analysis and a streamed dump pass. The inline per_file list is a
        bounded preview; page handle for full files, coverage_handle for identity counts,
        and diagnostics.handle for all runner messages. Missing Channel in ETW is not
        evidence of corruption, and successful exit does not establish complete parsing.
        """
        ctx = self.ctx
        evidence = ctx.evidence_paths(paths)
        args = ["analyse", "evtx", "--json"]
        if skip_errors:
            args.append("--skip-errors")
        result = ctx.runner.run(args + ["--"] + evidence)
        data = json.loads(result.stdout or "[]")
        if not isinstance(data, list) or not all(isinstance(row, dict) for row in data):
            raise ChainsawError("Unexpected EVTX analysis output: expected file objects")
        records = sum(int(f.get("records_seen", 0)) for f in data)
        totals: Counter[str] = Counter()
        providers: Counter[str] = Counter()
        event_ids: Counter[str] = Counter()
        combinations: Counter[tuple[str | None, str | None, str | None]] = Counter()
        missing = {"channel": 0, "provider": 0, "event_id": 0}
        observed = 0
        # Chainsaw's native summary omits provider identity and channel-less ETW events.
        # Dump directly to a private leased file; never capture the raw stream in RAM.
        scratch_handle, scratch_path = ctx.store.reserve()
        dump_args = ["dump", "--jsonl", "--extension", "evtx", "--output", str(scratch_path)]
        if skip_errors:
            dump_args.append("--skip-errors")
        dump_result = None
        coverage_error = None
        try:
            dump_result = ctx.runner.run(dump_args + ["--"] + evidence)
            with scratch_path.open(encoding="utf-8") as fh:
                for line in fh:
                    if not line.strip():
                        continue
                    row = json.loads(line)
                    system = row.get("Event", {}).get("System", {})
                    channel = _metadata_value(system.get("Channel"))
                    provider_attrs = system.get("Provider_attributes") or {}
                    provider = _metadata_value(provider_attrs.get("Name"))
                    if provider is None:
                        raw_provider = system.get("Provider")
                        if isinstance(raw_provider, dict):
                            raw_provider = raw_provider.get("Name") or raw_provider.get(
                                "#attributes", {}
                            ).get("Name")
                        provider = _metadata_value(raw_provider)
                    event_id = _metadata_value(system.get("EventID"))
                    observed += 1
                    for key, value in (
                        ("channel", channel),
                        ("provider", provider),
                        ("event_id", event_id),
                    ):
                        missing[key] += value is None
                    if channel is not None:
                        totals[channel] += 1
                    if provider is not None:
                        providers[provider] += 1
                    event_ids[f"{channel if channel is not None else '<missing>'}:{event_id}"] += 1
                    combinations[(provider, channel, event_id)] += 1
        except (ChainsawError, OSError, ValueError, AttributeError, TypeError) as exc:
            coverage_error = str(exc)
        finally:
            ctx.store.abort(scratch_handle)
        messages = result.messages + (dump_result.messages if dump_result else [])
        if coverage_error:
            messages.append("[!] Provider coverage incomplete: " + coverage_error)
        diagnostics = analysis_diagnostics(ctx, messages, result.argv, "chainsaw_analyse_evtx")
        if coverage_error or observed != records:
            diagnostics["parse_status"] = "incomplete"
        diagnostics["native_records"] = records
        diagnostics["coverage_records"] = observed
        coverage_handle = save_analysis_rows(
            ctx,
            (
                {"provider_name": p, "channel_name": c, "event_id_value": e, "count": n}
                for (p, c, e), n in combinations.items()
            ),
            "chainsaw_analyse_evtx_coverage",
            dump_result.argv if dump_result else [],
        )
        handle = save_analysis_rows(
            ctx,
            data,
            "chainsaw_analyse_evtx",
            result.argv,
            commands=[result.argv] + ([dump_result.argv] if dump_result else []),
        )
        response = {
            "handle": handle,
            "coverage_handle": coverage_handle,
            "files": len(data),
            "records": records,
            "by_channel": dict(totals.most_common(100)),
            "by_channel_distinct": len(totals),
            "by_provider": dict(providers.most_common(100)),
            "by_provider_distinct": len(providers),
            "top_event_ids": [
                {"channel_event": k, "count": v} for k, v in event_ids.most_common(40)
            ],
            "missing_metadata": missing,
            "coverage_status": "incomplete"
            if coverage_error or observed != records
            else "observed",
            "per_file": data[:10],
            "per_file_total": len(data),
            "diagnostics": diagnostics,
            "chainsaw_messages": diagnostics.pop("messages"),
            "duration_seconds": result.duration_seconds
            + (dump_result.duration_seconds if dump_result else 0),
            "note": (
                "Missing metadata is not evidence of corruption. Counts describe decoded records; "
                "skipped counts are unknown unless explicitly reported. Page handle for files "
                "and coverage_handle for provider/channel/event-ID combinations."
            ),
        }
        return bounded_analysis_response(response, "per_file", len(data))

    TOOLS = ("chainsaw_status", "chainsaw_list_evidence", "chainsaw_analyse_evtx")


def _metadata_value(value: Any) -> str | None:
    if isinstance(value, dict):
        value = value.get("#text", value.get("Value"))
    if value is None or value == "":
        return None
    return str(value)


def save_analysis_rows(
    ctx: ToolContext,
    rows: Iterable[dict[str, Any]],
    tool: str,
    argv: list[str],
    *,
    commands: list[list[str]] | None = None,
) -> str:
    handle, path = ctx.store.reserve()
    try:
        with path.open("w", encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row, ensure_ascii=True) + "\n")
        ctx.store.commit(handle, tool=tool, argv=argv, inputs={}, commands=commands)
        return handle
    finally:
        ctx.store.abort(handle)


def analysis_diagnostics(
    ctx: ToolContext, messages: list[str], argv: list[str], tool: str
) -> dict[str, Any]:
    """Report observed diagnostics, not fabricated completeness or skipped counts."""
    messages = ctx.redact(messages)
    warning = re.compile(r"^\s*(?:\[!\]|\[x\]|warn(?:ing)?\b|error\b)", re.I)
    warnings = [m for m in messages if warning.search(m)]
    incomplete = any(
        re.search(r"skip|fail|error|unable|unreadable|incomplete", m, re.I) for m in warnings
    )
    handle = save_analysis_rows(
        ctx, ({"message": m} for m in messages), tool + "_diagnostics", argv
    )
    preview = []
    for message in messages[:20]:
        preview.append(message.encode("utf-8")[:1000].decode("utf-8", errors="ignore"))
        if len(dumps(preview).encode("utf-8")) > 16_000:
            preview.pop()
            break
    return {
        "parse_status": "incomplete" if incomplete else "unknown",
        "skipped_files": None,
        "skipped_records": None,
        "message_count": len(messages),
        "warning_count": len(warnings),
        "messages": preview,
        "messages_truncated": preview != messages,
        "handle": handle,
        "note": (
            "Successful exit does not establish parse completeness; skipped counts are not "
            "reported by this interface."
        ),
    }


def bounded_analysis_response(data: dict[str, Any], preview_key: str, total: int) -> str:
    """Bound serialized bytes, keeping full details under the returned handles."""
    budget = 128 * 1024
    data["response_budget_bytes"] = budget
    data["truncated"] = len(data[preview_key]) < total
    while True:
        data["returned"] = len(data[preview_key])
        data["next_offset"] = data["returned"] if data["returned"] < total else None
        annotate_delivery(
            data,
            truncated=data["truncated"],
            reason="preview_or_byte_limit" if data["truncated"] else None,
        )
        encoded = dumps(data)
        if len(encoded.encode("utf-8")) <= budget:
            return encoded
        data["truncated"] = True
        if data[preview_key]:
            data[preview_key].pop()
            continue
        # Untrusted channel names and diagnostics can also be arbitrarily large.
        candidates = [
            k for k, v in data.items() if isinstance(v, (list, dict)) and v and k != "diagnostics"
        ]
        if not candidates:
            raise ValueError("Analysis response metadata exceeds response budget")
        key = max(candidates, key=lambda k: len(dumps(data[k])))
        data.setdefault("summary_omitted_fields", []).append(key)
        data[key] = {} if isinstance(data[key], dict) else []
