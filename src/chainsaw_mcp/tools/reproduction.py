"""Investigation command documentation, downloadable entirely through MCP."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Annotated

from pydantic import Field

from .. import CHAINSAW_RELEASE, __version__
from ..planning import PlannedStep, plan
from ..reproduction import DERIVED_NOTE, NOTE, Reproduction, checksum_check, fingerprint, json_line
from ..result_budget import bounded_dumps
from ..results import ResultMeta
from ._common import ToolContext


class ReproductionTools:
    def __init__(self, ctx: ToolContext) -> None:
        self.ctx = ctx

    def chainsaw_reproduce(
        self,
        handles: Annotated[
            list[str],
            Field(
                min_length=1,
                max_length=64,
                description=(
                    "Investigation result handles in replay order. Use primary hunt, search, dump "
                    "or analysis handles; duplicate handles are removed."
                ),
            ),
        ],
        hash_inputs: Annotated[
            bool,
            Field(
                description=(
                    "Hash evidence and rules now and add replay checks. May read large datasets; "
                    "these are export-time hashes, not historical acquisition hashes."
                )
            ),
        ] = True,
        redact_paths: Annotated[
            bool,
            Field(description="Export a labelled derivative with server paths replaced by roots."),
        ] = False,
    ) -> str:
        """Export recorded Chainsaw commands as a replay script and an investigation manifest.

        Does not rerun the investigation. Preserves filters, time windows and all recorded
        lineage queries; snapshots mappings, quotes shell arguments, and writes replay output
        to a new directory. Download script_handle and manifest_handle with
        chainsaw_result_chunk (follow next_byte_offset) or chainsaw_result_export.
        Commands reproduce native output; MCP aggregation and lineage filtering are documented
        separately. Hashes describe inputs at export time and cannot prove past input identity.
        Exports deliberately contain server-absolute binary, evidence-root and result-store
        paths for provenance by default. Set redact_paths=true for a labelled derivative
        requiring explicit replay roots. Content and relative names are not anonymised.
        Response and manifest partial flags identify legacy EVTX handles with missing commands.
        """
        if not 1 <= len(handles) <= 64:
            raise ValueError("Supply 1..64 result handles")
        metas = [self.ctx.store.meta(h) for h in dict.fromkeys(handles)]
        return self._export(
            metas, hash_inputs=hash_inputs, planned=False, redact_paths=redact_paths
        )

    def chainsaw_plan(
        self,
        steps: Annotated[
            list[PlannedStep],
            Field(
                min_length=1,
                max_length=64,
                description="Ordered native investigation steps: tool name and its arguments.",
            ),
        ],
        hash_inputs: Annotated[
            bool,
            Field(
                description="Hash currently mounted/uploaded inputs and check them before replay.",
            ),
        ] = False,
        redact_paths: Annotated[
            bool,
            Field(description="Export a labelled derivative with server paths replaced by roots."),
        ] = False,
    ) -> str:
        """Generate validated Chainsaw commands without executing an investigation.

        Uses the same parameter validation and argument construction as the real tools.
        Input files and rules must already exist on the server. Returns downloadable script
        and manifest handles labelled planned, never executed. EVTX planning covers native
        analyse evtx only; add a dump step for raw events. Lineage requires observed events
        and is supported by chainsaw_reproduce after execution. Like reproduce exports, plans
        contain server-absolute paths by default. Set redact_paths=true for a labelled
        derivative requiring explicit replay roots; content and relative names are retained.
        """
        if not 1 <= len(steps) <= 64:
            raise ValueError("Supply 1..64 planned steps")
        return self._export(
            plan(self.ctx.settings, steps),
            hash_inputs=hash_inputs,
            planned=True,
            redact_paths=redact_paths,
        )

    def _export(
        self, metas: list[ResultMeta], *, hash_inputs: bool, planned: bool, redact_paths: bool
    ) -> str:
        ctx = self.ctx
        replay = Reproduction(ctx.settings, redact_paths=redact_paths)
        partial_handles = [
            {"handle": meta.handle, "reason": "legacy_evtx_command_history_missing"}
            for meta in metas
            if not planned and meta.tool == "chainsaw_analyse_evtx" and not meta.commands
        ]
        partial_by_handle = {row["handle"]: row["reason"] for row in partial_handles}
        path_mode = "redacted" if redact_paths else "verbatim"
        note = (
            (
                "Planned commands only: no investigation was executed. Inputs were validated at "
                "export time; hashes, when requested, describe their current bytes."
            )
            if planned
            else NOTE
        )
        if redact_paths:
            note += (
                " Rebased/redacted derivative: server paths are labelled, not verbatim provenance."
            )
        if partial_handles:
            note += " Partial export: legacy EVTX overview handles lack their full command history."
        for meta in metas:
            replay.add(meta)
        binary = ctx.runner.require()
        binary_info = fingerprint(binary)
        manifest_handle, manifest_path = ctx.store.reserve()
        script_handle, script_path = ctx.store.reserve(".txt")
        published = []
        try:
            checks = []
            with manifest_path.open("w", encoding="utf-8") as stream:
                stream.write(
                    json_line(
                        {
                            "kind": "manifest",
                            "schema_version": 1,
                            "exported_at": datetime.now(UTC).isoformat(),
                            "server_version": __version__,
                            "bundled_chainsaw_release": CHAINSAW_RELEASE,
                            "binary": {
                                "path": "${CHAINSAW_BIN}" if redact_paths else str(binary),
                                **binary_info,
                            },
                            "hash_inputs": hash_inputs,
                            "mode": "planned" if planned else "recorded",
                            "path_mode": path_mode,
                            "partial": bool(partial_handles),
                            "partial_handles": partial_handles,
                            "note": note,
                            "postprocessing": DERIVED_NOTE,
                            "roots": {
                                name: "${" + name + "}" if redact_paths else str(path)
                                for name, path in replay.used.items()
                            },
                        }
                    )
                )
                for meta in [] if planned else metas:
                    stream.write(
                        json_line(
                            {
                                "kind": "result",
                                "handle": meta.handle,
                                "tool": meta.tool,
                                "count": meta.count,
                                "format": meta.format,
                                "partial": meta.handle in partial_by_handle,
                                "partial_reason": partial_by_handle.get(meta.handle),
                                **fingerprint(ctx.store.data_path(meta.handle, "." + meta.format)),
                            }
                        )
                    )
                for command in replay.commands:
                    command["executed"] = not planned
                    if planned and not redact_paths:
                        command["planned_argv"] = command.pop("recorded_argv")
                    stream.write(json_line(command))
                for row in replay.manifest_inputs(hash_inputs):
                    stream.write(json_line(row))
                    if row["sha256"]:
                        checks.append(checksum_check(row))
            script = replay.script(checks, binary_info["sha256"]).replace("# " + NOTE, "# " + note)
            script_path.write_text(script, encoding="utf-8")
            for handle, fmt in ((manifest_handle, "jsonl"), (script_handle, "txt")):
                ctx.store.commit(
                    handle,
                    tool="chainsaw_plan" if planned else "chainsaw_reproduce",
                    argv=[],
                    inputs={"handles": [m.handle for m in metas]},
                    fmt=fmt,
                )
                published.append(handle)
        except BaseException:
            for handle in published:
                ctx.store.delete(handle)
            raise
        finally:
            ctx.store.abort(manifest_handle)
            ctx.store.abort(script_handle)
        return bounded_dumps(
            {
                "script_handle": script_handle,
                "manifest_handle": manifest_handle,
                "commands": len(replay.commands),
                "source_handles": [] if planned else [m.handle for m in metas],
                "mode": "planned" if planned else "recorded",
                "path_mode": path_mode,
                "partial": bool(partial_handles),
                "partial_handles": partial_handles,
                "script_sha256": hashlib.sha256(script.encode("utf-8")).hexdigest(),
                "note": note,
                "postprocessing": DERIVED_NOTE,
                "download": "Use chainsaw_result_chunk until next_byte_offset is null. "
                "Save as reproduce.sh and manifest.jsonl; run sh reproduce.sh with "
                "Chainsaw installed.",
            }
        )

    TOOLS = ("chainsaw_reproduce", "chainsaw_plan")
