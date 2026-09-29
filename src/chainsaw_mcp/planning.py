"""Plan through existing tool validation and stop at the native execution seam."""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, validate_call

from .config import Settings
from .results import ResultMeta
from .runner import Runner, RunResult


class PlannedStep(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tool: Literal[
        "chainsaw_hunt",
        "chainsaw_search",
        "chainsaw_dump",
        "chainsaw_analyse_evtx",
        "chainsaw_analyse_gaps",
        "chainsaw_analyse_shimcache",
        "chainsaw_analyse_srum",
    ]
    arguments: dict[str, Any] = Field(description="Parameters accepted by the selected tool.")


class _CommandReady(Exception):
    def __init__(self, argv: list[str]) -> None:
        self.argv = argv


class _PlanningRunner(Runner):
    def run(self, args: list[str], *, cwd: Path | None = None) -> RunResult:
        raise _CommandReady(self.command(args))


def plan(settings: Settings, steps: list[PlannedStep]) -> list[ResultMeta]:
    # Imports here avoid coupling the execution modules to planning or its runner.
    from .tools._common import ToolContext
    from .tools.analyse import AnalyseTools
    from .tools.evidence import EvidenceTools
    from .tools.hunt import HuntTools

    ctx = ToolContext(settings)
    ctx.runner = _PlanningRunner(
        settings.binary, timeout=settings.timeout, threads=settings.threads
    )
    methods = {
        name: getattr(group, name)
        for group in (HuntTools(ctx), EvidenceTools(ctx), AnalyseTools(ctx))
        for name in group.TOOLS
    }
    results = []
    for i, step in enumerate(steps, 1):
        try:
            validate_call(methods[step.tool])(**step.arguments)
        except _CommandReady as ready:
            results.append(
                ResultMeta(
                    handle=f"plan_{i:03d}",
                    tool=step.tool,
                    created=time.time(),
                    count=0,
                    argv=ready.argv,
                    inputs=step.arguments,
                    format="csv" if step.tool.endswith("shimcache") else "txt",
                )
            )
        else:
            raise ValueError("This operation did not produce a native command")
    return results
