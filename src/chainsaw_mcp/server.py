"""MCP server assembly: tools, resources and prompts for Chainsaw."""

from __future__ import annotations

import functools
import json
from collections.abc import Callable
from typing import Any, Protocol

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp.types import ToolAnnotations

from . import __version__
from .config import Settings, load_settings
from .paths import PathError
from .results import ResultError
from .rules import KINDS, RuleError
from .runner import ChainsawError
from .tools import (
    AnalyseTools,
    CustodyTools,
    EvidenceTools,
    HuntTools,
    JevTools,
    ReproductionTools,
    ResultTools,
    RuleTools,
    UploadTools,
)
from .tools._common import ToolContext

INSTRUCTIONS = """\
Chainsaw hunts Windows forensic artefacts (EVTX event logs, MFT, shimcache, SRUM, registry
hives) with Sigma and Chainsaw detection rules.

Remote clients can upload files with chainsaw_upload_begin, chainsaw_upload_chunk, then
chainsaw_upload_finish. Uploads require a trusted Ed25519 signature of the file manifest.
Use HTTPS for remote connections and the verified path returned by finish. Mounted evidence is
read-only; incomplete uploads are not evidence. chainsaw_plan generates validated native
commands before execution when a planned investigation is wanted.

For custody checks, chainsaw_evidence_manifest creates a signed full-directory inventory;
chainsaw_evidence_validate compares the same scope or a relocated copy and signs a receipt.
Use around evidence copies, handoffs or analysis when integrity records are needed. Preserve
both artefact and signature handles before expiry. Operator/handoff fields are declarations;
these observations do not establish acquisition provenance or a complete custody history.

Recommended flow for an event-log triage:
1. chainsaw_status, then chainsaw_list_evidence to scope the evidence.
2. chainsaw_analyse_evtx for provider/channel/event-ID coverage; page its detail handles.
   Gaps require continuity and corroboration, particularly for curated/filtered samples.
3. chainsaw_hunt on the chosen paths. Read the returned summary, not raw rows.
4. chainsaw_result_summary(group_by=...) and chainsaw_result_page(where=...) to pivot on
   hosts, users, processes and time windows. chainsaw_result_fields lists usable paths.
5. chainsaw_search with tau expressions to pull surrounding events for a pivot value.
6. chainsaw_search_rules / chainsaw_get_rule to explain detections; chainsaw_save_rule to
   capture a new detection and chainsaw_lint_rules to validate it.
7. chainsaw_reproduce(handles=[...]) to document recorded commands and download a replay
   script and input manifest for the investigation before result handles expire.
   Use chainsaw_result_manifest and the pinned server public key to verify downloaded files.

Large outputs never come back inline. Hunts, searches and dumps return a result handle
(res_<hex>) that stays valid across calls; page or aggregate it. Evidence paths are
restricted to the configured evidence roots and are never modified.

Optional chainsaw_jev_triage sends selected result rows to TypeSafe's external Jev API.
Use only when external assessment is wanted and enabled in chainsaw_status. Preview rows
and choose fields before sending; scores are advisory and uncertain answers need review.
"""

# Tools that only read evidence or stored state.
_READ_ONLY = {
    "chainsaw_status",
    "chainsaw_list_evidence",
    "chainsaw_rule_stats",
    "chainsaw_search_rules",
    "chainsaw_get_rule",
    "chainsaw_get_mapping",
    "chainsaw_lint_rules",
    "chainsaw_result_page",
    "chainsaw_result_manifest",
    "chainsaw_result_chunk",
    "chainsaw_result_events",
    "chainsaw_result_summary",
    "chainsaw_result_fields",
    "chainsaw_result_export",
    "chainsaw_result_list",
}
# Tools that create new server-side state (result handles, rule files) but destroy nothing.
_ADDITIVE = {
    "chainsaw_evidence_manifest",
    "chainsaw_evidence_validate",
    "chainsaw_plan",
    "chainsaw_upload_begin",
    "chainsaw_upload_chunk",
    "chainsaw_reproduce",
    "chainsaw_hunt",
    "chainsaw_search",
    "chainsaw_dump",
    "chainsaw_process_lineage",
    "chainsaw_analyse_evtx",
    "chainsaw_analyse_gaps",
    "chainsaw_analyse_shimcache",
    "chainsaw_analyse_srum",
}
_TITLES = {
    "chainsaw_evidence_manifest": "Chainsaw: create signed evidence manifest",
    "chainsaw_evidence_validate": "Chainsaw: validate evidence against a signed manifest",
    "chainsaw_plan": "Chainsaw: plan investigation commands",
    "chainsaw_upload_begin": "Chainsaw: begin evidence upload",
    "chainsaw_upload_chunk": "Chainsaw: upload evidence chunk",
    "chainsaw_upload_finish": "Chainsaw: finish or resume evidence upload",
    "chainsaw_reproduce": "Chainsaw: reproduce investigation commands",
    "chainsaw_status": "Chainsaw: server status",
    "chainsaw_list_evidence": "Chainsaw: list evidence",
    "chainsaw_analyse_evtx": "Chainsaw: EVTX overview",
    "chainsaw_analyse_gaps": "Chainsaw: log gap analysis",
    "chainsaw_analyse_shimcache": "Chainsaw: shimcache timeline",
    "chainsaw_analyse_srum": "Chainsaw: SRUM analysis",
    "chainsaw_hunt": "Chainsaw: hunt with detection rules",
    "chainsaw_jev_triage": "Chainsaw: assess results with Jev",
    "chainsaw_search": "Chainsaw: search events",
    "chainsaw_dump": "Chainsaw: dump records",
    "chainsaw_result_page": "Chainsaw: page a result",
    "chainsaw_result_manifest": "Chainsaw: sign a result download manifest",
    "chainsaw_result_chunk": "Chainsaw: read result text chunks",
    "chainsaw_result_events": "Chainsaw: group detections by event",
    "chainsaw_process_lineage": "Chainsaw: pivot process lineage",
    "chainsaw_result_summary": "Chainsaw: summarise a result",
    "chainsaw_result_fields": "Chainsaw: result fields",
    "chainsaw_result_export": "Chainsaw: export a result",
    "chainsaw_result_list": "Chainsaw: list results",
    "chainsaw_result_delete": "Chainsaw: delete a result",
    "chainsaw_rule_stats": "Chainsaw: rule statistics",
    "chainsaw_search_rules": "Chainsaw: search rules",
    "chainsaw_get_rule": "Chainsaw: read a rule",
    "chainsaw_get_mapping": "Chainsaw: read a mapping",
    "chainsaw_lint_rules": "Chainsaw: lint rules",
    "chainsaw_save_rule": "Chainsaw: save custom rule",
    "chainsaw_delete_rule": "Chainsaw: delete custom rule",
}


def annotations_for(name: str) -> ToolAnnotations:
    if name == "chainsaw_jev_triage":
        # Nothing local changes, but evidence leaves the host and API usage is consumed.
        return ToolAnnotations(
            title=_TITLES[name],
            read_only_hint=False,
            destructive_hint=False,
            idempotent_hint=False,
            open_world_hint=True,
        )
    read_only = name in _READ_ONLY
    return ToolAnnotations(
        title=_TITLES.get(name, name),
        read_only_hint=read_only,
        destructive_hint=not read_only and name not in _ADDITIVE,
        idempotent_hint=read_only or name.endswith("_delete_rule") or name.endswith("_delete"),
        open_world_hint=False,
    )


# Errors that carry a message meant for the calling agent.
USER_ERRORS = (ValueError, PathError, ResultError, RuleError, ChainsawError, FileNotFoundError)


def _surface_errors(fn: Callable[..., str]) -> Callable[..., str]:
    """Turn validation and chainsaw failures into ToolError so the text reaches the client."""

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> str:
        try:
            return fn(*args, **kwargs)
        except ToolError:
            raise
        except USER_ERRORS as exc:
            raise ToolError(str(exc)) from exc

    return wrapper


class ToolGroup(Protocol):
    """A tool class exposing its public MCP tool names."""

    @property
    def TOOLS(self) -> tuple[str, ...]: ...  # noqa: N802


def collect_tools(ctx: ToolContext) -> dict[str, Callable[..., str]]:
    groups: list[ToolGroup] = [
        EvidenceTools(ctx),
        CustodyTools(ctx),
        HuntTools(ctx),
        AnalyseTools(ctx),
        ResultTools(ctx),
        RuleTools(ctx),
        JevTools(ctx),
        ReproductionTools(ctx),
        UploadTools(ctx),
    ]
    tools: dict[str, Callable[..., str]] = {}
    for group in groups:
        for name in group.TOOLS:
            tools[name] = _surface_errors(getattr(group, name))
    return dict(sorted(tools.items()))


def build_server(settings: Settings | None = None) -> MCPServer:
    settings = settings or load_settings()
    ctx = ToolContext(settings)
    server = MCPServer("chainsaw-mcp", version=__version__, instructions=INSTRUCTIONS)
    for name, fn in collect_tools(ctx).items():
        server.add_tool(
            fn,
            name=name,
            title=_TITLES.get(name),
            annotations=annotations_for(name),
            structured_output=False,
        )
    _register_resources(server, ctx)
    _register_prompts(server, ctx)
    server._chainsaw_ctx = ctx  # type: ignore[attr-defined]  # handy for tests
    return server


# -- resources ----------------------------------------------------------------------------

RULE_FORMAT_DOC = """\
# Chainsaw rule format

```yaml
title: Suspicious Service Installed From Temp
group: Persistence            # groups appear as separate tables/`group` values in hunt output
description: Service binary path under a temp directory
authors:
  - analyst
kind: evtx                    # evtx | mft | json | jsonl | xml | esedb | hve | shimcache | srum
level: high                   # critical | high | medium | low | info
status: stable                # stable | experimental
timestamp: Event.System.TimeCreated_attributes.SystemTime
fields:                       # columns shown in the detection table
  - name: Event ID
    to: Event.System.EventID
  - name: Service Name
    to: Event.EventData.ServiceName
  - name: Image Path
    to: Event.EventData.ImagePath
filter:                       # tau logic
  condition: service and temp
  service:
    Event.System.EventID: 7045
  temp:
    Event.EventData.ImagePath:
      - i*\\\\temp\\\\*
      - i*\\\\appdata\\\\local\\\\temp\\\\*
```

Tau operators inside a value: `i` prefix = case-insensitive, `*` wildcard, `?` single char,
`=`/`>`/`<`/`>=`/`<=` numeric, `not`, `all of`, `1 of`. Conditions combine keys with
`and`, `or`, `not`, parentheses. Field paths are dotted JSON paths into the parsed document
(`Event.EventData.CommandLine`). Use chainsaw_lint_rules after saving.
"""


def _register_resources(server: MCPServer, ctx: ToolContext) -> None:
    catalog = ctx.catalog

    @server.resource(
        "chainsaw://rules/{kind}/{+path}",
        name="chainsaw-rule",
        description=(
            "Detection rule YAML by kind (chainsaw|sigma|custom) and relative path; "
            "directory paths list their children as JSON."
        ),
        mime_type="text/plain",
    )
    def rule_resource(kind: str, path: str) -> str:
        if kind not in KINDS:
            raise RuleError(f"kind must be one of {', '.join(KINDS)}")
        data = catalog.read(kind, path)
        if "yaml" in data:
            return data["yaml"]
        return json.dumps(data, indent=2, default=str)

    @server.resource(
        "chainsaw://mappings/{name}",
        name="chainsaw-mapping",
        description="Sigma-to-event-log mapping YAML (e.g. sigma-event-logs-all.yml).",
        mime_type="text/plain",
    )
    def mapping_resource(name: str) -> str:
        return catalog.mapping(name).read_text(encoding="utf-8", errors="replace")

    @server.resource(
        "chainsaw://docs/rule-format",
        name="chainsaw-rule-format",
        description="How to write a Chainsaw detection rule (tau syntax, fields, kinds).",
        mime_type="text/markdown",
    )
    def rule_format_doc() -> str:
        return RULE_FORMAT_DOC

    @server.resource(
        "chainsaw://results/{handle}",
        name="chainsaw-result",
        description=(
            "Raw stored result (JSONL/CSV/text) for a handle from a hunt or analysis. "
            "Capped at 2 MB; chainsaw_result_export reports bytes and truncation."
        ),
        mime_type="text/plain",
    )
    def result_resource(handle: str) -> str:
        return ctx.store.text(handle)

    @server.resource(
        "chainsaw://config",
        name="chainsaw-config",
        description="Effective server configuration (paths, limits, Jev settings).",
        mime_type="application/json",
    )
    def config_resource() -> str:
        return json.dumps(ctx.settings.describe(), indent=2, default=str)


# -- prompts ------------------------------------------------------------------------------


def _register_prompts(server: MCPServer, ctx: ToolContext) -> None:
    @server.prompt(
        name="triage_evtx",
        description="Structured first-pass triage of Windows event logs with Chainsaw.",
    )
    def triage_evtx(
        path: str, focus: str = "credential access, lateral movement, persistence, defence evasion"
    ) -> str:
        return f"""\
You are running a first-pass forensic triage of Windows event logs at `{path}` with the
chainsaw MCP tools. Focus areas: {focus}.

1. chainsaw_list_evidence("{path}") and chainsaw_analyse_evtx to see channels, event IDs,
   hosts and record counts. Note whether Sysmon and PowerShell logging are present.
2. chainsaw_analyse_gaps on the same path. Establish continuity before interpreting gaps;
   curated/filtered samples are independent scenarios, not proof of deletion. Security 1102 /
   System 104 establish clearing, not malicious intent. Preserve source-file identities.
3. chainsaw_hunt(paths=["{path}"]). Do not page all rows. Use the summary's by_level,
   by_rule, by_computer, by_hour.
4. For every critical/high rule with few hits, chainsaw_result_page(where={{"rule": ...}},
   fields=[...]) to read the evidence. For noisy rules, chainsaw_result_summary(group_by=...)
   on the user, process or source-IP field to find outliers.
5. Pivot with chainsaw_search (tau expressions) around the interesting hosts, users, LogonIds
   or process GUIDs to reconstruct the sequence.
6. Explain each retained finding with chainsaw_get_rule and its ATT&CK tags.

Report: timeline of attacker activity (UTC), affected hosts and accounts, techniques with
ATT&CK IDs, confidence per finding, evidence pointers (file, EventRecordID), false positives
you discarded and why, and recommended next collections.
"""

    @server.prompt(
        name="pivot_on_indicator",
        description="Investigate one indicator (user, host, IP, process, LogonId) across evidence.",
    )
    def pivot_on_indicator(indicator: str, path: str) -> str:
        return f"""\
Investigate the indicator `{indicator}` across the evidence at `{path}`.

- chainsaw_search(paths=["{path}"], patterns=["{indicator}"]) for a broad match, then read
  the summary (hosts, channels, event IDs, hours).
- chainsaw_result_fields on that handle, then chainsaw_result_summary(group_by=[...]) on the
  fields that co-occur with the indicator (TargetUserName, IpAddress, LogonId, ParentImage).
- Narrow with tau expressions such as
  'Event.EventData.TargetUserName: i{indicator}' or 'Event.EventData.IpAddress: {indicator}'.
- Bound with from_time/to_time once you know the active window; check what happened just
  before and after with chainsaw_search on the same window without the indicator filter.

Produce a chronological account of what the indicator did, which accounts and hosts it
touched, and which detections (chainsaw_hunt on the narrowed window) relate to it.
"""

    @server.prompt(
        name="author_rule",
        description="Write, save and validate a Chainsaw detection rule from an observed pattern.",
    )
    def author_rule(behaviour: str, sample_handle: str = "") -> str:
        sample = (
            f"Use chainsaw_result_page('{sample_handle}') and chainsaw_result_fields to see the "
            "exact field names and values to match."
            if sample_handle
            else "If you have a result handle with an example event, inspect it with "
            "chainsaw_result_fields to get exact field paths."
        )
        return f"""\
Write a Chainsaw detection rule for: {behaviour}.

- Read the resource chainsaw://docs/rule-format for the schema and tau syntax.
- chainsaw_search_rules(query=...) to check for an existing Sigma or Chainsaw rule; prefer
  citing it over duplicating it.
- {sample}
- Save with chainsaw_save_rule(name, yaml_text). Fix any lint problems and save again with
  overwrite=true.
- Test with chainsaw_hunt(paths=[...], sigma=false, chainsaw_rules=false,
  extra_rules=["custom"]) against evidence that should and should not match.

Return the final YAML, the hunt results on positive and negative evidence, and the ATT&CK
mapping.
"""


__all__ = ["build_server", "collect_tools", "annotations_for", "INSTRUCTIONS"]
