"""Rule catalog tools: browse, read, lint, and author detection rules."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Annotated

from pydantic import Field

from ..rules import KINDS, LEVELS, SIGMA_COLLECTIONS, mapping_summary
from ._common import ToolContext, check_choice, dumps

# Linting a single file prints an empty path ("[!] : missing field ..."); a directory
# prints the offending file. Both forms are accepted.
_LINT_LINE = re.compile(r"^\[!\] (?P<file>[^:]*): (?P<message>.+)$")
_LINT_TOTAL = re.compile(r"Validated (?P<ok>\d+) detection rules out of (?P<total>\d+)")


def _relative_problem_path(raw: str, base: Path, base_rel: str) -> str:
    """Express a lint problem path relative to the linted rule root.

    Chainsaw prints the path it was given (or a child of it). Return the path relative to
    the kind's root so clients never see server-absolute filesystem locations.
    """
    if not raw.strip():
        return base_rel
    reported = Path(raw.strip())
    root = base if base.is_dir() else base.parent
    root_rel = base_rel if base.is_dir() else str(Path(base_rel).parent)
    try:
        inner = reported.resolve().relative_to(root.resolve())
    except (OSError, ValueError):
        return reported.name
    prefix = "" if root_rel in ("", ".") else root_rel.rstrip("/") + "/"
    return prefix + inner.as_posix()


class RuleTools:
    def __init__(self, ctx: ToolContext) -> None:
        self.ctx = ctx

    def chainsaw_rule_stats(self) -> str:
        """Count installed Chainsaw, Sigma and custom rules by level and status, plus mappings.

        Also lists the Sigma collections present; pass those names to chainsaw_hunt's
        sigma_collections when you want threat-hunting or emerging-threat rules included.
        """
        stats = self.ctx.catalog.stats()
        stats["sigma_collection_names"] = list(SIGMA_COLLECTIONS)
        return dumps(stats)

    def chainsaw_search_rules(
        self,
        query: Annotated[
            str, Field(description="Words matched against title, description, tags, path, id.")
        ] = "",
        kinds: Annotated[
            list[str] | None,
            Field(description="Restrict to rule kinds: chainsaw, sigma, custom. Default all."),
        ] = None,
        level: Annotated[
            str | None, Field(description="critical, high, medium, low or info.")
        ] = None,
        status: Annotated[
            str | None, Field(description="stable, experimental, test or deprecated.")
        ] = None,
        tag: Annotated[
            str | None, Field(description="Substring of an ATT&CK tag, e.g. t1003 or credential")
        ] = None,
        logsource: Annotated[
            str | None,
            Field(description="Substring of Sigma logsource values, e.g. process_creation."),
        ] = None,
        path_prefix: Annotated[
            str | None,
            Field(
                description="Rule path prefix, e.g. rules/windows/powershell or evtx/persistence"
            ),
        ] = None,
        limit: Annotated[int, Field(ge=1, le=200, description="Rules per page.")] = 50,
        offset: Annotated[int, Field(ge=0, description="Page start.")] = 0,
    ) -> str:
        """Find detection rules by keyword, ATT&CK tag, level, status or logsource.

        Use it to explain a detection name from a hunt, to check coverage for a technique,
        or to pick a sub-tree for a focused hunt. Returns rule URIs readable as resources.
        """
        for k in kinds or []:
            check_choice(k, KINDS, "kinds")
        return dumps(
            self.ctx.catalog.search(
                query,
                kinds=[k.lower() for k in kinds] if kinds else None,
                level=check_choice(level, LEVELS, "level"),
                status=status,
                tag=tag,
                logsource=logsource,
                path_prefix=path_prefix,
                limit=limit,
                offset=offset,
            )
        )

    def chainsaw_get_rule(
        self,
        kind: Annotated[str, Field(description="chainsaw, sigma or custom.")],
        path: Annotated[
            str,
            Field(
                description=(
                    "Rule path relative to that kind's root, e.g. "
                    "rules/windows/process_creation/proc_creation_win_lsass_dump.yml or "
                    "evtx/credential_access. Directories return their children."
                )
            ),
        ],
    ) -> str:
        """Read one rule's YAML and parsed summary, or list a rule directory."""
        return dumps(self.ctx.catalog.read(check_choice(kind, KINDS, "kind") or "", path))

    def chainsaw_get_mapping(
        self,
        name: Annotated[
            str | None,
            Field(description="Mapping file name. Omit for the effective hunt default."),
        ] = None,
        include_yaml: Annotated[bool, Field(description="Include the full YAML text.")] = False,
    ) -> str:
        """Describe a Sigma-to-event-log mapping file: groups, filters, field translations.

        Mappings decide which Sigma logsources apply to which Windows events. Read this
        when a Sigma rule you expect is not firing.
        """
        path = self.ctx.catalog.mapping(name)
        data = mapping_summary(path)
        if include_yaml:
            data["yaml"] = path.read_text(encoding="utf-8", errors="replace")
        return dumps(data)

    def chainsaw_lint_rules(
        self,
        kind: Annotated[str, Field(description="chainsaw, sigma or custom.")] = "custom",
        path: Annotated[
            str, Field(description="File or directory relative to the kind's root; '.' for all.")
        ] = ".",
        tau: Annotated[bool, Field(description="Show the compiled tau logic per rule.")] = False,
    ) -> str:
        """Validate rules with `chainsaw lint` and report which files fail to load and why.

        Run it after chainsaw_save_rule, or on a Sigma sub-tree to see unsupported modifiers.
        """
        ctx = self.ctx
        chosen = check_choice(kind, KINDS, "kind") or "custom"
        ref = ctx.catalog.resolve(chosen, path)
        lint_kind = "sigma" if chosen == "sigma" else "chainsaw"
        args = ["lint", "--kind", lint_kind]
        if tau:
            args.append("--tau")
        result = ctx.runner.run(args + ["--", str(ref.path)])
        problems = []
        validated = total = None
        for line in result.messages:
            if m := _LINT_LINE.match(line):
                problems.append(
                    {
                        "file": _relative_problem_path(m.group("file"), ref.path, ref.relpath),
                        "message": m.group("message"),
                    }
                )
            elif m := _LINT_TOTAL.search(line):
                validated, total = int(m.group("ok")), int(m.group("total"))
        return dumps(
            {
                "kind": chosen,
                "path": ref.relpath,
                "validated": validated,
                "total": total,
                "problems": problems,
                "ok": bool(total) and validated == total,
                "tau_logic": result.stdout if tau else None,
                "duration_seconds": result.duration_seconds,
            }
        )

    def chainsaw_save_rule(
        self,
        name: Annotated[
            str,
            Field(
                description="File name without directories, e.g. suspicious_rdp_from_workstation"
            ),
        ],
        yaml_text: Annotated[
            str,
            Field(
                description=(
                    "Complete Chainsaw rule YAML with title, group, description, authors, kind, "
                    "level, status, timestamp, fields and filter. See the chainsaw://docs/"
                    "rule-format resource."
                )
            ),
        ],
        overwrite: Annotated[bool, Field(description="Replace an existing custom rule.")] = False,
        lint: Annotated[bool, Field(description="Run chainsaw lint on the saved file.")] = True,
    ) -> str:
        """Save an analyst-authored Chainsaw rule into the custom rules directory.

        Saved rules are hunted with extra_rules=['custom']. The file is linted before the
        result is returned; a failing lint still leaves the file in place so it can be fixed
        with another save using overwrite=true.
        """
        ctx = self.ctx
        target = ctx.catalog.save_custom_rule(name, yaml_text, overwrite=overwrite)
        out = {
            "saved": str(target),
            "kind": "custom",
            "path": target.name,
            "uri": f"chainsaw://rules/custom/{target.name}",
            "hunt_with": {"extra_rules": ["custom"]},
        }
        if lint:
            import json

            out["lint"] = json.loads(self.chainsaw_lint_rules("custom", target.name))
        return dumps(out)

    def chainsaw_delete_rule(
        self, name: Annotated[str, Field(description="Custom rule file name.")]
    ) -> str:
        """Delete a custom rule. Bundled Chainsaw and Sigma rules cannot be deleted."""
        return dumps({"name": name, "deleted": self.ctx.catalog.delete_custom_rule(name)})

    TOOLS = (
        "chainsaw_rule_stats",
        "chainsaw_search_rules",
        "chainsaw_get_rule",
        "chainsaw_get_mapping",
        "chainsaw_lint_rules",
        "chainsaw_save_rule",
        "chainsaw_delete_rule",
    )
