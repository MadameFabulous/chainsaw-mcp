"""Regenerate docs/tools.md from the live tool schema.

uv run python scripts/gen-tool-docs.py > docs/tools.md
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import anyio
from mcp.client import Client

from chainsaw_mcp.config import load_settings
from chainsaw_mcp.server import build_server

FIELDS_DOC = (Path(__file__).resolve().parents[1] / "docs" / "_result-handles.md").read_text()


def _type(prop: dict) -> str:
    typ = prop.get("type")
    if not typ and "anyOf" in prop:
        parts = []
        for alt in prop["anyOf"]:
            t = alt.get("type", "?")
            parts.append(t + "[]" if t == "array" else t)
        return " or ".join(parts)
    if typ == "array":
        return prop.get("items", {}).get("type", "any") + "[]"
    return str(typ)


async def render() -> str:
    # A private home per run: a fixed /tmp path breaks once another user has created it.
    with tempfile.TemporaryDirectory(prefix="chainsaw-mcp-docs-") as home:
        settings = load_settings({"CHAINSAW_HOME": home, "CHAINSAW_EVIDENCE_ROOTS": home})
        out: list[str] = []
        async with Client(build_server(settings)) as client:
            tools = (await client.list_tools()).tools
            templates = (await client.list_resource_templates()).resource_templates
            resources = (await client.list_resources()).resources
            prompts = (await client.list_prompts()).prompts
    out.append("# Tool reference\n")
    out.append(
        "Generated from the live server schema by `scripts/gen-tool-docs.py`. All tools "
        "return a JSON text block; errors come back as `isError` results with a readable "
        "message.\n"
    )
    out.append("| Tool | Read-only | Destructive | Purpose |\n|---|---|---|---|")
    for t in tools:
        a = t.annotations
        first = t.description.strip().splitlines()[0]
        ro = "yes" if a.read_only_hint else "no"
        de = "yes" if a.destructive_hint else "no"
        out.append(f"| `{t.name}` | {ro} | {de} | {first} |")
    out.append("")
    for t in tools:
        out.append(f"## `{t.name}`\n")
        out.append(t.description.strip() + "\n")
        props = t.input_schema.get("properties", {})
        required = set(t.input_schema.get("required", []))
        if not props:
            out.append("No parameters.\n")
            continue
        out.append("| Parameter | Type | Default | Description |\n|---|---|---|---|")
        for name, prop in props.items():
            default = "required" if name in required else json.dumps(prop.get("default"))
            desc = (prop.get("description") or "").replace("|", "\\|").replace("\n", " ")
            limits = [
                f"{k}={v}"
                for k, v in prop.items()
                if k in ("minimum", "maximum", "minLength", "maxLength")
            ]
            if limits:
                desc += " (" + ", ".join(limits) + ")"
            out.append(f"| `{name}` | {_type(prop)} | {default} | {desc} |")
        out.append("")
    out.append("## Resources\n")
    for r in resources:
        out.append(f"- `{r.uri}`: {r.description}")
    for t in templates:
        out.append(f"- `{t.uri_template}`: {t.description}")
    out.append("\n## Prompts\n")
    for p in prompts:
        args = ", ".join(
            f"`{a.name}`" + ("" if a.required else " (optional)") for a in (p.arguments or [])
        )
        out.append(f"- `{p.name}`({args}): {p.description}")
    out.append("\n" + FIELDS_DOC)
    return "\n".join(out).rstrip()


if __name__ == "__main__":
    print(anyio.run(render))
