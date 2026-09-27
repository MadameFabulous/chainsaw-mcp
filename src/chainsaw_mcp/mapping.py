"""Compile the known upstream default into disjoint, provider-aware mapping groups.

Chainsaw 2.16.5's ``Group.filter`` accepts Tau identifier expressions (including
``not(Field)``), not Sigma condition blocks. ``extensions.preconditions`` apply
per rule, independently of the group. Keep them intact while routing field aliases.
"""

from __future__ import annotations

import copy
import hashlib
import os
import tempfile
from pathlib import Path
from typing import Any

import yaml

STOCK_MAPPING_SHA256 = "7a8d08a56665520d9db22fa5399079571ba32f640e4ddbd61a824168b5061b71"
SECURITY_PROVIDER = "Microsoft-Windows-Security-Auditing"


def provider_aware_default(source: Path, cache_dir: Path) -> Path:
    """Repair only a byte-identical known stock mapping; preserve custom sources.

    Cache complete, content-addressed files atomically. No vendor writes, temporary
    hunt lifetime races, or unbounded regeneration on every catalog lookup.
    """
    content = source.read_bytes()
    if hashlib.sha256(content).hexdigest() != STOCK_MAPPING_SHA256:
        return source
    doc: dict[str, Any] = yaml.safe_load(content)
    group = doc["groups"][0]
    other = copy.deepcopy(group)
    other["filter"] = {"not(Provider)": SECURITY_PROVIDER}
    security = copy.deepcopy(group)
    security["name"] = "Sigma Security Process Creation"
    security["filter"] = {"Provider": SECURITY_PROVIDER, "int(EventID)": 4688}
    for field in security["fields"]:
        if field.get("from") == "Image":
            field["to"] = "Event.EventData.NewProcessName"
    rest = copy.deepcopy(group)
    rest["name"] = "Sigma Security Other Events"
    # Tau numeric equality accepts numeric-string EventIDs too (verified on binary).
    rest["filter"] = {"Provider": SECURITY_PROVIDER, "not(EventID)": 4688}
    doc["name"] = "Chainsaw MCP provider-aware Event Logs mapping"
    doc["groups"] = [other, security, rest]
    rendered = yaml.safe_dump(doc, sort_keys=False).encode("utf-8")
    digest = hashlib.sha256(rendered).hexdigest()
    target = cache_dir / digest / "sigma-event-logs-provider-aware.yml"
    if target.is_file() and target.read_bytes() == rendered:
        return target
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=target.parent, suffix=".tmp", delete=False) as fh:
            temporary = Path(fh.name)
            fh.write(rendered)
        os.replace(temporary, target)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return target
