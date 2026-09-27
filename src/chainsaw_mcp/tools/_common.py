from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any

from ..config import Settings
from ..paths import PathError, display_path, resolve_under
from ..results import ResultStore
from ..rules import RuleCatalog
from ..runner import Runner

_TS = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}$")
_TZ = re.compile(r"^[A-Za-z][A-Za-z0-9_+\-/]{0,60}$")
_EXT = re.compile(r"^[A-Za-z0-9]{1,12}$")


class ToolContext:
    """Shared dependencies handed to every tool group."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.runner = Runner(settings.binary, timeout=settings.timeout, threads=settings.threads)
        self.store = ResultStore(settings.output_dir)
        self.catalog = RuleCatalog(settings)

    def evidence(self, raw: str) -> str:
        return str(resolve_under(raw, self.settings.evidence_roots, what="evidence path"))

    def evidence_paths(self, paths: list[str]) -> list[str]:
        """Resolve client paths, dropping duplicates and files inside a supplied directory.

        Chainsaw loads every argument, so a file listed next to its own directory would be
        hunted twice and every detection in it reported twice.
        """
        if not paths:
            raise PathError("At least one evidence path is required")
        if len(paths) > 64:
            raise PathError("At most 64 evidence paths per call")
        resolved: list[Path] = []
        for raw in paths:
            path = Path(self.evidence(raw))
            if path not in resolved:
                resolved.append(path)
        directories = [p for p in resolved if p.is_dir()]
        return [str(p) for p in resolved if not any(d != p and d in p.parents for d in directories)]

    def shown(self, path: str) -> str:
        return display_path(Path(path), self.settings.evidence_roots)

    def redact(self, messages: list[str]) -> list[str]:
        """Replace server-absolute locations in chainsaw's messages with stable names.

        Chainsaw echoes the rule and evidence paths it was given; clients only ever see
        root-relative evidence paths elsewhere, so its messages must not differ.
        """
        settings = self.settings
        pairs = [(str(root), root.name) for root in settings.evidence_roots]
        pairs += [
            (str(settings.output_dir), "<results>"),
            (str(settings.custom_rules_dir), "<custom-rules>"),
            (str(settings.mappings_dir), "<mappings>"),
            (str(settings.sigma_dir), "<sigma>"),
            (str(settings.rules_dir), "<rules>"),
            (str(settings.vendor_dir), "<vendor>"),
            (str(settings.home), "<home>"),
        ]
        pairs = [(a, b) for a, b in pairs if a not in ("", "/", ".")]
        pairs.sort(key=lambda pair: -len(pair[0]))
        out = []
        for line in messages:
            for absolute, name in pairs:
                line = line.replace(absolute, name)
            out.append(line)
        return out


def dumps(data: Any) -> str:
    return json.dumps(data, indent=2, default=str)


def check_timestamp(value: str | None, name: str) -> str | None:
    if value is None or value == "":
        return None
    if not _TS.match(value):
        raise ValueError(f"{name} must look like YYYY-MM-DDTHH:MM:SS (UTC unless timezone set)")
    try:
        datetime.strptime(value, "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        raise ValueError(f"{name} is not a valid calendar date and time: {value}") from None
    return value


def check_window(start: str | None, end: str | None) -> None:
    """Reject an empty time window; both values are already validated fixed-width strings."""
    if start and end and start > end:
        raise ValueError(f"from_time {start} is later than to_time {end}")


def check_timezone(value: str | None) -> str | None:
    if not value:
        return None
    if not _TZ.match(value):
        raise ValueError("timezone must be an IANA name such as Europe/London")
    return value


def check_extension(value: str | None) -> str | None:
    if not value:
        return None
    clean = value.lstrip(".")
    if not _EXT.match(clean):
        raise ValueError("extension must be alphanumeric, e.g. evtx")
    return clean


def check_choice(value: str | None, allowed: tuple[str, ...], name: str) -> str | None:
    if not value:
        return None
    low = value.lower()
    if low not in allowed:
        raise ValueError(f"{name} must be one of: {', '.join(allowed)}")
    return low


def check_choices(values: list[str] | None, allowed: tuple[str, ...], name: str) -> list[str]:
    out = []
    for v in values or []:
        chosen = check_choice(v, allowed, name)
        if chosen and chosen not in out:
            out.append(chosen)
    return out


def clamp(value: int, *, low: int, high: int, name: str) -> int:
    if value < low:
        raise ValueError(f"{name} must be >= {low}")
    return min(value, high)
