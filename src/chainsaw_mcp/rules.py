"""Rule catalog: Chainsaw rules, Sigma rules, mappings and analyst-authored custom rules.

Everything here is read-only except :func:`save_custom_rule`, which writes a single
YAML file under the configured custom-rules directory.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .config import DEFAULT_MAPPING, Settings
from .mapping import STOCK_MAPPING_SHA256, provider_aware_default

_Loader = getattr(yaml, "CSafeLoader", yaml.SafeLoader)

RULE_SUFFIXES = (".yml", ".yaml")
SIGMA_COLLECTIONS = (
    "rules",
    "rules-threat-hunting",
    "rules-emerging-threats",
    "rules-dfir",
    "rules-compliance",
)
# Sigma collections that chainsaw's stock mapping is designed for.
SIGMA_DEFAULT_COLLECTIONS = ("rules",)
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,120}$")
# Name under which the repaired stock mapping is addressable; see mapping.py.
DERIVED_MAPPING = "sigma-event-logs-provider-aware.yml"
REQUIRED_RULE_KEYS = (
    "title",
    "group",
    "description",
    "authors",
    "kind",
    "level",
    "status",
    "timestamp",
    "fields",
    "filter",
)
MAX_RULE_BYTES = 65_536
LEVELS = ("critical", "high", "medium", "low", "info")
STATUSES = ("stable", "experimental", "test", "deprecated", "unsupported")
KINDS = ("chainsaw", "sigma", "custom")


class RuleError(ValueError):
    """Bad rule reference or rule content."""


@dataclass(frozen=True)
class RuleRef:
    kind: str  # chainsaw | sigma | custom
    relpath: str  # path relative to that kind's root, always with forward slashes
    path: Path


@dataclass
class RuleSummary:
    kind: str
    relpath: str
    title: str
    level: str | None = None
    status: str | None = None
    id: str | None = None
    description: str = ""
    tags: list[str] = field(default_factory=list)
    logsource: dict[str, Any] = field(default_factory=dict)
    group: str | None = None
    authors: list[str] = field(default_factory=list)
    artefact_kind: str | None = None  # chainsaw rules: evtx, mft, ...

    def public(self) -> dict[str, Any]:
        data = asdict(self)
        data["uri"] = f"chainsaw://rules/{self.kind}/{self.relpath}"
        return data


class RuleCatalog:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self._lock = threading.Lock()
        self._index: dict[str, list[RuleSummary]] = {}
        self._index_fingerprint: dict[str, tuple[tuple[str, bytes], ...]] = {}

    # -- roots ----------------------------------------------------------------------

    def root(self, kind: str) -> Path:
        if kind == "chainsaw":
            return self.settings.rules_dir
        if kind == "sigma":
            return self.settings.sigma_dir
        if kind == "custom":
            return self.settings.custom_rules_dir
        raise RuleError(f"Unknown rule kind {kind!r}; expected one of {', '.join(KINDS)}")

    def resolve(self, kind: str, relpath: str) -> RuleRef:
        root = self.root(kind)
        if not relpath or "\x00" in relpath or Path(relpath).is_absolute():
            raise RuleError("Rule path must be relative to the rule root")
        if ".." in Path(relpath).parts:
            raise RuleError("Rule path must not contain '..'")
        path = (root / relpath).resolve()
        try:
            path.relative_to(root.resolve())
        except ValueError as exc:
            raise RuleError("Rule path escapes the rule root") from exc
        if not path.exists():
            raise RuleError(f"No {kind} rule or directory at {relpath!r}")
        return RuleRef(kind=kind, relpath=path.relative_to(root.resolve()).as_posix(), path=path)

    def rule_dirs_for_hunt(self, extra_rules: list[str]) -> list[Path]:
        """Translate hunt `extra_rules` entries into directories chainsaw accepts.

        Entries are `custom`, `chainsaw`, or `<kind>/<relative dir>`.
        """
        out: list[Path] = []
        for entry in extra_rules:
            kind, _, rel = entry.partition("/")
            if kind not in ("chainsaw", "custom"):
                raise RuleError(
                    f"extra_rules entry {entry!r} must start with 'chainsaw' or 'custom'"
                )
            ref = self.resolve(kind, rel or ".")
            out.append(ref.path)
        return out

    def sigma_dirs(self, collections: list[str] | None) -> list[Path]:
        chosen = collections or list(SIGMA_DEFAULT_COLLECTIONS)
        dirs = []
        for name in chosen:
            if "/" in name or name not in SIGMA_COLLECTIONS:
                # Allow a sub-tree such as rules/windows/process_creation.
                ref = self.resolve("sigma", name)
                if not ref.path.is_dir():
                    raise RuleError(f"Sigma selection {name!r} is not a directory")
                dirs.append(ref.path)
                continue
            path = self.settings.sigma_dir / name
            if not path.is_dir():
                raise RuleError(f"Sigma collection {name!r} is not installed")
            dirs.append(path)
        return dirs

    def mapping(self, name: str | None) -> Path:
        """Resolve explicit mappings verbatim; repair only the known bundled default.

        Custom mappings (including a replacement with the stock file name) retain
        their author's semantics. The generated mapping is pinned to the upstream
        source it repairs, rather than silently rewriting future mapping formats.
        """
        chosen = name or DEFAULT_MAPPING
        if not SAFE_NAME.match(chosen):
            raise RuleError("Mapping names are plain file names inside the mappings directory")
        cache = self.settings.output_dir / ".mappings"
        if chosen == DERIVED_MAPPING:
            stock = self.settings.mappings_dir / DEFAULT_MAPPING
            derived = provider_aware_default(stock, cache) if stock.is_file() else stock
            if derived == stock:
                raise RuleError(
                    f"Mapping {chosen!r} is derived from the unmodified bundled "
                    f"{DEFAULT_MAPPING}, which is not installed"
                )
            return derived
        path = self.settings.mappings_dir / chosen
        if not path.is_file():
            available = ", ".join(self.mapping_names()) or "none installed"
            raise RuleError(f"Mapping {chosen!r} not found; available: {available}")
        if name is None:
            return provider_aware_default(path, cache)
        return path

    def mapping_names(self) -> list[str]:
        if not self.settings.mappings_dir.is_dir():
            return []
        names = sorted(p.name for p in self.settings.mappings_dir.glob("*.yml"))
        stock = self.settings.mappings_dir / DEFAULT_MAPPING
        if stock.is_file():
            digest = hashlib.sha256(stock.read_bytes()).hexdigest()
            if digest == STOCK_MAPPING_SHA256:
                names.append(DERIVED_MAPPING)
        return names

    # -- indexing -------------------------------------------------------------------

    def _load_file(
        self, kind: str, root: Path, path: Path, *, text: str | None = None
    ) -> RuleSummary | None:
        if text is None:
            text = path.read_text(encoding="utf-8", errors="replace")
        try:
            docs = [d for d in yaml.load_all(text, _Loader) if isinstance(d, dict)]
        except yaml.YAMLError:
            return RuleSummary(
                kind=kind,
                relpath=path.relative_to(root).as_posix(),
                title=path.stem,
                status="unparseable",
            )
        if not docs:
            return None
        doc = docs[0]
        tags = doc.get("tags") or []
        authors = doc.get("authors") or doc.get("author") or []
        if isinstance(authors, str):
            authors = [a.strip() for a in authors.split(",") if a.strip()]
        raw_logsource = doc.get("logsource")
        logsource: dict[str, Any] = raw_logsource if isinstance(raw_logsource, dict) else {}
        return RuleSummary(
            kind=kind,
            relpath=path.relative_to(root).as_posix(),
            title=str(doc.get("title") or path.stem),
            level=str(doc["level"]) if doc.get("level") is not None else None,
            status=str(doc["status"]) if doc.get("status") is not None else None,
            id=str(doc["id"]) if doc.get("id") is not None else None,
            description=str(doc.get("description") or "").strip(),
            tags=[str(t) for t in tags] if isinstance(tags, list) else [],
            logsource=logsource,
            group=str(doc["group"]) if doc.get("group") is not None else None,
            authors=[str(a) for a in authors] if isinstance(authors, list) else [],
            artefact_kind=str(doc["kind"]) if kind != "sigma" and doc.get("kind") else None,
        )

    def index(self, kind: str, *, refresh: bool = False) -> list[RuleSummary]:
        root = self.root(kind)
        with self._lock:
            # Hash the actual inputs, not directory mtimes (which do not change on
            # edits). Parse these same bytes so a concurrent replacement cannot
            # associate a new summary with an old fingerprint, or vice versa.
            files: list[tuple[Path, bytes]] = []
            if root.is_dir():
                skip = {".git", "tests", "regression_data", "documentation", "images"}
                for path in sorted(root.rglob("*")):
                    if path.suffix.lower() not in RULE_SUFFIXES or not path.is_file():
                        continue
                    if skip & set(path.relative_to(root).parts):
                        continue
                    try:
                        files.append((path, path.read_bytes()))
                    except FileNotFoundError:
                        # External rule updates may remove files during discovery.
                        continue
            fingerprint = tuple(
                (path.relative_to(root).as_posix(), hashlib.sha256(content).digest())
                for path, content in files
            )
            if (
                not refresh
                and kind in self._index
                and self._index_fingerprint.get(kind) == fingerprint
            ):
                return self._index[kind]
            rules: list[RuleSummary] = []
            for path, content in files:
                summary = self._load_file(
                    kind, root, path, text=content.decode("utf-8", errors="replace")
                )
                if summary is not None:
                    rules.append(summary)
            self._index[kind] = rules
            self._index_fingerprint[kind] = fingerprint
            return rules

    def search(
        self,
        query: str = "",
        *,
        kinds: list[str] | None = None,
        level: str | None = None,
        status: str | None = None,
        tag: str | None = None,
        logsource: str | None = None,
        path_prefix: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        needles = [w for w in query.lower().split() if w]
        results: list[RuleSummary] = []
        for kind in kinds or list(KINDS):
            for rule in self.index(kind):
                if level and (rule.level or "").lower() != level.lower():
                    continue
                if status and (rule.status or "").lower() != status.lower():
                    continue
                if tag and not any(tag.lower() in t.lower() for t in rule.tags):
                    continue
                if logsource:
                    haystack = " ".join(str(v) for v in rule.logsource.values()).lower()
                    if logsource.lower() not in haystack:
                        continue
                if path_prefix and not rule.relpath.startswith(path_prefix.strip("/")):
                    continue
                if needles:
                    text = " ".join(
                        [
                            rule.title,
                            rule.description,
                            rule.relpath,
                            " ".join(rule.tags),
                            rule.group or "",
                            rule.id or "",
                        ]
                    ).lower()
                    if not all(n in text for n in needles):
                        continue
                results.append(rule)
        total = len(results)
        page = results[offset : offset + limit]
        return {
            "total": total,
            "offset": offset,
            "returned": len(page),
            "next_offset": offset + len(page) if offset + len(page) < total else None,
            "rules": [r.public() for r in page],
        }

    def stats(self) -> dict[str, Any]:
        out: dict[str, Any] = {"mappings": self.mapping_names()}
        for kind in KINDS:
            root = self.root(kind)
            if not root.is_dir():
                out[kind] = {"installed": False, "path": str(root)}
                continue
            rules = self.index(kind)
            levels: dict[str, int] = {}
            statuses: dict[str, int] = {}
            for r in rules:
                levels[r.level or "unset"] = levels.get(r.level or "unset", 0) + 1
                statuses[r.status or "unset"] = statuses.get(r.status or "unset", 0) + 1
            entry: dict[str, Any] = {
                "installed": True,
                "path": str(root),
                "count": len(rules),
                "by_level": levels,
                "by_status": statuses,
            }
            if kind == "sigma":
                entry["collections"] = {
                    name: sum(1 for r in rules if r.relpath.startswith(name + "/"))
                    for name in SIGMA_COLLECTIONS
                    if (root / name).is_dir()
                }
            out[kind] = entry
        return out

    # -- reading and writing --------------------------------------------------------

    def read(self, kind: str, relpath: str) -> dict[str, Any]:
        ref = self.resolve(kind, relpath)
        if ref.path.is_dir():
            children = sorted(
                p.relative_to(self.root(kind)).as_posix()
                for p in ref.path.iterdir()
                if p.is_dir() or p.suffix.lower() in RULE_SUFFIXES
            )
            return {"kind": kind, "path": ref.relpath, "directory": True, "children": children}
        text = ref.path.read_text(encoding="utf-8", errors="replace")
        summary = self._load_file(kind, self.root(kind), ref.path)
        return {
            "kind": kind,
            "path": ref.relpath,
            "directory": False,
            "uri": f"chainsaw://rules/{kind}/{ref.relpath}",
            "summary": summary.public() if summary else None,
            "yaml": text,
        }

    def save_custom_rule(self, name: str, content: str, *, overwrite: bool = False) -> Path:
        clean = name.removesuffix(".yml").removesuffix(".yaml")
        if not SAFE_NAME.match(clean):
            raise RuleError(
                "Rule name must be 1-121 chars of letters, digits, '_', '.', '-' (no slashes)"
            )
        if len(content.encode("utf-8")) > MAX_RULE_BYTES:
            raise RuleError(f"Rule exceeds {MAX_RULE_BYTES} bytes")
        try:
            # Aliases expand on load (billion-laughs); scan the event stream first.
            for event in yaml.parse(content, _Loader):
                if isinstance(event, yaml.AliasEvent):
                    raise RuleError("YAML anchors and aliases are not allowed in rules")
            docs = list(yaml.load_all(content, _Loader))
        except yaml.YAMLError as exc:
            raise RuleError(f"Rule is not valid YAML: {exc}") from exc
        doc = next((d for d in docs if isinstance(d, dict)), None)
        if doc is None:
            raise RuleError("Rule must be a YAML mapping")
        missing = [k for k in REQUIRED_RULE_KEYS if k not in doc]
        if missing:
            raise RuleError(
                "Chainsaw rules need title, group, description, authors, kind, level, status, "
                f"timestamp, fields and filter; missing: {', '.join(missing)}"
            )
        root = self.settings.custom_rules_dir
        target = root / f"{clean}.yml"
        with self._lock:
            root.mkdir(parents=True, exist_ok=True)
            if target.exists() and not overwrite:
                raise RuleError(f"Custom rule {clean!r} already exists; pass overwrite=true")
            # Publish a complete file atomically. link() also enforces no-clobber
            # across catalog instances/processes; replace() is for explicit overwrites.
            temporary: Path | None = None
            try:
                with tempfile.NamedTemporaryFile(
                    mode="w", encoding="utf-8", dir=root, suffix=".tmp", delete=False
                ) as fh:
                    temporary = Path(fh.name)
                    fh.write(content)
                if overwrite:
                    os.replace(temporary, target)
                else:
                    try:
                        os.link(temporary, target)
                    except FileExistsError:
                        raise RuleError(
                            f"Custom rule {clean!r} already exists; pass overwrite=true"
                        ) from None
            finally:
                if temporary is not None:
                    temporary.unlink(missing_ok=True)
            self._index.pop("custom", None)
            self._index_fingerprint.pop("custom", None)
        return target

    def delete_custom_rule(self, name: str) -> bool:
        clean = name.removesuffix(".yml").removesuffix(".yaml")
        if not SAFE_NAME.match(clean):
            raise RuleError("Invalid custom rule name")
        target = self.settings.custom_rules_dir / f"{clean}.yml"
        with self._lock:
            existed = target.is_file()
            target.unlink(missing_ok=True)
            self._index.pop("custom", None)
            self._index_fingerprint.pop("custom", None)
        return existed


def mapping_summary(path: Path) -> dict[str, Any]:
    """Expose applicability and translations, bounded to 200 entries per collection.

    Preconditions are ordered: Chainsaw 2.16 uses the last matching rule selector.
    Counts and truncation flags distinguish absent constraints from omitted entries;
    callers can request the full YAML when investigating a truncated summary.
    """
    doc = yaml.load(path.read_text(encoding="utf-8", errors="replace"), _Loader) or {}
    groups = doc.get("groups") or []
    exclusions = doc.get("exclusions") or []
    preconditions = (doc.get("extensions") or {}).get("preconditions") or []
    limit = 200
    return {
        "name": path.name,
        "title": doc.get("name"),
        "kind": doc.get("kind"),
        "rules": doc.get("rules"),
        "exclusions": len(exclusions),
        "exclusion_names": exclusions[:limit],
        "exclusions_truncated": len(exclusions) > limit,
        "precondition_count": len(preconditions),
        "preconditions": preconditions[:limit],
        "preconditions_truncated": len(preconditions) > limit,
        "precondition_resolution": "last matching selector wins (Chainsaw 2.16)",
        "group_count": len(groups),
        "groups_truncated": len(groups) > limit,
        "groups": [
            {
                "name": g.get("name"),
                "timestamp": g.get("timestamp"),
                "fields": len(g.get("fields") or []),
                "translations": (g.get("fields") or [])[:limit],
                "translations_truncated": len(g.get("fields") or []) > limit,
                "filter": g.get("filter"),
            }
            for g in groups[:limit]
            if isinstance(g, dict)
        ],
        "yaml_bytes": path.stat().st_size,
    }


def dump_json(data: Any) -> str:
    return json.dumps(data, indent=2, sort_keys=False, default=str)


__all__ = [
    "KINDS",
    "LEVELS",
    "SIGMA_COLLECTIONS",
    "STATUSES",
    "RuleCatalog",
    "RuleError",
    "RuleRef",
    "RuleSummary",
    "dump_json",
    "mapping_summary",
]
