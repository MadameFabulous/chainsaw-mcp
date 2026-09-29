"""Server-minted result handles.

Chainsaw can emit tens of thousands of JSON documents for one hunt. Tools write the
full JSONL stream to disk, return a summary plus a preview page, and hand the client an
opaque handle. Follow-up tools page and aggregate through the handle, so clients never
need session state and never receive a multi-megabyte blob in one response.
"""

from __future__ import annotations

import builtins
import csv
import fcntl
import hashlib
import io
import itertools
import json
import os
import re
import secrets
import time
from collections import Counter
from collections.abc import Iterator
from dataclasses import asdict, dataclass, field
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any

from .result_budget import (
    DEFAULT_MAX_BYTES,
    ResultError,
    annotate_delivery,
    budget,
    encoded_size,
    oversized,
)

HANDLE_RE = re.compile(r"^res_[0-9a-f]{16}$")
DEFAULT_TTL_SECONDS = 7 * 24 * 3600
# ``where`` operands: text matches as a substring, numbers and booleans exactly.
WhereValue = str | int | float | bool


@dataclass
class ResultMeta:
    handle: str
    tool: str
    created: float
    count: int
    argv: list[str]
    inputs: dict[str, Any] = field(default_factory=dict)
    format: str = "jsonl"
    columns: list[str] = field(default_factory=list)
    commands: list[list[str]] = field(default_factory=list)

    def public(self) -> dict[str, Any]:
        """Client-facing view: the command line holds server-absolute paths and stays private."""
        data = asdict(self)
        del data["argv"]
        del data["commands"]
        data["created_iso"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.created))
        return data


class ResultStore:
    def __init__(self, directory: Path, *, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> None:
        self.directory = directory
        self.ttl = ttl_seconds
        self._active: dict[str, tuple[Path, int]] = {}
        self._secure_tree()

    def _ensure_directory(self) -> None:
        self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.directory.chmod(0o700)

    def _secure_tree(self) -> None:
        """Fix the modes of a pre-existing tree once, at start-up.

        Other stores on the same directory publish, expire and abort files concurrently,
        so an entry seen by the walk may be gone by the time it is chmod'ed.
        """
        self._ensure_directory()
        for root, dirs, files in os.walk(self.directory, followlinks=False):
            for name in dirs + files:
                path = Path(root) / name
                try:
                    if not path.is_symlink():
                        path.chmod(0o700 if path.is_dir() else 0o600)
                except FileNotFoundError:
                    continue

    # -- creation -------------------------------------------------------------------

    def new_handle(self) -> str:
        return "res_" + secrets.token_hex(8)

    def data_path(self, handle: str, suffix: str = ".jsonl") -> Path:
        self._check(handle)
        return self.directory / f"{handle}{suffix}"

    def meta_path(self, handle: str) -> Path:
        self._check(handle)
        return self.directory / f"{handle}.meta.json"

    def reserve(self, suffix: str = ".jsonl") -> tuple[str, Path]:
        self._ensure_directory()
        self.expire()
        handle = self.new_handle()
        self.data_path(handle, suffix)
        path = self.directory / f".{handle}{suffix}.pending"
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        self._active[handle] = (path, fd)
        return handle, path

    def commit(
        self,
        handle: str,
        *,
        tool: str,
        argv: list[str],
        inputs: dict[str, Any],
        fmt: str = "jsonl",
        columns: list[str] | None = None,
        commands: list[list[str]] | None = None,
    ) -> ResultMeta:
        self._check(handle)
        if handle not in self._active:
            raise ResultError("Result is not reserved by this store")
        path, _ = self._active[handle]
        count = self._count(path, fmt)
        meta = ResultMeta(
            handle=handle,
            tool=tool,
            created=time.time(),
            count=count,
            argv=argv,
            inputs=inputs,
            format=fmt,
            columns=columns or [],
            commands=commands or [],
        )
        path.chmod(0o600)
        temporary = self.directory / f".{handle}.meta.pending"
        try:
            with os.fdopen(
                os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "w"
            ) as fh:
                fh.write(json.dumps(asdict(meta)))
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(path, self.data_path(handle, "." + fmt))
            os.replace(temporary, self.meta_path(handle))
        except BaseException:
            self.data_path(handle, "." + fmt).unlink(missing_ok=True)
            raise
        finally:
            temporary.unlink(missing_ok=True)
            self.abort(handle)
        return meta

    def abort(self, handle: str) -> None:
        """Release an unpublished result, including its active-writer lease."""
        active = self._active.pop(handle, None)
        if active:
            path, fd = active
            path.unlink(missing_ok=True)
            os.close(fd)

    # -- retrieval ------------------------------------------------------------------

    def meta(self, handle: str) -> ResultMeta:
        path = self.meta_path(handle)
        if not path.is_file():
            raise ResultError(f"Unknown or expired result handle {handle!r}")
        try:
            meta = ResultMeta(**json.loads(path.read_text()))
        except (OSError, ValueError, TypeError) as exc:
            raise ResultError(f"Unknown or expired result handle {handle!r}") from exc
        if meta.created <= time.time() - self.ttl:
            raise ResultError(f"Unknown or expired result handle {handle!r}")
        return meta

    def rows(self, handle: str) -> Iterator[dict[str, Any]]:
        meta = self.meta(handle)
        if meta.format != "jsonl":
            raise ResultError(f"Handle {handle} holds {meta.format} data, not JSON rows")
        with self.data_path(handle).open(encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    yield json.loads(line)

    def text(self, handle: str, *, max_bytes: int = 2_000_000) -> str:
        return self.text_result(handle, max_bytes=max_bytes)["content"]

    def text_result(self, handle: str, *, max_bytes: int = 2_000_000) -> dict[str, Any]:
        """Read at most the byte budget plus one sentinel, never the whole file."""
        if max_bytes < 0:
            raise ResultError("max_bytes must be >= 0")
        meta = self.meta(handle)
        path = self.data_path(handle, "." + meta.format)
        with path.open("rb") as fh:
            data = fh.read(max_bytes + 1)
        content = data[:max_bytes].decode("utf-8", errors="ignore")
        returned = len(content.encode("utf-8"))
        return {
            "content": content,
            "bytes": path.stat().st_size,
            "returned_bytes": returned,
            "truncated": len(data) > returned,
        }

    def page(
        self,
        handle: str,
        *,
        offset: int = 0,
        limit: int = 50,
        fields: list[str] | None = None,
        where: dict[str, WhereValue] | None = None,
        max_bytes: int = DEFAULT_MAX_BYTES,
    ) -> dict[str, Any]:
        meta = self.meta(handle)
        total = sum(1 for _ in self._filtered(handle, where)) if where else meta.count
        rows = (
            (index, project(r, fields, meta.tool) if fields else r)
            for index, r in self._filtered_indexed(handle, where)
        )
        return self._page_rows(handle, rows, total, offset, limit, max_bytes)

    def _page_rows(self, handle, source, total, offset, limit, max_bytes):
        max_bytes = budget(max_bytes)
        if offset < 0 or limit < 1:
            raise ResultError("offset must be >= 0 and limit >= 1")
        out = {
            "handle": handle,
            "tool": self.meta(handle).tool,
            "total": total,
            "offset": offset,
            "returned": 0,
            "next_offset": offset if offset < total else None,
            "rows": [],
        }
        annotate_delivery(out, truncated=offset < total, reason="max_bytes")
        for source_index, row in itertools.islice(source, offset, offset + limit):
            previous = dict(out)
            out["rows"] = [*out["rows"], row]
            out["returned"] += 1
            end = offset + out["returned"]
            out["next_offset"] = end if end < total else None
            annotate_delivery(out, truncated=end < total, reason="max_bytes")
            if encoded_size(out) > max_bytes:
                if not previous["returned"]:
                    raise oversized(handle, source_index)
                return previous
        annotate_delivery(out, truncated=out["next_offset"] is not None, reason="limit")
        if encoded_size(out) > max_bytes:
            raise ResultError("Response envelope exceeds max_bytes")
        return out

    def events(
        self,
        handle: str,
        *,
        offset: int = 0,
        limit: int = 50,
        fields: list[str] | None = None,
        max_bytes: int = DEFAULT_MAX_BYTES,
    ):
        """One event per source-qualified identity, retaining every detection association."""
        grouped: dict[Any, dict[str, Any]] = {}
        for index, row in enumerate(self.rows(handle)):
            documents = detection_documents(row)
            if documents is None:
                views: list[dict[str, Any]] = [row]
            else:
                views = [{"document": d} for d in documents]
                match = {k: v for k, v in row.items() if k not in ("document", "documents")}
            for part, view in enumerate(views):
                key = event_identity(view) or ("unidentifiable", index, part)
                entry = grouped.setdefault(
                    key,
                    {
                        "event": view.get("document", {}).get("data", view),
                        "path": get_path(view, "document.path"),
                        "matches": [],
                    },
                )
                if documents is not None:
                    entry["matches"].append(match)
        values = list(grouped.values())
        if fields:
            for value in values:
                value["event"] = {f: get_path(value["event"], _expand(f, "event")) for f in fields}
        try:
            return self._page_rows(handle, enumerate(values), len(values), offset, limit, max_bytes)
        except ResultError as exc:
            raise ResultError(
                f"Event view for {handle} exceeds its budget or has invalid paging parameters. "
                "Narrow event fields, raise max_bytes, or use chainsaw_result_page to retrieve "
                "individual detections (and chainsaw_result_chunk for oversized detection rows). "
                "Event offsets are not detection row offsets."
            ) from exc

    def chunk(
        self,
        handle: str,
        *,
        row_offset: int | None = None,
        byte_offset: int = 0,
        max_bytes: int = DEFAULT_MAX_BYTES,
    ):
        """Resumable UTF-8 text; chunks need not be standalone JSON/CSV records."""
        max_bytes = budget(max_bytes)
        meta = self.meta(handle)
        if byte_offset < 0 or (row_offset is not None and row_offset < 0):
            raise ResultError("Offsets must be >= 0")
        if row_offset is None:
            path = self.data_path(handle, "." + meta.format)
            total = path.stat().st_size
            with path.open("rb") as fh:
                fh.seek(byte_offset)
                data = fh.read(max_bytes)
        else:
            row = next(itertools.islice(self.rows(handle), row_offset, row_offset + 1), None)
            if row is None:
                raise ResultError("row_offset is outside the result")
            raw = json.dumps(row, ensure_ascii=False).encode("utf-8")
            total = len(raw)
            data = raw[byte_offset : byte_offset + max_bytes]
        if byte_offset > total:
            raise ResultError("byte_offset is outside the result")
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            if exc.reason != "unexpected end of data":
                raise ResultError(
                    "byte_offset must be a UTF-8 boundary; file must be UTF-8"
                ) from exc
            text = data[: exc.start].decode("utf-8")

        def envelope(content):
            end = byte_offset + len(content.encode("utf-8"))
            return annotate_delivery(
                {
                    "handle": handle,
                    "format": meta.format,
                    "row_offset": row_offset,
                    "byte_offset": byte_offset,
                    "bytes": total,
                    "returned_bytes": end - byte_offset,
                    "next_byte_offset": end if end < total else None,
                    "truncated": end < total,
                    "content": content,
                },
                truncated=end < total,
                reason="max_bytes",
                byte_field="response_bytes",
            )

        low, high = 0, len(text)
        while low < high:
            mid = (low + high + 1) // 2
            if encoded_size(envelope(text[:mid])) <= max_bytes:
                low = mid
            else:
                high = mid - 1
        out = envelope(text[:low])
        if encoded_size(out) > max_bytes or (not low and byte_offset < total):
            raise ResultError("max_bytes is too small for the response envelope and one character")
        return out

    def _filtered(
        self, handle: str, where: dict[str, WhereValue] | None
    ) -> Iterator[dict[str, Any]]:
        for _, row in self._filtered_indexed(handle, where):
            yield row

    def _filtered_indexed(
        self, handle: str, where: dict[str, WhereValue] | None
    ) -> Iterator[tuple[int, dict[str, Any]]]:
        meta = self.meta(handle)
        filters = {_expand(k, meta.tool): str(v) for k, v in (where or {}).items()}
        for index, row in enumerate(self.rows(handle)):
            if _row_matches(row, filters):
                yield index, row

    def summary(
        self,
        handle: str,
        *,
        group_by: list[str] | None = None,
        top: int = 25,
        where: dict[str, WhereValue] | None = None,
    ) -> dict[str, Any]:
        meta = self.meta(handle)
        rows = self._filtered(handle, where)
        if not group_by:
            return {"handle": handle, "tool": meta.tool, **summarize(rows, top=top)}
        paths = list(dict.fromkeys(_expand(g, meta.tool) for g in group_by))
        counters: dict[str, Counter[str]] = {p: Counter() for p in paths}
        combined: Counter[str] = Counter()
        total = 0
        for row in rows:
            total += 1
            # Each distinct value counts once per row: an aggregate detection spanning
            # three documents on one host is one row for that host, and a row carrying
            # several tags contributes to each tag.
            per_path = {p: row_values(row, p) for p in paths}
            for p, values in per_path.items():
                for key in {k for v in values for k in _group_keys(v)}:
                    counters[p][key] += 1
            if len(paths) > 1:
                width = max(len(v) for v in per_path.values())
                combos = {
                    " | ".join(
                        _group_key(per_path[p][i] if len(per_path[p]) > 1 else per_path[p][0])
                        for p in paths
                    )
                    for i in range(width)
                }
                for combo in combos:
                    combined[combo] += 1
        out = {
            "handle": handle,
            "tool": meta.tool,
            "total": total,
            "groups": {
                p: {
                    "distinct": len(c),
                    "top": [{"value": v, "count": n} for v, n in c.most_common(top)],
                }
                for p, c in counters.items()
            },
        }
        if combined:
            out["combined"] = [{"value": v, "count": n} for v, n in combined.most_common(top)]
        return out

    def fields(self, handle: str, *, sample: int = 200) -> dict[str, Any]:
        meta = self.meta(handle)
        seen: dict[str, dict[str, Any]] = {}
        n = 0
        for row in itertools.islice(self.rows(handle), sample):
            n += 1
            for path, value in _flatten(row):
                entry = seen.setdefault(path, {"count": 0, "example": value})
                entry["count"] += 1
        return {
            "handle": handle,
            "tool": meta.tool,
            "sampled": n,
            "shorthand": _shorthand(meta.tool),
            "fields": [
                {"path": p, "present_in": v["count"], "example": _short(v["example"])}
                for p, v in sorted(seen.items())
            ],
        }

    def export(
        self,
        handle: str,
        *,
        format: str = "csv",
        fields: list[str] | None = None,
        max_rows: int = 5000,
        max_bytes: int = DEFAULT_MAX_BYTES,
        offset: int = 0,
        byte_offset: int = 0,
    ) -> dict[str, Any]:
        max_bytes = budget(max_bytes)
        meta = self.meta(handle)
        fmt = format.lower()
        if offset < 0 or max_rows < 1:
            raise ResultError("offset must be >= 0 and max_rows >= 1")
        if meta.format != "jsonl":
            return self.chunk(handle, byte_offset=byte_offset, max_bytes=max_bytes)
        if byte_offset:
            raise ResultError("Use offset for record exports or chainsaw_result_chunk for bytes")
        if fmt not in ("csv", "jsonl", "text"):
            raise ResultError("format must be csv, jsonl or text")
        names = fields or list(_shorthand(meta.tool)) or self._sampled_columns(handle)

        def csv_record(values):
            buf = io.StringIO()
            csv.writer(buf).writerow(values)
            return buf.getvalue()

        out: dict[str, Any] = {
            "handle": handle,
            "format": fmt,
            "rows": 0,
            "total": meta.count,
            "offset": offset,
            "next_offset": offset if offset < meta.count else None,
            "truncated": offset < meta.count,
            "content": csv_record(names) if fmt != "jsonl" else "",
        }
        annotate_delivery(out, truncated=offset < meta.count, reason="max_bytes")
        if encoded_size(out) > max_bytes:
            raise ResultError("Export header exceeds max_bytes; narrow fields")
        for row in itertools.islice(self.rows(handle), offset, offset + max_rows):
            if fmt == "jsonl":
                projected = project(row, fields, meta.tool) if fields else row
                record = json.dumps(projected, default=str) + "\n"
            else:
                record = csv_record([_cell(v) for v in project(row, names, meta.tool).values()])
            candidate = dict(out, content=out["content"] + record, rows=out["rows"] + 1)
            end = offset + candidate["rows"]
            candidate.update(
                next_offset=end if end < meta.count else None, truncated=end < meta.count
            )
            annotate_delivery(candidate, truncated=end < meta.count, reason="max_bytes")
            if encoded_size(candidate) > max_bytes:
                if not out["rows"]:
                    raise oversized(handle, offset)
                break
            out = candidate
        else:
            annotate_delivery(out, truncated=out["next_offset"] is not None, reason="max_rows")
        return out

    def list(self) -> list[dict[str, Any]]:
        """Stored results, newest first."""
        self.expire()
        if not self.directory.is_dir():
            return []
        out = []
        for meta_file in self.directory.glob("res_*.meta.json"):
            try:
                out.append(self.meta(meta_file.name.split(".")[0]).public())
            except (ValueError, TypeError):
                continue
        return sorted(out, key=lambda m: (-m["created"], m["handle"]))

    def list_page(
        self, *, offset: int = 0, limit: int = 50, max_bytes: int = DEFAULT_MAX_BYTES
    ) -> dict[str, Any]:
        """Fit complete metadata entries and continue from the number actually returned."""
        max_bytes = budget(max_bytes)
        if offset < 0 or limit < 1:
            raise ResultError("offset must be >= 0 and limit >= 1")
        entries = self.list()
        page = entries[offset : offset + limit]
        reason = "limit"
        while True:
            end = offset + len(page)
            out = {
                "results": page,
                "total": len(entries),
                "offset": offset,
                "returned": len(page),
                "next_offset": end if end < len(entries) else None,
            }
            annotate_delivery(out, truncated=end < len(entries), reason=reason)
            if encoded_size(out) <= max_bytes:
                return out
            if len(page) <= 1:
                handle = page[0]["handle"] if page else "<empty page>"
                raise ResultError(
                    f"Result metadata for {handle} at offset {offset} exceeds max_bytes; "
                    f"increase max_bytes or use offset={offset + 1} to continue past this entry."
                )
            page.pop()
            reason = "max_bytes"

    def delete(self, handle: str) -> bool:
        self._check(handle)
        removed = False
        for path in self.directory.glob(f"{handle}.*"):
            path.unlink(missing_ok=True)
            removed = True
        return removed

    def expire(self) -> int:
        if not self.directory.is_dir():
            return 0
        cutoff = time.time() - self.ttl
        removed = 0
        for meta_file in self.directory.glob("res_*.meta.json"):
            try:
                created = json.loads(meta_file.read_text())["created"]
                if created <= cutoff:
                    handle = meta_file.name.split(".")[0]
                    if self.delete(handle):
                        removed += 1
            except (OSError, ValueError, KeyError, TypeError):
                continue
        for path in self.directory.iterdir():
            handle = path.name.lstrip(".").split(".")[0]
            if not HANDLE_RE.fullmatch(handle) or path.is_symlink():
                continue
            try:
                if self.meta_path(handle).exists() or path.stat().st_mtime >= cutoff:
                    continue
                with path.open("rb") as fh:
                    try:
                        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    except BlockingIOError:
                        continue
                    # Publication might have completed while acquiring the lease.
                    if not self.meta_path(handle).exists():
                        path.unlink(missing_ok=True)
                        removed += 1
            except FileNotFoundError:
                continue
        return removed

    # -- helpers --------------------------------------------------------------------

    @staticmethod
    def _check(handle: str) -> None:
        if not HANDLE_RE.fullmatch(handle or ""):
            raise ResultError("Malformed result handle")

    # ``list`` is shadowed by the method above; spell the builtin out for the checker.
    def _sampled_columns(self, handle: str, sample: int = 50) -> builtins.list[str]:
        """Top-level keys of the first rows, in first-seen order, for shapeless results."""
        columns: dict[str, None] = {}
        for row in itertools.islice(self.rows(handle), sample):
            if isinstance(row, dict):
                columns.update(dict.fromkeys(row))
        return list(columns)

    @staticmethod
    def _count(path: Path, fmt: str) -> int:
        if fmt != "jsonl":
            return 1 if path.stat().st_size else 0
        with path.open("rb") as fh:
            return sum(1 for line in fh if line.strip())


def get_path(row: Any, dotted: str) -> Any:
    cur = row
    for part in dotted.split("."):
        if isinstance(cur, dict):
            cur = cur.get(part)
        elif isinstance(cur, list) and part.isdigit():
            idx = int(part)
            cur = cur[idx] if idx < len(cur) else None
        else:
            return None
        if cur is None:
            return None
    return cur


def row_values(row: dict[str, Any], dotted: str) -> list[Any]:
    """Every value a dotted path takes in a row.

    A single-document row yields one value. An aggregate detection (Chainsaw rules with
    ``aggregate:`` emit ``documents`` instead of ``document``) yields one value per
    matched document for ``document.*`` paths, so filters and projections see the
    events behind the detection instead of a missing key.
    """
    if dotted.startswith("document.") and "document" not in row:
        documents = row.get("documents")
        if isinstance(documents, list):
            inner = dotted[len("document.") :]
            return [get_path(d, inner) for d in documents]
    return [get_path(row, dotted)]


def project(row: dict[str, Any], fields: list[str], tool: str = "") -> dict[str, Any]:
    """Project fields (dotted or shorthand); multi-document values come back as a list."""
    out: dict[str, Any] = {}
    for name in fields:
        values = row_values(row, _expand(name, tool))
        out[name] = values[0] if len(values) == 1 else values
    return out


def _matches(value: Any, needle: str) -> bool:
    """Case-insensitive substring match on text; exact match on numbers and booleans."""
    if value is None:
        return False
    lowered = needle.lower()
    if isinstance(value, bool):
        return lowered == str(value).lower()
    if isinstance(value, int | float):
        if lowered == str(value).lower():
            return True
        try:
            # Converting an operand to float aliases adjacent 64-bit integer IDs.
            # Compare the JSON number spellings without losing their decimal precision.
            return Decimal(needle) == Decimal(str(value))
        except (InvalidOperation, ValueError):
            return False
    if isinstance(value, str):
        return lowered in value.lower()
    return lowered in json.dumps(value, default=str).lower()


def _row_matches(row: dict[str, Any], filters: dict[str, str]) -> bool:
    """Every filter must hold. On an aggregate row the ``document.*`` filters must all
    hold on one and the same document, so a host filter and an event filter describe a
    single source event rather than two unrelated ones. Rows are selected whole: a
    matching aggregate keeps every document for projection and summaries."""
    documents = row.get("documents") if "document" not in row else None
    if not isinstance(documents, list):
        return all(_matches(get_path(row, path), needle) for path, needle in filters.items())
    prefix = "document."
    row_level = {p: n for p, n in filters.items() if not p.startswith(prefix)}
    doc_level = {p[len(prefix) :]: n for p, n in filters.items() if p.startswith(prefix)}
    if not all(_matches(get_path(row, path), needle) for path, needle in row_level.items()):
        return False
    return not doc_level or any(
        all(_matches(get_path(doc, path), needle) for path, needle in doc_level.items())
        for doc in documents
    )


def _group_key(value: Any) -> str:
    if value is None:
        return "<missing>"
    if isinstance(value, list):
        return ", ".join(_group_key(v) for v in value) if value else "<missing>"
    return str(value)


def _group_keys(value: Any) -> list[str]:
    """Group-by keys for one value; lists of scalars (tags) count under each element."""
    if isinstance(value, list) and value and all(isinstance(v, str | int | float) for v in value):
        return [str(v) for v in value]
    return [_group_key(value)]


_EVENT_TOOLS = frozenset({"chainsaw_search", "chainsaw_dump", "chainsaw_process_lineage", "event"})


def _shorthand(tool: str) -> dict[str, str]:
    """Shorthand table for the row shape a tool stores; empty for analysis tables."""
    if tool == "chainsaw_hunt":
        return HUNT_FIELDS
    if tool in _EVENT_TOOLS:
        return EVENT_FIELDS
    return {}


def _expand(name: str, tool: str) -> str:
    table = _shorthand(tool)
    if name in table:
        return table[name]
    if tool == "chainsaw_hunt" and name.startswith("Event."):
        return "document.data." + name
    return name


def _flatten(value: Any, prefix: str = ""):
    if isinstance(value, dict):
        for k, v in value.items():
            yield from _flatten(v, f"{prefix}.{k}" if prefix else str(k))
    elif isinstance(value, list) and value and all(isinstance(x, dict) for x in value):
        yield from _flatten(value[0], f"{prefix}.0")
    else:
        yield prefix, value


def _short(value: Any, limit: int = 120) -> Any:
    text = value if isinstance(value, str) else repr(value)
    return text if len(text) <= limit else text[:limit] + "…"


def _cell(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, list | dict):
        return json.dumps(value, default=str)
    return str(value)


# Field paths that make sense for the different chainsaw document shapes.
HUNT_FIELDS = {
    "rule": "name",
    "level": "level",
    "status": "status",
    "source": "source",
    "group": "group",
    "timestamp": "timestamp",
    "path": "document.path",
    "computer": "document.data.Event.System.Computer",
    "channel": "document.data.Event.System.Channel",
    "event_id": "document.data.Event.System.EventID",
    "provider": "document.data.Event.System.Provider_attributes.Name",
    "record_id": "document.data.Event.System.EventRecordID",
    "tags": "tags",
}
EVENT_FIELDS = {
    "timestamp": "Event.System.TimeCreated_attributes.SystemTime",
    "computer": "Event.System.Computer",
    "channel": "Event.System.Channel",
    "event_id": "Event.System.EventID",
    "provider": "Event.System.Provider_attributes.Name",
    "record_id": "Event.System.EventRecordID",
}


PROCESS_FIELDS = {
    "process_guid": "ProcessGuid",
    "parent_guid": "ParentProcessGuid",
    "image": "Image",
    "command": "CommandLine",
    "user": "User",
}
EVENT_FIELDS.update({k: "Event.EventData." + v for k, v in PROCESS_FIELDS.items()})
HUNT_FIELDS.update({k: "document.data." + EVENT_FIELDS[k] for k in PROCESS_FIELDS})


def detection_documents(row: dict[str, Any]) -> list[dict[str, Any]] | None:
    """Event documents behind a hunt detection; None for raw search/dump rows.

    Chainsaw aggregate rules emit every matched event under 'documents' instead of
    a single 'document'.
    """
    if "name" not in row:
        return None
    if "document" in row:
        return [row["document"]]
    documents = row.get("documents")
    return documents if isinstance(documents, list) else None


def event_identity(row: dict[str, Any]) -> tuple[str, ...] | None:
    """Conservative identity: never merge incomplete event records.

    Detection documents carry their source file, which is part of the identity. Raw
    search and dump rows are the event itself with no source recorded; they are
    identified by the event's own coordinates plus a digest of the full record, so only
    byte-identical records ever merge.
    """
    raw = "document" not in row and "documents" not in row
    source = get_path(row, "document.path") or row.get("path") or ("" if raw else None)
    data = get_path(row, "document.data") or row
    system = get_path(data, "Event.System") or {}
    values = [
        source,
        system.get("Computer"),
        system.get("Channel"),
        system.get("EventRecordID"),
        get_path(system, "TimeCreated_attributes.SystemTime"),
    ]
    if any(v is None or v == "" for v in values[1:]) or source is None:
        return None
    # Distinguish conflicting records without retaining entire scripts in summary keys.
    digest = hashlib.sha256()
    for part in json.JSONEncoder(sort_keys=True, default=str).iterencode(data):
        digest.update(part.encode("utf-8"))
    return (*map(str, values), digest.hexdigest())


def summarize(rows: Iterator[dict[str, Any]], *, top: int = 15) -> dict[str, Any]:
    """Aggregate hunt or search rows without materialising them."""
    total = 0
    is_hunt: bool | None = None
    counters: dict[str, Counter[str]] = {
        "by_rule": Counter(),
        "by_level": Counter(),
        "by_source": Counter(),
        "by_computer": Counter(),
        "by_channel": Counter(),
        "by_event_id": Counter(),
        "by_file": Counter(),
        "by_tag": Counter(),
        "by_hour": Counter(),
    }
    first = last = None
    identities = set()
    unidentifiable = detections = 0
    for row in rows:
        total += 1
        documents = detection_documents(row)
        is_hunt = documents is not None
        detections += int(is_hunt)
        # One view per underlying event: a detection row wraps one or more documents.
        views = [{"document": d} for d in documents] if documents is not None else [row]
        for view in views:
            identity = event_identity(view)
            if identity is None:
                unidentifiable += 1
            else:
                identities.add(identity)
        fields = HUNT_FIELDS if is_hunt else EVENT_FIELDS
        if is_hunt:
            counters["by_rule"][str(get_path(row, "name"))] += 1
            counters["by_level"][str(get_path(row, "level"))] += 1
            counters["by_source"][str(get_path(row, "source"))] += 1
            for name in {str(get_path(v, "document.path")).rsplit("/", 1)[-1] for v in views}:
                counters["by_file"][name] += 1
            for tag in get_path(row, "tags") or []:
                counters["by_tag"][str(tag)] += 1
        for key in ("computer", "channel", "event_id"):
            values = [get_path(v, fields[key]) for v in views]
            for value in {str(v) for v in values if v is not None}:
                counters["by_" + key][value] += 1
        ts = get_path(row, fields["timestamp"])
        if isinstance(ts, str) and len(ts) >= 13:
            counters["by_hour"][ts[:13].replace("T", " ")] += 1
            first = ts if first is None or ts < first else first
            last = ts if last is None or ts > last else last
    summary: dict[str, Any] = {
        "total": total,
        "detection_count": detections,
        "unique_event_count": len(identities),
        "unidentifiable_count": unidentifiable,
        "event_count_including_unidentifiable": len(identities) + unidentifiable,
        "shape": "detections" if detections else "events",
        "time_range": {"first": first, "last": last},
    }
    for key, counter in counters.items():
        if counter:
            summary[key] = [{"value": v, "count": c} for v, c in counter.most_common(top)]
            summary[key + "_distinct"] = len(counter)
    return summary
