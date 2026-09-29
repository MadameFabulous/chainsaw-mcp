"""Portable evidence inventories and point-in-time validation records.

Directory descriptors and O_NOFOLLOW keep reads inside the selected tree. Stability
checks detect observed races; immutable snapshots remain an operator responsibility.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import stat
import time
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO

from . import __version__

MAX_MANIFEST_BYTES = 64 * 1024**2
MAX_ROW_BYTES = 65536
# Receipt entry rows are larger than manifest rows and include unexpected paths, so their
# budget is a multiple of the manifest cap. Headroom beyond it always fits the truncation
# and error diagnostics and the completion row, so a receipt can always be signed.
RECEIPT_SIZE_FACTOR = 4
RECEIPT_HEADROOM = 3 * MAX_ROW_BYTES
MAX_ENTRIES = 100_000
DEFAULT_HASH_BYTES = 64 * 1024**3
DECLARATIONS = {
    "case_id",
    "evidence_id",
    "operator",
    "action",
    "from_custodian",
    "to_custodian",
    "reason",
    "snapshot_id",
    "notes",
    "previous_manifest_sha256",
}
LIMITATION = (
    "Hashes describe bytes observed during this operation. Stability checks do not prove "
    "snapshot immutability, acquisition time, custodian identity or a complete custody history. "
    "Operator declarations are supplied claims; timestamps use the server clock."
)
POLICY = {"include_hidden": True, "symlinks": "reject", "hash_algorithm": "SHA-256"}


def now() -> str:
    return datetime.now(UTC).isoformat()


def declarations(values: dict[str, str] | None) -> dict[str, str]:
    values = {} if values is None else values
    if not isinstance(values, dict):
        raise ValueError("Custody declarations must be an object")
    if set(values) - DECLARATIONS:
        raise ValueError("Unsupported custody declaration; see the tool's context fields")
    if any(not isinstance(value, str) or len(value) > 2048 for value in values.values()):
        raise ValueError("Custody declarations must be strings of at most 2048 characters")
    if "previous_manifest_sha256" in values and not re.fullmatch(
        "[0-9a-f]{64}", values["previous_manifest_sha256"]
    ):
        raise ValueError("previous_manifest_sha256 must be a lowercase SHA-256 digest")
    return dict(values)


@dataclass
class Limits:
    max_entries: int
    max_bytes: int
    deadline: float
    bytes_read: int = 0

    def check(self) -> None:
        if time.monotonic() > self.deadline:
            raise ValueError("Custody operation exceeded the server time budget")
        if self.bytes_read > self.max_bytes:
            raise ValueError("Custody operation exceeded max_total_bytes")


def _stamp(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


@contextmanager
def open_checked(path: Path, *, directory: bool = False) -> Iterator[int]:
    """Open a canonical absolute path without following links in any component."""
    if not path.is_absolute() or any(part in (".", "..") for part in path.parts[1:]):
        raise ValueError("Expected a canonical absolute path")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for index, component in enumerate(path.parts[1:]):
            is_dir = directory or index < len(path.parts) - 2
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            if is_dir:
                flags |= os.O_DIRECTORY
            else:
                info = os.stat(component, dir_fd=fd, follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode):
                    raise ValueError("Custody inputs must be regular files")
            next_fd = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        if not directory and not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError("Custody inputs must be regular files")
        yield fd
    finally:
        os.close(fd)


@dataclass(frozen=True)
class Entry:
    kind: str
    info: os.stat_result
    unreadable: bool = False


class ArtefactTooLarge(ValueError):
    pass


def inventory(root_fd: int, limits: Limits, *, strict: bool) -> dict[str, Entry]:
    found: dict[str, Entry] = {}
    visited: set[tuple[int, int]] = set()

    def walk(fd: int, relative: str, depth: int) -> None:
        limits.check()
        if depth > 128:
            raise ValueError("Evidence tree exceeds 128 directory levels")
        info = os.fstat(fd)
        identity = info.st_dev, info.st_ino
        if identity in visited:
            raise ValueError(
                "Repeated directory identity; remove cyclic or aliased directory mounts"
            )
        visited.add(identity)
        found[relative] = Entry("directory", info)
        with os.scandir(fd) as children:
            for child in children:
                limits.check()
                if len(found) >= limits.max_entries:
                    raise ValueError("Evidence inventory exceeds max_entries; narrow the scope")
                name = child.name if relative == "." else relative + "/" + child.name
                info = os.stat(child.name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    try:
                        child_fd = os.open(
                            child.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd
                        )
                    except PermissionError:
                        if strict:
                            raise
                        # Comparison records the directory as unreadable and does not descend.
                        found[name] = Entry("directory", info, unreadable=True)
                        continue
                    try:
                        if _stamp(os.fstat(child_fd)) != _stamp(info):
                            raise ValueError("Evidence directory changed while being inventoried")
                        walk(child_fd, name, depth + 1)
                    finally:
                        os.close(child_fd)
                else:
                    kind = (
                        "file"
                        if stat.S_ISREG(info.st_mode)
                        else "symlink"
                        if stat.S_ISLNK(info.st_mode)
                        else "special"
                    )
                    if strict and kind != "file":
                        raise ValueError(f"Unsupported {kind} in evidence scope: {name!r}")
                    found[name] = Entry(kind, info)

    walk(root_fd, ".", 0)
    return found


def hash_entry(root_fd: int, path: str, expected: Entry, limits: Limits) -> str:
    limits.check()
    if limits.bytes_read + expected.info.st_size > limits.max_bytes:
        raise ValueError("Custody operation would exceed max_total_bytes")
    fd = os.dup(root_fd)
    try:
        components = path.split("/")
        for index, component in enumerate(components):
            flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
            if index < len(components) - 1:
                flags |= os.O_DIRECTORY
            next_fd = os.open(component, flags, dir_fd=fd)
            os.close(fd)
            fd = next_fd
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or _stamp(before) != _stamp(expected.info):
            raise ValueError("Evidence file changed before hashing")
        digest = hashlib.sha256()
        remaining = before.st_size
        while remaining:
            limits.check()
            data = os.read(fd, min(1024 * 1024, remaining))
            if not data:
                raise ValueError("Evidence file became shorter during hashing")
            remaining -= len(data)
            limits.bytes_read += len(data)
            digest.update(data)
        if os.read(fd, 1) or _stamp(os.fstat(fd)) != _stamp(before):
            raise ValueError("Evidence file changed during hashing")
        return digest.hexdigest()
    finally:
        os.close(fd)


def stable_tree(root: Path, root_fd: int, initial: dict[str, Entry], limits: Limits) -> bool:
    final = inventory(root_fd, limits, strict=False)
    with open_checked(root, directory=True) as current:
        root_same = _stamp(os.fstat(current)) == _stamp(initial["."].info)
    return root_same and {p: (v.kind, _stamp(v.info)) for p, v in initial.items()} == {
        p: (v.kind, _stamp(v.info)) for p, v in final.items()
    }


def write_row(stream: BinaryIO, row: dict[str, Any], limit: int | None = None) -> None:
    """Append one row, keeping the artefact within ``limit`` (default: the manifest cap)."""
    limit = MAX_MANIFEST_BYTES if limit is None else limit
    encoded = (json.dumps(row, ensure_ascii=True, allow_nan=False) + "\n").encode()
    if len(encoded) > MAX_ROW_BYTES or stream.tell() + len(encoded) > limit:
        raise ArtefactTooLarge("Custody artefact exceeds its size limit; narrow the scope")
    stream.write(encoded)


def create_manifest(
    root: Path, destination: Path, context: dict[str, str], limits: Limits
) -> dict[str, Any]:
    started = now()
    with open_checked(root, directory=True) as root_fd, destination.open("wb") as output:
        entries = inventory(root_fd, limits, strict=True)
        total = sum(entry.info.st_size for entry in entries.values() if entry.kind == "file")
        if total > limits.max_bytes:
            raise ValueError(
                "Evidence scope exceeds max_total_bytes; narrow the scope or raise the limit"
            )
        header = {
            "kind": "manifest",
            "schema_version": 1,
            "manifest_id": secrets.token_hex(16),
            "started_at": started,
            "source_path": str(root),
            "policy": POLICY,
            "operator_declarations": declarations(context),
            "server_version": __version__,
        }
        write_row(output, header)
        for path, entry in sorted(entries.items()):
            row = {"kind": entry.kind, "path": path, "mtime_ns": entry.info.st_mtime_ns}
            if entry.kind == "file":
                row.update(
                    size_bytes=entry.info.st_size, sha256=hash_entry(root_fd, path, entry, limits)
                )
            write_row(output, row)
        if not stable_tree(root, root_fd, entries, limits):
            raise ValueError(
                "Evidence tree changed during manifest creation; use an immutable snapshot"
            )
        summary = {
            "kind": "completion",
            "completed_at": now(),
            "entry_count": len(entries),
            "file_count": sum(entry.kind == "file" for entry in entries.values()),
            "total_bytes": total,
            "stability_check": "passed",
            "limitation": LIMITATION,
        }
        write_row(output, summary)
        return {**summary, "manifest_id": header["manifest_id"]}


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate JSON key in custody artefact")
        result[key] = value
    return result


def read_json(raw: bytes) -> dict[str, Any]:
    def reject_constant(value: str) -> None:
        raise ValueError(f"Non-finite JSON number in custody artefact: {value}")

    value = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=reject_constant)
    if not isinstance(value, dict):
        raise ValueError("Custody artefact rows must be JSON objects")
    return value


def _timestamp(value: Any) -> None:
    if not isinstance(value, str) or datetime.fromisoformat(value).utcoffset() is None:
        raise ValueError("Custody timestamps must include a timezone")


def load_manifest(path: Path, max_entries: int) -> tuple[dict[str, Any], dict[str, dict[str, Any]]]:
    """Only called on a private, signature-verified copy; validate paths before evidence I/O."""
    entries: dict[str, dict[str, Any]] = {}
    completion = None
    with path.open("rb") as stream:
        raw_header = stream.readline(65537)
        if len(raw_header) > 65536:
            raise ValueError("Oversized evidence manifest header")
        header = read_json(raw_header)
        if (
            header.get("kind") != "manifest"
            or type(header.get("schema_version")) is not int
            or header["schema_version"] != 1
            or header.get("policy") != POLICY
            or header["policy"].get("include_hidden") is not True
        ):
            raise ValueError("Unsupported evidence manifest schema or inventory policy")
        if not isinstance(header.get("manifest_id"), str) or not re.fullmatch(
            "[0-9a-f]{32}", header["manifest_id"]
        ):
            raise ValueError("Invalid evidence manifest identity")
        if set(header) != {
            "kind",
            "schema_version",
            "manifest_id",
            "started_at",
            "source_path",
            "policy",
            "operator_declarations",
            "server_version",
        } or any(
            not isinstance(header.get(key), str) or not header[key]
            for key in ("source_path", "server_version")
        ):
            raise ValueError("Invalid evidence manifest header")
        _timestamp(header["started_at"])
        if not isinstance(header["operator_declarations"], dict):
            raise ValueError("Invalid manifest operator declarations")
        declarations(header["operator_declarations"])
        for line in iter(lambda: stream.readline(65537), b""):
            if len(line) > 65536 or completion is not None:
                raise ValueError("Oversized row or trailing data in evidence manifest")
            row = read_json(line)
            if row.get("kind") == "completion":
                completion = row
                continue
            name, kind = row.get("path"), row.get("kind")
            if (
                not isinstance(name, str)
                or not name
                or "\x00" in name
                or (name != "." and any(part in ("", ".", "..") for part in name.split("/")))
                or kind not in ("file", "directory")
                or (name == "." and kind != "directory")
                or name in entries
                or type(row.get("mtime_ns")) is not int
            ):
                raise ValueError("Invalid, duplicate or unsafe manifest entry")
            if kind == "file" and (
                type(row.get("size_bytes")) is not int
                or row["size_bytes"] < 0
                or not isinstance(row.get("sha256"), str)
                or not re.fullmatch("[0-9a-f]{64}", row["sha256"])
            ):
                raise ValueError("Invalid file size or SHA-256 in evidence manifest")
            fields = {"kind", "path", "mtime_ns"}
            if kind == "file":
                fields |= {"size_bytes", "sha256"}
            if set(row) != fields:
                raise ValueError("Unsupported evidence manifest entry fields")
            entries[name] = row
            if len(entries) > max_entries:
                raise ValueError("Manifest exceeds max_entries")
    if "." not in entries:
        raise ValueError("Manifest lacks its root directory entry")
    for name in entries:
        if name != ".":
            parent = name.rsplit("/", 1)[0] if "/" in name else "."
            if entries.get(parent, {}).get("kind") != "directory":
                raise ValueError("Manifest contains an entry without its parent directory")
    counts = {
        "entry_count": len(entries),
        "file_count": sum(row["kind"] == "file" for row in entries.values()),
        "total_bytes": sum(row["size_bytes"] for row in entries.values() if row["kind"] == "file"),
    }
    if (
        not completion
        or set(completion)
        != {
            "kind",
            "completed_at",
            "entry_count",
            "file_count",
            "total_bytes",
            "stability_check",
            "limitation",
        }
        or completion.get("stability_check") != "passed"
        or not isinstance(completion.get("limitation"), str)
        or any(type(completion.get(k)) is not int or completion[k] != v for k, v in counts.items())
    ):
        raise ValueError("Missing or inconsistent manifest completion record")
    _timestamp(completion["completed_at"])
    return header, entries


def validate_collection(
    root: Path,
    destination: Path,
    header: dict[str, Any],
    expected: dict[str, dict[str, Any]],
    context: dict[str, str],
    reference: dict[str, Any],
    limits: Limits,
) -> dict[str, Any]:
    counts: Counter[str] = Counter()
    matched_files = metadata_changed = 0
    stability = "not_checked"
    truncated = False
    receipt_limit = RECEIPT_SIZE_FACTOR * MAX_MANIFEST_BYTES
    final_limit = receipt_limit + RECEIPT_HEADROOM
    unreadable_dirs: list[str] = []
    with destination.open("wb") as output:
        write_row(
            output,
            {
                "kind": "validation",
                "schema_version": 1,
                "started_at": now(),
                "source_path": str(root),
                "manifest_id": header["manifest_id"],
                "manifest_reference": reference,
                "operator_declarations": declarations(context),
                "server_version": __version__,
            },
        )
        try:
            with open_checked(root, directory=True) as root_fd:
                actual = inventory(root_fd, limits, strict=False)
                for name in sorted(expected.keys() | actual.keys()):
                    limits.check()
                    wanted, observed = expected.get(name), actual.get(name)
                    row: dict[str, Any] = {"kind": "entry", "path": name}
                    blocked = next(
                        (d for d in unreadable_dirs if name.startswith(d + "/")), None
                    )
                    if blocked is not None:
                        row.update(status="unreadable", reason=f"inside unreadable {blocked!r}")
                    elif wanted is None:
                        row.update(
                            status="unexpected", observed_kind=observed.kind if observed else None
                        )
                    elif observed is None:
                        row.update(status="missing", expected_kind=wanted["kind"])
                    elif observed.kind != wanted["kind"]:
                        row.update(
                            status="type_changed",
                            expected_kind=wanted["kind"],
                            observed_kind=observed.kind,
                        )
                    elif observed.unreadable:
                        row.update(
                            status="unreadable",
                            observed_kind=observed.kind,
                            reason="permission denied",
                        )
                        unreadable_dirs.append(name)
                    else:
                        row.update(
                            status="matched",
                            observed_kind=observed.kind,
                            metadata_changed=observed.info.st_mtime_ns != wanted["mtime_ns"],
                            expected_mtime_ns=wanted["mtime_ns"],
                            observed_mtime_ns=observed.info.st_mtime_ns,
                        )
                        if observed.kind == "file":
                            row.update(
                                expected_sha256=wanted["sha256"],
                                expected_size_bytes=wanted["size_bytes"],
                                observed_size_bytes=observed.info.st_size,
                            )
                            try:
                                if observed.info.st_size != wanted["size_bytes"]:
                                    row.update(status="changed", reason="size_mismatch")
                                else:
                                    digest = hash_entry(root_fd, name, observed, limits)
                                    row.update(
                                        observed_sha256=digest,
                                        status="matched"
                                        if digest == wanted["sha256"]
                                        else "changed",
                                    )
                            except PermissionError as exc:
                                row.update(status="unreadable", reason=str(exc))
                            except (OSError, ValueError) as exc:
                                row.update(status="error", reason=str(exc))
                    try:
                        write_row(output, row, receipt_limit)
                    except ArtefactTooLarge:
                        # Stop per-path rows; the headroom keeps the receipt signable.
                        truncated = True
                        write_row(
                            output,
                            {
                                "kind": "diagnostic",
                                "status": "truncated",
                                "reason": "Receipt size limit reached; later paths not recorded",
                            },
                            final_limit,
                        )
                        break
                    # Counters describe written rows only, so update them after the write.
                    counts[row["status"]] += 1
                    metadata_changed += bool(row.get("metadata_changed"))
                    matched_files += row["status"] == "matched" and row["observed_kind"] == "file"
                stability = "passed" if stable_tree(root, root_fd, actual, limits) else "failed"
                if stability != "passed":
                    raise ValueError("Evidence tree changed during validation")
        except (OSError, ValueError) as exc:
            counts["error"] += 1
            write_row(
                output,
                {"kind": "diagnostic", "status": "error", "reason": str(exc)[:4096]},
                final_limit,
            )
        mismatch = any(counts[key] for key in ("missing", "unexpected", "type_changed", "changed"))
        status = (
            "incomplete"
            if counts["error"] or counts["unreadable"] or truncated or stability != "passed"
            else "mismatch"
            if mismatch
            else "match"
        )
        summary = {
            "kind": "completion",
            "completed_at": now(),
            "status": status,
            "valid": status == "match",
            "counts": dict(counts),
            "mismatches_found": mismatch,
            "truncated": truncated,
            "matched_files": matched_files,
            "metadata_changed": metadata_changed,
            "stability_check": stability,
            "bytes_hashed": limits.bytes_read,
            "limitation": LIMITATION,
        }
        write_row(output, summary, final_limit)
        return summary


def copy_artifact(source: Path, destination: Path, expected: dict[str, Any]) -> None:
    if expected["size_bytes"] > MAX_MANIFEST_BYTES:
        raise ValueError("Signed evidence manifest exceeds the 64 MiB size limit")
    digest = hashlib.sha256()
    size = 0
    with open_checked(source) as fd, destination.open("wb") as output:
        while data := os.read(fd, min(1024 * 1024, expected["size_bytes"] - size + 1)):
            size += len(data)
            if size > expected["size_bytes"]:
                raise ValueError("Evidence manifest exceeds its signed size")
            digest.update(data)
            output.write(data)
    if size != expected["size_bytes"] or digest.hexdigest() != expected["sha256"]:
        raise ValueError("Evidence manifest size or SHA-256 differs from its signature")
