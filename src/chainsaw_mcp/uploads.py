"""Resumable, size-limited evidence ingestion with atomic checksum-verified publication."""

from __future__ import annotations

import base64
import binascii
import fcntl
import hashlib
import json
import logging
import os
import re
import secrets
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .transfers import upload_manifest, verify_manifest

logger = logging.getLogger(__name__)

MAX_CHUNK_BYTES = 196_608
# Only the signed envelope is retained; unsigned extras never reach reservation metadata.
SIGNATURE_FIELDS = ("algorithm", "key_id", "manifest", "signature")
_HANDLE = re.compile(r"upl_[0-9a-f]{32}\Z")
_DIGEST = re.compile(r"[0-9a-fA-F]{64}\Z")


class UploadStore:
    def __init__(
        self,
        directory: Path,
        *,
        max_bytes: int,
        quota_bytes: int,
        trusted_keys: dict[str, Ed25519PublicKey] | None = None,
    ) -> None:
        self.directory = directory
        self.staging = directory / "staging"
        self.evidence = directory / "evidence"
        self.max_bytes = max_bytes
        self.quota_bytes = quota_bytes
        self.trusted_keys = trusted_keys or {}
        for path in (directory, self.staging, self.evidence):
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
            path.chmod(0o700)

    @contextmanager
    def _lock(self):
        # One lock protects reservations, retransmits and publication across server processes.
        with (self.directory / ".lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            yield

    def _meta_path(self, handle: str) -> Path:
        if not _HANDLE.fullmatch(handle):
            raise ValueError("Invalid upload handle")
        return self.staging / f"{handle}.json"

    def _meta(self, handle: str) -> dict[str, Any]:
        try:
            return json.loads(self._meta_path(handle).read_text())
        except FileNotFoundError:
            raise ValueError("Unknown or aborted upload") from None

    def _status(self, meta: dict[str, Any]) -> dict[str, Any]:
        target = self.evidence / meta["upload_id"] / meta["name"]
        part = self.staging / (meta["upload_id"] + ".part")
        complete = target.is_file()
        return {
            **meta,
            "complete": complete,
            "next_offset": meta["size_bytes"] if complete else part.stat().st_size,
            "path": str(target) if complete else None,
            "max_chunk_bytes": MAX_CHUNK_BYTES,
        }

    def _verify_signature(self, meta: dict[str, Any]) -> None:
        manifest = verify_manifest(meta.get("signature"), self.trusted_keys, purpose="upload")
        if manifest != upload_manifest(meta["name"], meta["size_bytes"], meta["sha256"]):
            raise ValueError("Upload declaration differs from its signed manifest")

    def begin(
        self,
        name: str,
        size_bytes: int,
        sha256: str,
        signature: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        if (
            not name
            or len(name.encode("utf-8")) > 200
            or name in {".", ".."}
            or name.startswith(".")
            or any(c in name for c in "/\\")
            or any(ord(c) < 32 for c in name)
        ):
            raise ValueError("name must be a plain filename of at most 200 bytes")
        if not 1 <= size_bytes <= self.max_bytes:
            raise ValueError(f"size_bytes must be 1..{self.max_bytes}")
        if not _DIGEST.fullmatch(sha256):
            raise ValueError("sha256 must contain 64 hexadecimal characters")
        if isinstance(signature, dict):
            signature = {k: signature[k] for k in SIGNATURE_FIELDS if k in signature}
        declaration = {
            "name": name,
            "size_bytes": size_bytes,
            "sha256": sha256.lower(),
            "signature": signature,
        }
        self._verify_signature(declaration)
        with self._lock():
            reserved = 0
            for record in self.staging.glob("upl_*.json"):
                try:
                    size = json.loads(record.read_text())["size_bytes"]
                    if type(size) is not int or size < 0:
                        raise TypeError("size_bytes is not a non-negative integer")
                except (OSError, ValueError, KeyError, TypeError) as exc:
                    # Its retained bytes are unknown; counting it as zero would overrun the quota.
                    logger.error("Unreadable upload reservation %s: %s", record, exc)
                    raise ValueError(
                        f"Upload reservation {record.name} is unreadable; "
                        "reconcile it before new uploads"
                    ) from None
                reserved += size
            if reserved + size_bytes > self.quota_bytes:
                raise ValueError(
                    "Upload quota exceeded; the quota counts retained uploaded evidence plus "
                    "incomplete reservations. Abort incomplete uploads or ask the operator to "
                    "remove retained evidence and its reservation record offline"
                )
            handle = "upl_" + secrets.token_hex(16)
            meta = {
                "upload_id": handle,
                **declaration,
            }
            path = self.staging / f"{handle}.part"
            temporary = self.staging / f".{handle}.json.tmp"
            final = self._meta_path(handle)
            linked = False
            path.touch(mode=0o600, exist_ok=False)
            try:
                # Publish complete metadata atomically; link refuses to overwrite.
                fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
                with os.fdopen(fd, "w") as stream:
                    json.dump(meta, stream)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.link(temporary, final)
                linked = True
                temporary.unlink()
            except BaseException:
                path.unlink(missing_ok=True)
                temporary.unlink(missing_ok=True)
                if linked:
                    final.unlink(missing_ok=True)
                raise
            return self._status(meta)

    def status(self, handle: str) -> dict[str, Any]:
        with self._lock():
            return self._status(self._meta(handle))

    def append(self, handle: str, offset: int, data_base64: str) -> dict[str, Any]:
        if not data_base64 or len(data_base64) > MAX_CHUNK_BYTES * 4 // 3:
            raise ValueError(f"Supply 1..{MAX_CHUNK_BYTES} decoded bytes per chunk")
        try:
            data = base64.b64decode(data_base64, validate=True)
        except (binascii.Error, ValueError):
            raise ValueError("data_base64 must be valid base64") from None
        if not data or len(data) > MAX_CHUNK_BYTES or offset < 0:
            raise ValueError("Invalid chunk size or offset")
        with self._lock():
            meta = self._meta(handle)
            self._verify_signature(meta)
            status = self._status(meta)
            if status["complete"]:
                raise ValueError("Upload is already published; evidence cannot be modified")
            if offset > status["next_offset"] or offset + len(data) > meta["size_bytes"]:
                raise ValueError("Chunk exceeds the declared size or is out of order")
            with (self.staging / f"{handle}.part").open("r+b") as stream:
                stream.seek(offset)
                if offset < status["next_offset"]:
                    if offset + len(data) > status["next_offset"] or stream.read(len(data)) != data:
                        raise ValueError("Retry bytes differ from the previously accepted chunk")
                else:
                    stream.write(data)
                    stream.flush()
                    os.fsync(stream.fileno())
            return self._status(meta)

    def finish(self, handle: str) -> dict[str, Any]:
        with self._lock():
            meta = self._meta(handle)
            self._verify_signature(meta)
            status = self._status(meta)
            if status["complete"]:
                return status
            if status["next_offset"] != meta["size_bytes"]:
                raise ValueError("Upload is incomplete; continue at next_offset")
            part = self.staging / f"{handle}.part"
            digest = hashlib.sha256()
            with part.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            if digest.hexdigest() != meta["sha256"]:
                raise ValueError("SHA-256 mismatch; abort this upload and begin again")
            target_dir = self.evidence / handle
            target_dir.mkdir(mode=0o700, exist_ok=True)
            part.chmod(0o400)
            # link refuses to overwrite; evidence and staging share one filesystem.
            os.link(part, target_dir / meta["name"])
            part.unlink()
            return self._status(meta)

    def abort(self, handle: str) -> dict[str, Any]:
        with self._lock():
            meta = self._meta(handle)
            if self._status(meta)["complete"]:
                raise ValueError("Published evidence cannot be aborted or deleted through MCP")
            (self.staging / f"{handle}.part").unlink(missing_ok=True)
            self._meta_path(handle).unlink()
            return {"upload_id": handle, "aborted": True}
