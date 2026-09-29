"""Signed evidence observations to support chain-of-custody activities."""

from __future__ import annotations

import os
import tempfile
import time
from pathlib import Path
from typing import Annotated, Any

from pydantic import Field

from ..custody import (
    DEFAULT_HASH_BYTES,
    MAX_ENTRIES,
    Limits,
    copy_artifact,
    create_manifest,
    declarations,
    load_manifest,
    open_checked,
    read_json,
    validate_collection,
    write_row,
)
from ..result_budget import bounded_dumps
from ..results import HANDLE_RE
from ..transfers import file_fingerprint, sign_manifest, verify_manifest
from ._common import ToolContext

_CONTEXT = (
    "Optional operator declarations: case_id, evidence_id, operator, action, from_custodian, "
    "to_custodian, reason, snapshot_id, notes, previous_manifest_sha256. These are supplied "
    "claims, not verified identity or custody events. Values are limited to 2048 characters."
)
_SOURCE = (
    "Result handle, or saved file under an allowed evidence root (including verified uploads)."
)


class CustodyTools:
    def __init__(self, ctx: ToolContext) -> None:
        self.ctx = ctx

    def _scope(self, raw: str) -> Path:
        root = Path(self.ctx.evidence(raw))
        if not root.is_dir():
            raise ValueError("Select an evidence directory for a custody inventory")
        if self.ctx.store.directory.resolve().is_relative_to(root):
            raise ValueError("Result storage must be outside the evidence scope")
        if self.ctx.transfer_key is None:
            raise ValueError("Custody records require CHAINSAW_TRANSFER_SIGNING_KEY_FILE")
        return root

    def _source(self, value: str) -> Path:
        if HANDLE_RE.fullmatch(value):
            meta = self.ctx.store.meta(value)
            return self.ctx.store.data_path(value, "." + meta.format)
        return Path(self.ctx.evidence(value))

    def _publish(
        self,
        handle: str,
        path: Path,
        *,
        purpose: str,
        tool: str,
        inputs: dict[str, Any],
    ) -> dict[str, Any]:
        key = self.ctx.transfer_key
        if key is None:
            raise ValueError("Custody records require a signing key")
        fingerprint = file_fingerprint(path)
        attestation = sign_manifest({"version": 1, "purpose": purpose, **fingerprint}, key)
        signature_handle, signature_path = self.ctx.store.reserve()
        published = []
        try:
            with signature_path.open("wb") as output:
                write_row(output, attestation)
            for candidate in (handle, signature_handle):
                self.ctx.store.commit(candidate, tool=tool, argv=[], inputs=inputs)
                published.append(candidate)
        except BaseException:
            for candidate in published:
                self.ctx.store.delete(candidate)
            raise
        finally:
            self.ctx.store.abort(signature_handle)
        return {
            "signature_handle": signature_handle,
            "sha256": fingerprint["sha256"],
            "size_bytes": fingerprint["size_bytes"],
            "signer_key_id": attestation["key_id"],
        }

    def chainsaw_evidence_manifest(
        self,
        path: Annotated[str, Field(description="Directory under an allowed evidence root.")] = ".",
        context: Annotated[dict[str, str] | None, Field(description=_CONTEXT)] = None,
        max_entries: Annotated[
            int,
            Field(
                ge=1,
                le=MAX_ENTRIES,
                description="Maximum files and directories, including the root.",
            ),
        ] = MAX_ENTRIES,
        max_total_bytes: Annotated[
            int, Field(ge=1, description="Maximum total file bytes to hash; default 64 GiB.")
        ] = DEFAULT_HASH_BYTES,
    ) -> str:
        """Create a signed SHA-256 inventory to support chain-of-custody documentation.

        Includes all files and directories, including hidden/empty entries; rejects links,
        special files, unreadable entries and observed changes. Uses relative paths for
        relocation. Returns manifest_handle and signature_handle; preserve both before expiry.
        Reads the complete collection subject to byte/entry limits and CHAINSAW_TIMEOUT.
        It records current observations and operator declarations, not a complete custody chain.
        """
        root = self._scope(path)
        context = declarations(context)
        handle, destination = self.ctx.store.reserve()
        try:
            limits = Limits(
                max_entries, max_total_bytes, time.monotonic() + self.ctx.settings.timeout
            )
            summary = create_manifest(root, destination, context, limits)
            signed = self._publish(
                handle,
                destination,
                purpose="evidence-manifest",
                tool="chainsaw_evidence_manifest",
                inputs={"path": str(root), "context": context},
            )
            return bounded_dumps({"manifest_handle": handle, **signed, **summary})
        except OSError as exc:
            raise ValueError(f"Evidence manifest could not be completed: {exc}") from exc
        finally:
            self.ctx.store.abort(handle)

    def chainsaw_evidence_validate(
        self,
        manifest: Annotated[str, Field(description=_SOURCE)],
        signature: Annotated[
            str, Field(description="Detached evidence-manifest signature. " + _SOURCE)
        ],
        path: Annotated[
            str, Field(description="Directory to compare, which may be a relocated copy.")
        ] = ".",
        context: Annotated[dict[str, str] | None, Field(description=_CONTEXT)] = None,
        max_entries: Annotated[
            int,
            Field(
                ge=1,
                le=MAX_ENTRIES,
                description="Maximum entries in each inventory, including the root.",
            ),
        ] = MAX_ENTRIES,
        max_total_bytes: Annotated[
            int, Field(ge=1, description="Maximum bytes to hash during comparison; default 64 GiB.")
        ] = DEFAULT_HASH_BYTES,
    ) -> str:
        """Verify a signed manifest and compare the full evidence directory against it.

        Trust comes from the configured server signing key and CHAINSAW_CUSTODY_TRUSTED_KEYS_DIR,
        never from the evidence volume. Rejects invalid signatures before scanning the target.
        Returns match, mismatch or incomplete, plus signed receipt/detail handles. Added,
        missing, changed and unreadable entries are explicit; mtime differences are separate
        observations and do not fail a byte-for-byte match. No files are repaired or rewritten.
        """
        root = self._scope(path)
        context = declarations(context)
        with open_checked(self._source(signature)) as fd:
            raw = os.read(fd, 8193)
        if len(raw) > 8192:
            raise ValueError("Custody signature exceeds its size limit")
        attestation = read_json(raw)
        descriptor = verify_manifest(
            attestation, self.ctx.custody_keys, purpose="evidence-manifest"
        )
        with tempfile.TemporaryDirectory(prefix=".custody-", dir=self.ctx.store.directory) as work:
            copied = Path(work) / "manifest.jsonl"
            copy_artifact(self._source(manifest), copied, descriptor)
            header, expected = load_manifest(copied, max_entries)
            handle, destination = self.ctx.store.reserve()
            try:
                limits = Limits(
                    max_entries, max_total_bytes, time.monotonic() + self.ctx.settings.timeout
                )
                summary = validate_collection(
                    root,
                    destination,
                    header,
                    expected,
                    context,
                    {
                        "sha256": descriptor["sha256"],
                        "signer_key_id": attestation["key_id"],
                        "manifest_source": manifest,
                        "signature_source": signature,
                    },
                    limits,
                )
                signed = self._publish(
                    handle,
                    destination,
                    purpose="evidence-validation",
                    tool="chainsaw_evidence_validate",
                    inputs={"path": str(root), "manifest": manifest},
                )
                return bounded_dumps({"validation_handle": handle, **signed, **summary})
            finally:
                self.ctx.store.abort(handle)

    TOOLS = ("chainsaw_evidence_manifest", "chainsaw_evidence_validate")
