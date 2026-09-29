"""Remote evidence ingestion without giving clients filesystem write access."""

from typing import Annotated, Any, Literal

from pydantic import Field

from ..uploads import MAX_CHUNK_BYTES, UploadStore
from ._common import ToolContext, dumps


class UploadTools:
    def __init__(self, ctx: ToolContext) -> None:
        self.ctx = ctx

    def _store(self) -> UploadStore:
        if self.ctx.uploads is None:
            raise ValueError("Remote uploads are disabled; configure CHAINSAW_UPLOAD_DIR")
        return self.ctx.uploads

    def chainsaw_upload_begin(
        self,
        name: Annotated[str, Field(description="Original filename, without directories.")],
        size_bytes: Annotated[int, Field(ge=1, description="Exact file length in bytes.")],
        sha256: Annotated[
            str, Field(description="Expected SHA-256 of the complete evidence file.")
        ],
        signature: Annotated[
            dict[str, Any] | None,
            Field(
                description="Trusted Ed25519 attestation of upload name, size and SHA-256."
            ),
        ] = None,
    ) -> str:
        """Reserve a remote evidence upload after verifying its trusted Ed25519 signature.

        Send base64 chunks using chainsaw_upload_chunk, then seal with chainsaw_upload_finish.
        Incomplete uploads remain outside evidence roots. No archive extraction is performed.
        Unsigned uploads are rejected; configure CHAINSAW_UPLOAD_TRUSTED_KEYS_DIR on the server.
        The quota counts retained uploaded evidence plus incomplete reservations.
        """
        return dumps(self._store().begin(name, size_bytes, sha256, signature))

    def chainsaw_upload_chunk(
        self,
        upload_id: Annotated[str, Field(description="Server-issued upl_ handle.")],
        offset: Annotated[
            int, Field(ge=0, description="Byte offset; use next_offset from the server.")
        ],
        data_base64: Annotated[
            str,
            Field(
                max_length=MAX_CHUNK_BYTES * 4 // 3,
                description="Base64-encoded file bytes; at most 196608 decoded bytes per call.",
            ),
        ],
    ) -> str:
        """Append an evidence chunk; retrying identical bytes at the same offset is safe."""
        return dumps(self._store().append(upload_id, offset, data_base64))

    def chainsaw_upload_finish(
        self,
        upload_id: Annotated[str, Field(description="Server-issued upl_ handle.")],
        action: Annotated[
            Literal["finish", "status", "abort"],
            Field(
                description="finish verifies and publishes; status resumes; abort removes staging.",
            ),
        ] = "finish",
    ) -> str:
        """Verify the signature, size and SHA-256, then publish a new read-only evidence file.

        Returns an evidence path accepted by all investigation tools. Published evidence
        cannot be overwritten or deleted. status returns next_offset after a reconnect.
        """
        store = self._store()
        if action == "status":
            return dumps(store.status(upload_id))
        if action == "abort":
            return dumps(store.abort(upload_id))
        return dumps(store.finish(upload_id))

    TOOLS = ("chainsaw_upload_begin", "chainsaw_upload_chunk", "chainsaw_upload_finish")
