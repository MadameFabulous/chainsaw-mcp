"""Ed25519 file attestations, with trust supplied independently of the transferred data."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

_DOMAIN = b"chainsaw-mcp-transfer-v1\n"
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
PURPOSES = ("upload", "download", "evidence-manifest", "evidence-validation")


def file_fingerprint(path: Path) -> dict[str, Any]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(chunk)
            digest.update(chunk)
    return {"size_bytes": size, "sha256": digest.hexdigest()}


def load_private_key(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("Transfer signing key must be an Ed25519 private key")
    return key


def load_public_key(path: Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("Transfer trust key must be an Ed25519 public key")
    return key


def key_id(key: Ed25519PublicKey) -> str:
    return hashlib.sha256(key.public_bytes_raw()).hexdigest()


def load_trusted_keys(
    directory: Path | None, *, purpose: str = "upload"
) -> dict[str, Ed25519PublicKey]:
    if directory is None:
        return {}
    if not directory.is_dir():
        raise ValueError(f"{purpose.capitalize()} trust directory does not exist")
    keys = [load_public_key(path) for path in sorted(directory.glob("*.pem"))]
    if not keys:
        raise ValueError(
            f"{purpose.capitalize()} trust directory must contain Ed25519 public .pem files"
        )
    return {key_id(key): key for key in keys}


def upload_manifest(name: str, size_bytes: int, sha256: str) -> dict[str, Any]:
    return {
        "version": 1,
        "purpose": "upload",
        "name": name,
        "size_bytes": size_bytes,
        "sha256": sha256.lower(),
    }


def _message(manifest: dict[str, Any]) -> bytes:
    return _DOMAIN + json.dumps(
        manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False
    ).encode("utf-8")


def sign_manifest(manifest: dict[str, Any], key: Ed25519PrivateKey) -> dict[str, Any]:
    return {
        "algorithm": "Ed25519",
        "key_id": key_id(key.public_key()),
        "manifest": manifest,
        "signature": base64.b64encode(key.sign(_message(manifest))).decode("ascii"),
    }


def verify_manifest(
    attestation: dict[str, Any] | None,
    trusted_keys: dict[str, Ed25519PublicKey],
    *,
    purpose: str | Iterable[str],
) -> dict[str, Any]:
    """Verify against operator-pinned keys, never a public key supplied in the envelope.

    The caller names the purpose(s) it accepts, so one kind of signature cannot stand in
    for another (a custody record is not a download).
    """
    allowed = {purpose} if isinstance(purpose, str) else set(purpose)
    if not trusted_keys:
        raise ValueError("No trusted transfer signing keys configured")
    if not isinstance(attestation, dict) or attestation.get("algorithm") != "Ed25519":
        raise ValueError("An Ed25519 file signature is required")
    signer_id = attestation.get("key_id")
    if not isinstance(signer_id, str) or signer_id not in trusted_keys:
        raise ValueError("Untrusted transfer signing key")
    manifest = attestation.get("manifest")
    if not isinstance(manifest, dict):
        raise ValueError("Invalid signed transfer manifest")
    try:
        signature = base64.b64decode(attestation["signature"], validate=True)
        trusted_keys[signer_id].verify(signature, _message(manifest))
    except (InvalidSignature, KeyError, TypeError, ValueError, binascii.Error):
        raise ValueError("Invalid transfer signature") from None
    if (
        type(manifest.get("version")) is not int
        or manifest["version"] != 1
        or manifest.get("purpose") not in PURPOSES
        or type(manifest.get("size_bytes")) is not int
        or manifest["size_bytes"] < 0
        or not isinstance(manifest.get("sha256"), str)
        or not _DIGEST.fullmatch(manifest["sha256"])
    ):
        raise ValueError("Invalid signed transfer manifest")
    if manifest["purpose"] not in allowed:
        raise ValueError(
            f"Signed manifest purpose {manifest['purpose']!r} is not the expected "
            + " or ".join(repr(p) for p in sorted(allowed))
        )
    return manifest


def verify_file(
    path: Path,
    attestation: dict[str, Any],
    key: Ed25519PublicKey,
    *,
    purpose: str | Iterable[str],
) -> dict[str, Any]:
    manifest = verify_manifest(attestation, {key_id(key): key}, purpose=purpose)
    fingerprint = file_fingerprint(path)
    if any(fingerprint[field] != manifest[field] for field in fingerprint):
        raise ValueError("File size or SHA-256 differs from its signed manifest")
    return manifest


def generate_keypair(private_path: Path, public_path: Path) -> str:
    """Create a fresh pair without replacing keys or leaving a private key world-readable."""
    if private_path.resolve() == public_path.resolve():
        raise ValueError("Private and public key paths must differ")
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    created = []
    try:
        for path, data in ((private_path, private), (public_path, public)):
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            created.append(path)
            with os.fdopen(fd, "wb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
    except BaseException:
        for path in created:
            path.unlink(missing_ok=True)
        raise
    return key_id(key.public_key())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    generate = sub.add_parser("keygen", help="Generate an Ed25519 signing key and public trust key")
    generate.add_argument("--private-key", type=Path, required=True)
    generate.add_argument("--public-key", type=Path, required=True)
    verify = sub.add_parser("verify", help="Verify a saved transfer against a pinned public key")
    verify.add_argument("file", type=Path)
    verify.add_argument("--signature-file", type=Path, required=True)
    verify.add_argument("--trusted-key", type=Path, required=True)
    verify.add_argument(
        "--purpose",
        choices=PURPOSES,
        default="download",
        help="Signature purpose the file must carry (default: download)",
    )
    args = parser.parse_args()
    result: dict[str, Any]
    if args.action == "keygen":
        result = {"key_id": generate_keypair(args.private_key, args.public_key)}
    else:
        manifest = verify_file(
            args.file,
            json.loads(args.signature_file.read_text()),
            load_public_key(args.trusted_key),
            purpose=args.purpose,
        )
        result = {"verified": True, "manifest": manifest}
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
