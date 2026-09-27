"""Download and verify the pinned Chainsaw release into vendor/chainsaw.

    chainsaw-mcp-bootstrap [--dest vendor/chainsaw] [--skip-sigma] [--force]

The all-platforms bundle carries the binaries for Linux/macOS/Windows, the Chainsaw rules,
the Sigma rule repository, and the Sigma mapping files. Only the binary for this host is
kept. Checksums are pinned to v2.16.5; bump CHAINSAW_RELEASE and the digests together.
"""

from __future__ import annotations

import argparse
import hashlib
import os
import platform
import shutil
import stat
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path

from . import CHAINSAW_RELEASE

BASE_URL = "https://github.com/WithSecureLabs/chainsaw/releases/download"
BUNDLE_NAME = "chainsaw_all_platforms+rules+examples.zip"
BUNDLE_SHA256 = "b007d1d9ccc62ad269fe717593d3ad63e00e994f92a120dbc2c47efb72a92e3d"
BUNDLE_BYTES = 47_568_011

BINARIES = {
    ("Linux", "x86_64"): "chainsaw_x86_64-unknown-linux-gnu",
    ("Linux", "aarch64"): "chainsaw_aarch64-unknown-linux-gnu",
    ("Darwin", "x86_64"): "chainsaw_x86_64-apple-darwin",
    ("Darwin", "arm64"): "chainsaw_aarch64-apple-darwin",
    ("Windows", "AMD64"): "chainsaw_x86_64-pc-windows-msvc.exe",
}
BINARY_SHA256 = {
    "chainsaw_x86_64-unknown-linux-gnu": (
        "1bdbead62a186e61ba2970172fdb4d89052b5b1fe80cc824774bb673c06a87bb"
    ),
}
# Sigma sub-trees that are large and never used by hunts.
SIGMA_SKIP = (
    "sigma/.git/",
    "sigma/tests/",
    "sigma/regression_data/",
    "sigma/images/",
    "sigma/documentation/",
    "sigma/.github/",
)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def download(url: str, dest: Path, *, expected_bytes: int | None = None) -> None:
    print(f"[*] downloading {url}", file=sys.stderr)
    with urllib.request.urlopen(url, timeout=120) as resp, dest.open("wb") as out:  # noqa: S310
        shutil.copyfileobj(resp, out)
    if expected_bytes is not None and dest.stat().st_size != expected_bytes:
        raise SystemExit(f"[x] size mismatch: {dest.stat().st_size} != {expected_bytes}")


def host_binary() -> str:
    key = (platform.system(), platform.machine())
    try:
        return BINARIES[key]
    except KeyError as exc:
        raise SystemExit(f"[x] no chainsaw binary for {key}; set CHAINSAW_BIN manually") from exc


def install(bundle: Path, dest: Path, *, skip_sigma: bool, binary_name: str) -> None:
    prefix = "chainsaw/"
    with zipfile.ZipFile(bundle) as zf:
        members = [m for m in zf.namelist() if m.startswith(prefix)]
        for member in members:
            rel = member[len(prefix) :]
            if not rel or member.endswith("/"):
                continue
            if rel.startswith("EVTX-ATTACK-SAMPLES/"):
                continue
            if rel.startswith("chainsaw_") and rel != binary_name:
                continue
            if rel.startswith("sigma/") and (
                skip_sigma or any(rel.startswith(s) for s in SIGMA_SKIP)
            ):
                continue
            rel_path = Path(rel)
            if rel_path.is_absolute() or ".." in rel_path.parts:
                raise SystemExit(f"[x] refusing suspicious archive member {member}")
            target = dest / ("chainsaw" if rel == binary_name else rel)
            target.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(member) as src, target.open("wb") as out:
                shutil.copyfileobj(src, out)
    binary = dest / "chainsaw"
    binary.chmod(binary.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    expected = BINARY_SHA256.get(binary_name)
    if expected:
        actual = sha256(binary)
        if actual != expected:
            raise SystemExit(f"[x] binary checksum mismatch: {actual}")
    print(f"[+] installed chainsaw {CHAINSAW_RELEASE} into {dest}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="chainsaw-mcp-bootstrap", description=__doc__)
    parser.add_argument(
        "--dest",
        default=os.environ.get("CHAINSAW_VENDOR_DIR", "vendor/chainsaw"),
        help="Install directory (default vendor/chainsaw under the current directory).",
    )
    parser.add_argument("--bundle", help="Use an already-downloaded zip instead of fetching.")
    parser.add_argument("--skip-sigma", action="store_true", help="Do not install Sigma rules.")
    parser.add_argument("--force", action="store_true", help="Replace an existing install.")
    parser.add_argument(
        "--binary", default=None, help="Bundle member name to install as the chainsaw binary."
    )
    args = parser.parse_args(argv)

    dest = Path(args.dest).resolve()
    populated = dest.exists() and any(dest.iterdir())
    if populated and not args.force:
        print(f"[!] {dest} already populated; use --force to replace", file=sys.stderr)
        return 1
    binary_name = args.binary or host_binary()

    with tempfile.TemporaryDirectory() as tmp:
        bundle = Path(args.bundle) if args.bundle else Path(tmp) / BUNDLE_NAME
        if not args.bundle:
            download(
                f"{BASE_URL}/{CHAINSAW_RELEASE}/{BUNDLE_NAME}", bundle, expected_bytes=BUNDLE_BYTES
            )
        actual = sha256(bundle)
        if actual != BUNDLE_SHA256:
            raise SystemExit(f"[x] bundle checksum mismatch: {actual} != {BUNDLE_SHA256}")
        print("[+] bundle checksum verified", file=sys.stderr)
        # Only replace a working install once the new bundle has been fetched and verified.
        if populated:
            shutil.rmtree(dest)
        dest.mkdir(parents=True, exist_ok=True)
        install(bundle, dest, skip_sigma=args.skip_sigma, binary_name=binary_name)
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
