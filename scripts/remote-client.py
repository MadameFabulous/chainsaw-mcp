"""Transfer Ed25519-signed files over certificate-verified MCP HTTPS."""

import argparse
import json
import os
import ssl
import tempfile
from pathlib import Path

import httpx

from chainsaw_mcp.transfers import (
    file_fingerprint,
    key_id,
    load_private_key,
    load_public_key,
    sign_manifest,
    upload_manifest,
    verify_file,
    verify_manifest,
)


class Remote:
    def __init__(self, url, token, *, ca_file=None, transport=None):
        target = httpx.URL(url)
        if target.scheme != "https" or not target.host or target.userinfo:
            raise ValueError("Use an HTTPS MCP endpoint without URL credentials")
        self.url = url
        self.client = httpx.Client(
            headers={
                "Authorization": "Bearer " + token,
                "Accept": "application/json, text/event-stream",
            },
            timeout=600,
            follow_redirects=False,
            transport=transport,
            verify=ssl.create_default_context(cafile=ca_file),
            trust_env=False,
        )
        self.sequence = 0

    def __enter__(self):
        try:
            result = self.request(
                "initialize",
                {
                    "protocolVersion": "2026-07-28",
                    "capabilities": {},
                    "clientInfo": {"name": "chainsaw-remote-client", "version": "1"},
                },
            )
            self.client.headers["MCP-Protocol-Version"] = result["protocolVersion"]
            self.request("notifications/initialized", {}, notification=True)
        except BaseException:
            self.client.close()
            raise
        return self

    def __exit__(self, *args):
        self.client.close()

    def request(self, method, params, *, notification=False):
        self.sequence += 1
        body = {"jsonrpc": "2.0", "method": method, "params": params}
        if not notification:
            body["id"] = self.sequence
        with self.client.stream("POST", self.url, json=body) as response:
            response.raise_for_status()
            if session := response.headers.get("Mcp-Session-Id"):
                self.client.headers["Mcp-Session-Id"] = session
            if notification:
                return None
            if "text/event-stream" in response.headers.get("content-type", ""):
                for line in response.iter_lines():
                    if line.startswith("data:"):
                        result = json.loads(line[5:])
                        if result.get("id") == self.sequence:
                            break
                else:
                    raise RuntimeError("MCP stream ended without a result")
            else:
                result = json.loads(response.read())
        if "error" in result:
            raise RuntimeError(str(result["error"]))
        return result["result"]

    def call(self, name, arguments):
        result = self.request("tools/call", {"name": name, "arguments": arguments})
        text = "".join(item["text"] for item in result["content"] if item["type"] == "text")
        if result.get("isError"):
            raise RuntimeError(text)
        return json.loads(text)


def upload(remote, file, signing_key, resume=None):
    import base64

    fingerprint = file_fingerprint(file)
    manifest = upload_manifest(file.name, **fingerprint)
    signature = sign_manifest(manifest, signing_key)
    if resume:
        state = remote.call("chainsaw_upload_finish", {"upload_id": resume, "action": "status"})
    else:
        state = remote.call(
            "chainsaw_upload_begin",
            {
                "name": file.name,
                **fingerprint,
                "signature": signature,
            },
        )
    trusted = {key_id(signing_key.public_key()): signing_key.public_key()}
    if verify_manifest(state.get("signature"), trusted, purpose="upload") != manifest:
        raise ValueError("Resume file differs from the upload's signed declaration")
    if not 0 <= state["next_offset"] <= manifest["size_bytes"]:
        raise ValueError("Invalid upload resume offset")
    print(
        json.dumps({"upload_id": state["upload_id"], "next_offset": state["next_offset"]}),
        flush=True,
    )
    if state["complete"]:
        return state
    with file.open("rb") as stream:
        stream.seek(state["next_offset"])
        while chunk := stream.read(state["max_chunk_bytes"]):
            state = remote.call(
                "chainsaw_upload_chunk",
                {
                    "upload_id": state["upload_id"],
                    "offset": state["next_offset"],
                    "data_base64": base64.b64encode(chunk).decode("ascii"),
                },
            )
    return remote.call("chainsaw_upload_finish", {"upload_id": state["upload_id"]})


def download(remote, handle, destination, trusted_key):
    receipt = destination.with_name(destination.name + ".signature.json")
    if destination.exists() or receipt.exists():
        raise FileExistsError("Download destination or signature receipt already exists")
    attestation = remote.call("chainsaw_result_manifest", {"handle": handle})
    manifest = verify_manifest(
        attestation, {key_id(trusted_key): trusted_key}, purpose="download"
    )
    if manifest.get("handle") != handle:
        raise ValueError("Signed manifest is not for the requested result handle")
    with tempfile.TemporaryDirectory(prefix=".chainsaw-download-", dir=destination.parent) as work:
        staged = Path(work) / "content"
        with os.fdopen(
            os.open(staged, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb"
        ) as stream:
            offset = 0
            while True:
                result = remote.call(
                    "chainsaw_result_chunk", {"handle": handle, "byte_offset": offset}
                )
                data = result["content"].encode("utf-8")
                if offset + len(data) > manifest["size_bytes"]:
                    raise ValueError("Download exceeds its signed size")
                stream.write(data)
                offset += len(data)
                following = result["next_byte_offset"]
                if following is None:
                    break
                if not data or following != offset:
                    raise ValueError("Invalid download continuation offset")
            stream.flush()
            os.fsync(stream.fileno())
        verify_file(staged, attestation, trusted_key, purpose="download")
        signature_path = Path(work) / "signature.json"
        signature_path.write_text(json.dumps(attestation, indent=2) + "\n")
        signature_path.chmod(0o600)
        os.link(signature_path, receipt)
        try:
            os.link(staged, destination)
        except BaseException:
            receipt.unlink()
            raise
    return {
        "path": str(destination),
        "bytes": manifest["size_bytes"],
        "sha256": manifest["sha256"],
        "signer_key_id": attestation["key_id"],
        "signature_file": str(receipt),
        "verified": True,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", help="Remote MCP URL, e.g. https://forensics.example/mcp")
    parser.add_argument("--token-file", type=Path, required=True)
    parser.add_argument(
        "--ca-file", type=Path, help="CA/certificate PEM for a private TLS endpoint"
    )
    sub = parser.add_subparsers(dest="action", required=True)
    up = sub.add_parser("upload")
    up.add_argument("file", type=Path)
    up.add_argument("--resume", help="upl_ handle printed by an interrupted upload")
    up.add_argument(
        "--signing-key", type=Path, required=True, help="Client Ed25519 private PEM key"
    )
    down = sub.add_parser("download")
    down.add_argument("handle")
    down.add_argument("destination", type=Path)
    down.add_argument(
        "--trusted-key", type=Path, required=True, help="Pinned server Ed25519 public PEM key"
    )
    args = parser.parse_args()
    with Remote(args.url, args.token_file.read_text().strip(), ca_file=args.ca_file) as remote:
        result = (
            upload(remote, args.file, load_private_key(args.signing_key), args.resume)
            if args.action == "upload"
            else download(
                remote,
                args.handle,
                args.destination,
                load_public_key(args.trusted_key),
            )
        )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
