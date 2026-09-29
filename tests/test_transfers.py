"""Trust, tampering, atomic downloads and real certificate-verified HTTPS transfers."""

import base64
import copy
import hashlib
import json
import runpy
import socket
import ssl
import threading
import time
from dataclasses import replace
from pathlib import Path

import httpx
import pytest
import uvicorn
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from chainsaw_mcp.http import http_app
from chainsaw_mcp.server import build_server
from chainsaw_mcp.transfers import (
    generate_keypair,
    load_trusted_keys,
    sign_manifest,
    upload_manifest,
    verify_file,
    verify_manifest,
)
from chainsaw_mcp.uploads import UploadStore
from tests.test_server import call, payload

CLIENT = runpy.run_path(str(Path(__file__).resolve().parents[1] / "scripts/remote-client.py"))
DATA = "evidence café 🔎\n".encode()


def attestation(key, data=DATA, handle="res_0123456789abcdef"):
    return sign_manifest(
        {
            "version": 1,
            "purpose": "download",
            "handle": handle,
            "format": "txt",
            "size_bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        },
        key,
    )


@pytest.mark.parametrize(
    "field,value",
    [("purpose", "download"), ("name", "changed.evtx"), ("size_bytes", 999), ("sha256", "0" * 64)],
)
def test_signed_upload_declaration_cannot_be_changed(transfer_keys, field, value):
    signed = sign_manifest(
        upload_manifest("a.evtx", len(DATA), hashlib.sha256(DATA).hexdigest()), transfer_keys["key"]
    )
    signed["manifest"][field] = value
    with pytest.raises(ValueError, match="signature"):
        verify_manifest(signed, transfer_keys["trusted"], purpose="upload")


def test_unknown_signers_unsigned_and_corrupt_signatures_rejected(transfer_keys):
    signed = attestation(Ed25519PrivateKey.generate())
    with pytest.raises(ValueError, match="Untrusted"):
        verify_manifest(signed, transfer_keys["trusted"], purpose="download")
    with pytest.raises(ValueError, match="required"):
        verify_manifest(None, transfer_keys["trusted"], purpose="download")
    signed = attestation(transfer_keys["key"])
    signed["signature"] = "!"
    with pytest.raises(ValueError, match="signature"):
        verify_manifest(signed, transfer_keys["trusted"], purpose="download")
    with pytest.raises(ValueError, match="No trusted"):
        verify_manifest(signed, {}, purpose="download")


def test_keygen_preserves_existing_keys_and_uses_private_permissions(tmp_path):
    private, public = tmp_path / "private.key", tmp_path / "public.pem"
    signer = generate_keypair(private, public)
    original = private.read_bytes()
    assert private.stat().st_mode & 0o777 == 0o600
    assert signer in load_trusted_keys(tmp_path)
    with pytest.raises(FileExistsError):
        generate_keypair(private, public)
    assert private.read_bytes() == original
    other = tmp_path / "other.key"
    with pytest.raises(FileExistsError):
        generate_keypair(other, public)
    assert not other.exists()


def test_upload_fails_closed_and_rechecks_before_publication(tmp_path, transfer_keys):
    store = UploadStore(
        tmp_path / "uploads",
        max_bytes=1000,
        quota_bytes=2000,
        trusted_keys=transfer_keys["trusted"],
    )
    digest = hashlib.sha256(DATA).hexdigest()
    with pytest.raises(ValueError, match="required"):
        store.begin("x.evtx", len(DATA), digest)
    signature = sign_manifest(upload_manifest("x.evtx", len(DATA), digest), transfer_keys["key"])
    with pytest.raises(ValueError, match="differs"):
        store.begin("renamed.evtx", len(DATA), digest, signature)
    started = store.begin("x.evtx", len(DATA), digest, signature)
    store.append(started["upload_id"], 0, base64.b64encode(DATA).decode())
    # A restart after removal of the trusted key must not publish a staged file.
    revoked = UploadStore(store.directory, max_bytes=1000, quota_bytes=2000)
    with pytest.raises(ValueError, match="No trusted"):
        revoked.finish(started["upload_id"])
    assert list(store.evidence.iterdir()) == []
    assert store.finish(started["upload_id"])["signature"] == signature


def upload_store(tmp_path, transfer_keys):
    return UploadStore(
        tmp_path / "uploads",
        max_bytes=1000,
        quota_bytes=2000,
        trusted_keys=transfer_keys["trusted"],
    )


def upload_signature(transfer_keys, name="x.evtx"):
    digest = hashlib.sha256(DATA).hexdigest()
    return digest, sign_manifest(upload_manifest(name, len(DATA), digest), transfer_keys["key"])


def test_upload_stores_only_signature_envelope_fields(tmp_path, transfer_keys):
    store = upload_store(tmp_path, transfer_keys)
    digest, signature = upload_signature(transfer_keys)
    started = store.begin("x.evtx", len(DATA), digest, {**signature, "note": "unsigned extra"})
    assert started["signature"] == signature
    stored = json.loads((store.staging / f"{started['upload_id']}.json").read_text())
    assert stored["signature"] == signature


def test_failed_upload_reservation_leaves_no_staging_files(tmp_path, transfer_keys, monkeypatch):
    store = upload_store(tmp_path, transfer_keys)
    digest, signature = upload_signature(transfer_keys)

    def interrupted(fd):
        raise OSError("disk full")

    monkeypatch.setattr("chainsaw_mcp.uploads.os.fsync", interrupted)
    with pytest.raises(OSError, match="disk full"):
        store.begin("x.evtx", len(DATA), digest, signature)
    assert list(store.staging.iterdir()) == []


@pytest.mark.parametrize("damaged", ["{not json", '{"size_bytes": "big"}'])
def test_upload_quota_refuses_new_uploads_with_unreadable_reservation(
    tmp_path, transfer_keys, caplog, damaged
):
    store = upload_store(tmp_path, transfer_keys)
    record = "upl_" + "0" * 32 + ".json"
    (store.staging / record).write_text(damaged)
    digest, signature = upload_signature(transfer_keys)
    with (
        caplog.at_level("ERROR", logger="chainsaw_mcp.uploads"),
        pytest.raises(ValueError, match=f"reservation {record} is unreadable; reconcile"),
    ):
        store.begin("x.evtx", len(DATA), digest, signature)
    assert record in caplog.text
    assert list(store.staging.glob("upl_*.part")) == []


def test_corrupt_published_reservation_still_counts_toward_quota(tmp_path, transfer_keys):
    store = UploadStore(
        tmp_path / "uploads",
        max_bytes=100,
        quota_bytes=len(DATA),
        trusted_keys=transfer_keys["trusted"],
    )
    digest, signature = upload_signature(transfer_keys)
    first = store.begin("x.evtx", len(DATA), digest, signature)["upload_id"]
    store.append(first, 0, base64.b64encode(DATA).decode())
    assert store.finish(first)["complete"]
    (store.staging / f"{first}.json").write_text("{damaged")
    digest, signature = upload_signature(transfer_keys, "y.evtx")
    with pytest.raises(ValueError, match="unreadable"):
        store.begin("y.evtx", len(DATA), digest, signature)
    assert [p.name for p in store.evidence.iterdir()] == [first]


def test_upload_quota_error_names_the_retention_contract(tmp_path, transfer_keys):
    store = UploadStore(
        tmp_path / "uploads", max_bytes=100, quota_bytes=1, trusted_keys=transfer_keys["trusted"]
    )
    digest, signature = upload_signature(transfer_keys)
    with pytest.raises(ValueError) as caught:
        store.begin("x.evtx", len(DATA), digest, signature)
    message = str(caught.value)
    assert "retained uploaded evidence plus incomplete reservations" in message
    assert "reservation record offline" in message


class DownloadRemote:
    def __init__(self, signed, data=DATA, *, truncate=False, bad_offset=False):
        self.signed, self.data = signed, data
        self.truncate, self.bad_offset = truncate, bad_offset

    def call(self, name, arguments):
        if name == "chainsaw_result_manifest":
            return copy.deepcopy(self.signed)
        offset = arguments["byte_offset"]
        # Split only on a UTF-8 boundary, exercising both byte offsets and Unicode.
        end = 9 if offset == 0 else len(self.data)
        following = None if self.truncate or end == len(self.data) else end
        return {
            "content": self.data[offset:end].decode(),
            "next_byte_offset": 0 if self.bad_offset else following,
        }


@pytest.mark.parametrize("failure", ["bytes", "truncated", "offset", "signature", "handle"])
def test_failed_download_never_publishes_file_or_receipt(tmp_path, transfer_keys, failure):
    signed = attestation(transfer_keys["key"])
    data = DATA.replace(b"evidence", b"modified") if failure == "bytes" else DATA
    if failure == "signature":
        signed["signature"] = base64.b64encode(b"x" * 64).decode()
    if failure == "handle":
        signed = attestation(transfer_keys["key"], handle="res_ffffffffffffffff")
    remote = DownloadRemote(
        signed, data, truncate=failure == "truncated", bad_offset=failure == "offset"
    )
    destination = tmp_path / "result.txt"
    with pytest.raises(ValueError):
        CLIENT["download"](
            remote, "res_0123456789abcdef", destination, transfer_keys["key"].public_key()
        )
    assert list(tmp_path.glob("result*")) == []
    assert list(tmp_path.glob(".chainsaw-download-*")) == []


def test_download_preserves_signature_for_offline_verification(tmp_path, transfer_keys):
    signed = attestation(transfer_keys["key"])
    destination = tmp_path / "result.txt"
    result = CLIENT["download"](
        DownloadRemote(signed),
        "res_0123456789abcdef",
        destination,
        transfer_keys["key"].public_key(),
    )
    assert result["verified"] and destination.read_bytes() == DATA
    assert destination.stat().st_mode & 0o777 == 0o600
    receipt = json.loads(Path(result["signature_file"]).read_text())
    assert (
        verify_file(destination, receipt, transfer_keys["key"].public_key(), purpose="download")
        == signed["manifest"]
    )
    with pytest.raises(ValueError, match="purpose"):
        verify_file(destination, receipt, transfer_keys["key"].public_key(), purpose="upload")
    with pytest.raises(FileExistsError):
        CLIENT["download"](
            DownloadRemote(signed),
            "res_0123456789abcdef",
            destination,
            transfer_keys["key"].public_key(),
        )


def test_client_refuses_plaintext_before_connecting():
    with pytest.raises(ValueError, match="HTTPS"):
        CLIENT["Remote"]("http://127.0.0.1:18098/mcp", "secret")


def test_signed_download_unavailable_without_server_key(settings):
    result = call(build_server(settings), "chainsaw_result_manifest", {"handle": "res_" + "0" * 16})
    assert result.is_error and "CHAINSAW_TRANSFER_SIGNING_KEY_FILE" in result.content[0].text


def test_real_https_signed_upload_and_download(settings, transfer_keys, tls_files, tmp_path):
    large_data = DATA * 20000
    secure = replace(
        settings,
        upload_dir=tmp_path / "uploads",
        upload_trusted_keys_dir=transfer_keys["directory"],
        transfer_signing_key_file=transfer_keys["private"],
    )
    server = build_server(secure)
    store = server._chainsaw_ctx.store
    handle, path = store.reserve(".txt")
    path.write_bytes(large_data)
    store.commit(handle, tool="fixture", argv=[], inputs={}, fmt="txt")
    signed = payload(call(server, "chainsaw_result_manifest", {"handle": handle}))
    assert (
        verify_manifest(signed, transfer_keys["trusted"], purpose="download")["sha256"]
        == hashlib.sha256(large_data).hexdigest()
    )
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    app = http_app(
        server, host="127.0.0.1", port=port, path="/mcp", json_response=True, token="a" * 64
    )
    config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=port,
        log_level="error",
        ssl_certfile=str(tls_files[0]),
        ssl_keyfile=str(tls_files[1]),
        ssl_version=ssl.PROTOCOL_TLS_SERVER,
        proxy_headers=False,
    )
    listener = uvicorn.Server(config)
    thread = threading.Thread(target=listener.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 5
        while not listener.started and time.monotonic() < deadline:
            time.sleep(0.01)
        assert listener.started
        url = f"https://127.0.0.1:{port}/mcp"
        with (
            pytest.raises(httpx.ConnectError, match="CERTIFICATE_VERIFY_FAILED"),
            CLIENT["Remote"](url, "a" * 64),
        ):
            pass
        context = ssl.create_default_context(cafile=tls_files[0])
        with (
            socket.create_connection(("127.0.0.1", port)) as connection,
            pytest.raises(ssl.SSLCertVerificationError, match="Hostname mismatch"),
        ):
            context.wrap_socket(connection, server_hostname="wrong.example")
        with CLIENT["Remote"](url, "a" * 64, ca_file=tls_files[0]) as remote:
            source = tmp_path / "input.evtx"
            source.write_bytes(large_data)
            uploaded = CLIENT["upload"](remote, source, transfer_keys["key"])
            assert uploaded["complete"] and Path(uploaded["path"]).read_bytes() == large_data
            destination = tmp_path / "download.txt"
            CLIENT["download"](remote, handle, destination, transfer_keys["key"].public_key())
            assert destination.read_bytes() == large_data
            with pytest.raises(ValueError, match="Untrusted"):
                CLIENT["download"](
                    remote,
                    handle,
                    tmp_path / "untrusted.txt",
                    Ed25519PrivateKey.generate().public_key(),
                )
    finally:
        listener.should_exit = True
        thread.join(10)
        sock.close()
    assert not thread.is_alive()
