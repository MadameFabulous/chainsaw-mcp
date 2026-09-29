"""Evidence manifests preserve scope and fail closed on trust, path and observation errors."""

import json
import os
import shutil
import time
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from chainsaw_mcp import custody, transfers
from chainsaw_mcp.config import load_settings
from chainsaw_mcp.server import build_server
from chainsaw_mcp.transfers import (
    file_fingerprint,
    generate_keypair,
    sign_manifest,
    verify_file,
    verify_manifest,
)
from tests.test_server import call, payload


@pytest.fixture
def case(settings, transfer_keys):
    root = settings.evidence_roots[0] / "case-A"
    root.mkdir()
    (root / "Security.evtx").write_bytes(b"original evidence")
    (root / ".hidden").write_bytes(b"hidden evidence")
    (root / "notes.md").write_text("analyst notes")
    (root / "empty").mkdir()
    (root / "café.bin").write_bytes(b"")
    secure = replace(settings, transfer_signing_key_file=transfer_keys["private"])
    return build_server(secure), root, transfer_keys


def manifest(case, **arguments):
    server, root, _ = case
    result = call(server, "chainsaw_evidence_manifest", {"path": str(root), **arguments})
    assert not result.is_error, result.content
    return payload(result)


def validate(case, baseline, **arguments):
    server, root, _ = case
    result = call(
        server,
        "chainsaw_evidence_validate",
        {
            "path": str(root),
            "manifest": baseline["manifest_handle"],
            "signature": baseline["signature_handle"],
            **arguments,
        },
    )
    assert not result.is_error, result.content
    return payload(result)


def rows(server, handle):
    return list(server._chainsaw_ctx.store.rows(handle))


def save_rows(server, values):
    store = server._chainsaw_ctx.store
    handle, path = store.reserve()
    with path.open("w") as stream:
        for row in values:
            stream.write(json.dumps(row) + "\n")
    store.commit(handle, tool="fixture", argv=[], inputs={})
    return handle


def sign_artifact(server, handle, key, purpose="evidence-manifest"):
    data = server._chainsaw_ctx.store.data_path(handle)
    return save_rows(
        server, [sign_manifest({"version": 1, "purpose": purpose, **file_fingerprint(data)}, key)]
    )


def test_signed_manifest_covers_hidden_files_unknown_extensions_and_empty_directories(case):
    server, root, keys = case
    before = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in root.iterdir() if p.is_file()}
    baseline = manifest(
        case,
        context={"case_id": "IR-42", "operator": "Analyst A", "snapshot_id": "declared-snapshot"},
    )
    contents = rows(server, baseline["manifest_handle"])
    assert contents[0]["operator_declarations"]["case_id"] == "IR-42"
    assert contents[0]["policy"]["include_hidden"] is True
    assert {row["path"] for row in contents[1:-1]} == {
        ".",
        ".hidden",
        "Security.evtx",
        "notes.md",
        "empty",
        "café.bin",
    }
    assert (baseline["entry_count"], baseline["file_count"]) == (6, 4)
    signed = rows(server, baseline["signature_handle"])[0]
    descriptor = verify_file(
        server._chainsaw_ctx.store.data_path(baseline["manifest_handle"]),
        signed,
        keys["key"].public_key(),
        purpose="evidence-manifest",
    )
    assert descriptor["purpose"] == "evidence-manifest"
    assert before == {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in before}
    result = validate(case, baseline, context={"action": "verify before analysis"})
    assert result["valid"] and result["status"] == "match" and result["matched_files"] == 4
    receipt = rows(server, result["validation_handle"])
    assert receipt[0]["manifest_reference"]["sha256"] == baseline["sha256"]
    assert receipt[-1]["stability_check"] == "passed"
    verified = verify_file(
        server._chainsaw_ctx.store.data_path(result["validation_handle"]),
        rows(server, result["signature_handle"])[0],
        keys["key"].public_key(),
        purpose="evidence-validation",
    )
    assert verified["purpose"] == "evidence-validation"


def test_custody_signature_does_not_verify_as_a_download(case, tmp_path, monkeypatch, capsys):
    server, _, keys = case
    baseline = manifest(case)
    data = server._chainsaw_ctx.store.data_path(baseline["manifest_handle"])
    signed = rows(server, baseline["signature_handle"])[0]
    with pytest.raises(ValueError, match="purpose"):
        verify_file(data, signed, keys["key"].public_key(), purpose="download")
    with pytest.raises(ValueError, match="purpose"):
        verify_manifest(signed, keys["trusted"], purpose=("download", "upload"))
    signature_file = tmp_path / "manifest-signature.json"
    signature_file.write_text(json.dumps(signed))
    command = [
        "chainsaw-mcp-transfer",
        "verify",
        str(data),
        "--signature-file",
        str(signature_file),
        "--trusted-key",
        str(keys["public"]),
    ]
    monkeypatch.setattr("sys.argv", command)
    with pytest.raises(ValueError, match="purpose"):
        transfers.main()
    monkeypatch.setattr("sys.argv", [*command, "--purpose", "evidence-manifest"])
    transfers.main()
    assert json.loads(capsys.readouterr().out)["manifest"]["purpose"] == "evidence-manifest"


def test_relocated_copy_and_changed_mtime_are_separate_from_byte_integrity(case):
    server, root, _ = case
    baseline = manifest(case)
    copied = root.parent / "relocated"
    shutil.copytree(root, copied)
    source = copied / "Security.evtx"
    info = source.stat()
    os.utime(source, ns=(info.st_atime_ns, info.st_mtime_ns + 1_000_000_000))
    result = validate(case, baseline, path=str(copied))
    assert result["status"] == "match" and result["metadata_changed"] >= 1
    assert result["valid"]
    assert any(row.get("metadata_changed") for row in rows(server, result["validation_handle"]))


def test_changes_missing_and_added_entries_are_reported(case):
    server, root, _ = case
    baseline = manifest(case)
    (root / "Security.evtx").write_bytes(b"modified evidence")
    (root / ".hidden").unlink()
    (root / ".new-hidden").write_bytes(b"new")
    (root / "notes.md").unlink()
    (root / "notes.md").mkdir()
    result = validate(case, baseline)
    assert result["status"] == "mismatch" and not result["valid"]
    assert {
        key: result["counts"][key] for key in ("changed", "missing", "unexpected", "type_changed")
    } == {"changed": 1, "missing": 1, "unexpected": 1, "type_changed": 1}
    changed = next(
        row
        for row in rows(server, result["validation_handle"])
        if row.get("path") == "Security.evtx"
    )
    assert changed["expected_sha256"] != changed["observed_sha256"]


def test_size_difference_does_not_require_reading_the_changed_file(case, monkeypatch):
    _, root, _ = case
    baseline = manifest(case)
    target = root / "Security.evtx"
    target.write_bytes(b"different size")
    original = custody.hash_entry

    def checked(fd, name, entry, limits):
        assert name != target.name
        return original(fd, name, entry, limits)

    monkeypatch.setattr(custody, "hash_entry", checked)
    assert validate(case, baseline)["counts"]["changed"] == 1


@pytest.mark.parametrize("link_kind", ["file", "directory", "fifo"])
def test_manifest_rejects_links_and_special_files_without_publishing(case, link_kind):
    server, root, _ = case
    if link_kind == "fifo":
        os.mkfifo(root / "bad")
    else:
        (root / "bad").symlink_to(root / ("empty" if link_kind == "directory" else "Security.evtx"))
    result = call(server, "chainsaw_evidence_manifest", {"path": str(root)})
    assert result.is_error and "Unsupported" in result.content[0].text
    assert server._chainsaw_ctx.store.list() == []
    assert not list(server._chainsaw_ctx.store.directory.glob("*.pending"))


def test_validation_does_not_follow_replacement_symlinks(case):
    server, root, _ = case
    baseline = manifest(case)
    (root / "Security.evtx").unlink()
    (root / "Security.evtx").symlink_to(root.parent.parent / "outside" / "secret.evtx")
    result = validate(case, baseline)
    assert result["status"] == "mismatch" and result["counts"]["type_changed"] == 1
    assert not any(
        "observed_sha256" in row
        for row in rows(server, result["validation_handle"])
        if row.get("path") == "Security.evtx"
    )


@pytest.mark.parametrize("attack", ["tampered", "unknown_signer", "wrong_purpose"])
def test_untrusted_manifests_are_rejected_before_inventory(case, monkeypatch, attack):
    server, _, keys = case
    baseline = manifest(case)
    if attack == "tampered":
        server._chainsaw_ctx.store.data_path(baseline["manifest_handle"]).write_text("{}\n")
    else:
        key = Ed25519PrivateKey.generate() if attack == "unknown_signer" else keys["key"]
        baseline["signature_handle"] = sign_artifact(
            server,
            baseline["manifest_handle"],
            key,
            "download" if attack == "wrong_purpose" else "evidence-manifest",
        )

    def no_inventory(*args, **kwargs):
        raise AssertionError("Untrusted manifest reached evidence scan")

    monkeypatch.setattr(custody, "inventory", no_inventory)
    result = call(
        server,
        "chainsaw_evidence_validate",
        {
            "path": str(case[1]),
            "manifest": baseline["manifest_handle"],
            "signature": baseline["signature_handle"],
        },
    )
    assert result.is_error


@pytest.mark.parametrize(
    "bad_path", ["../outside/secret.evtx", "/etc/passwd", "empty/../notes.md", "empty//child", "."]
)
def test_even_signed_manifests_cannot_inject_paths(case, bad_path):
    server, root, keys = case
    baseline = manifest(case)
    contents = rows(server, baseline["manifest_handle"])
    next(row for row in contents if row.get("kind") == "file")["path"] = bad_path
    altered = save_rows(server, contents)
    signature = sign_artifact(server, altered, keys["key"])
    result = call(
        server,
        "chainsaw_evidence_validate",
        {"path": str(root), "manifest": altered, "signature": signature},
    )
    assert result.is_error and "unsafe" in result.content[0].text


@pytest.mark.parametrize(
    "malformation",
    ["truncated", "trailing", "counts", "header", "timestamp", "declarations", "parent", "extra"],
)
def test_signed_malformed_manifests_are_rejected_before_inventory(case, monkeypatch, malformation):
    server, root, keys = case
    baseline = manifest(case)
    contents = rows(server, baseline["manifest_handle"])
    if malformation == "truncated":
        contents.pop()
    elif malformation == "trailing":
        contents.append(contents[-1])
    elif malformation == "counts":
        contents[-1]["entry_count"] += 1
    elif malformation == "header":
        del contents[0]["source_path"]
    elif malformation == "timestamp":
        contents[0]["started_at"] = "2026-09-29T12:00:00"
    elif malformation == "declarations":
        contents[0]["operator_declarations"] = {"verified_identity": True}
    elif malformation == "parent":
        contents[2]["path"] = "missing-parent/child"
    else:
        contents[1]["hash_algorithm"] = "MD5"
    altered = save_rows(server, contents)
    signature = sign_artifact(server, altered, keys["key"])

    def no_inventory(*args, **kwargs):
        raise AssertionError("Malformed manifest reached evidence scan")

    monkeypatch.setattr(custody, "inventory", no_inventory)
    result = call(
        server,
        "chainsaw_evidence_validate",
        {"path": str(root), "manifest": altered, "signature": signature},
    )
    assert result.is_error


@pytest.mark.parametrize("raw", [b'{"kind": "manifest", "kind": "completion"}', b'{"v": NaN}'])
def test_ambiguous_json_is_rejected(raw):
    with pytest.raises(ValueError):
        custody.read_json(raw)


def test_link_substitution_between_inventory_and_open_is_not_followed(case, monkeypatch):
    _, root, _ = case
    baseline = manifest(case)
    original = custody.hash_entry
    secret = root.parent.parent / "outside" / "secret.evtx"
    with custody.open_checked(secret) as fd:
        secret_identity = os.fstat(fd).st_dev, os.fstat(fd).st_ino
    original_read = os.read

    def checked_read(fd, size):
        info = os.fstat(fd)
        assert (info.st_dev, info.st_ino) != secret_identity, "Followed a substituted link"
        return original_read(fd, size)

    def substitute(fd, name, entry, limits):
        if name == "Security.evtx":
            (root / name).unlink()
            (root / name).symlink_to(secret)
        return original(fd, name, entry, limits)

    monkeypatch.setattr(custody.os, "read", checked_read)
    monkeypatch.setattr(custody, "hash_entry", substitute)
    result = validate(case, baseline)
    assert result["status"] == "incomplete" and not result["valid"]


def test_archived_manifests_can_be_validated_after_handles_expire(case):
    server, root, _ = case
    baseline = manifest(case)
    archive = root.parent / "custody-records"
    archive.mkdir()
    saved = archive / "manifest.jsonl"
    signature = archive / "signature.json"
    store = server._chainsaw_ctx.store
    shutil.copyfile(store.data_path(baseline["manifest_handle"]), saved)
    shutil.copyfile(store.data_path(baseline["signature_handle"]), signature)
    store.delete(baseline["manifest_handle"])
    store.delete(baseline["signature_handle"])
    result = validate(case, {"manifest_handle": str(saved), "signature_handle": str(signature)})
    assert result["valid"]


def test_external_signers_need_separate_custody_trust(case, tmp_path):
    server, root, keys = case
    baseline = manifest(case)
    private, public = tmp_path / "next.key", tmp_path / "next.pem"
    generate_keypair(private, public)
    next_settings = replace(server._chainsaw_ctx.settings, transfer_signing_key_file=private)
    next_server = build_server(next_settings)
    arguments = {
        "path": str(root),
        "manifest": baseline["manifest_handle"],
        "signature": baseline["signature_handle"],
    }
    assert call(next_server, "chainsaw_evidence_validate", arguments).is_error
    trusted_server = build_server(
        replace(next_settings, custody_trusted_keys_dir=keys["directory"])
    )
    assert payload(call(trusted_server, "chainsaw_evidence_validate", arguments))["valid"]


@pytest.mark.parametrize("action", ["manifest", "validate"])
def test_collection_mutation_during_hashing_never_produces_a_match(case, monkeypatch, action):
    server, root, _ = case
    baseline = manifest(case) if action == "validate" else None
    original = custody.hash_entry

    def mutate(fd, name, entry, limits):
        digest = original(fd, name, entry, limits)
        if name == "Security.evtx":
            (root / name).write_bytes(b"changed after it was hashed")
        return digest

    monkeypatch.setattr(custody, "hash_entry", mutate)
    if baseline:
        result = validate(case, baseline)
        assert result["status"] == "incomplete" and not result["valid"]
    else:
        result = call(server, "chainsaw_evidence_manifest", {"path": str(root)})
        assert result.is_error and "changed" in result.content[0].text
        assert server._chainsaw_ctx.store.list() == []


def test_unreadable_entries_produce_signed_incomplete_receipts(case, monkeypatch):
    server, _, keys = case
    baseline = manifest(case)
    original = custody.hash_entry

    def fail(fd, name, entry, limits):
        if name == ".hidden":
            raise PermissionError("test file unreadable")
        return original(fd, name, entry, limits)

    monkeypatch.setattr(custody, "hash_entry", fail)
    result = validate(case, baseline)
    assert (
        result["status"] == "incomplete"
        and not result["valid"]
        and result["counts"]["unreadable"] == 1
    )
    assert (
        verify_manifest(
            rows(server, result["signature_handle"])[0],
            keys["trusted"],
            purpose="evidence-validation",
        )["purpose"]
        == "evidence-validation"
    )


def test_limits_cannot_be_reported_as_complete(case):
    server, root, _ = case
    for limit in ({"max_entries": 1}, {"max_total_bytes": 1}):
        assert call(server, "chainsaw_evidence_manifest", {"path": str(root), **limit}).is_error
    baseline = manifest(case)
    assert validate(case, baseline, max_total_bytes=1)["status"] == "incomplete"
    with (
        custody.open_checked(root, directory=True) as fd,
        pytest.raises(ValueError, match="time budget"),
    ):
        custody.inventory(fd, custody.Limits(100, 100, time.monotonic() - 1), strict=True)


def test_receipts_have_their_own_limit_and_are_signed_when_truncated(case, monkeypatch):
    server, root, keys = case
    baseline = manifest(case)
    cap = server._chainsaw_ctx.store.data_path(baseline["manifest_handle"]).stat().st_size
    # Receipt rows are larger than manifest rows: a manifest at the cap must still validate.
    monkeypatch.setattr(custody, "MAX_MANIFEST_BYTES", cap)
    assert validate(case, baseline)["status"] == "match"
    for index in range(40 * custody.RECEIPT_SIZE_FACTOR):
        (root / f"added-{index:04d}.bin").write_bytes(b"")
    (root / "Security.evtx").write_bytes(b"changed")
    result = validate(case, baseline)
    assert result["status"] == "incomplete" and not result["valid"]
    assert result["truncated"] and result["mismatches_found"]
    receipt = rows(server, result["validation_handle"])
    assert receipt[-1]["kind"] == "completion" and receipt[-1]["truncated"]
    assert any(row.get("status") == "truncated" for row in receipt)
    verify_file(
        server._chainsaw_ctx.store.data_path(result["validation_handle"]),
        rows(server, result["signature_handle"])[0],
        keys["key"].public_key(),
        purpose="evidence-validation",
    )


def test_truncated_matched_directory_row_does_not_change_counters(case, monkeypatch):
    server, root, keys = case
    tree = root.parent / "directories-only"
    (tree / "z").mkdir(parents=True)
    scoped = (server, tree, keys)
    baseline = manifest(scoped)
    for index in range(41):
        (tree / f"a{index:03d}").write_bytes(b"")
    full = validate(scoped, baseline)
    assert not full["truncated"] and full["counts"]["matched"] == 2
    lines = server._chainsaw_ctx.store.data_path(full["validation_handle"]).read_bytes()
    lines = lines.splitlines(keepends=True)
    index = next(i for i, line in enumerate(lines) if json.loads(line).get("path") == "z")
    before_z = sum(len(line) for line in lines[:index])
    # Truncate exactly on the matched directory row "z", after all unexpected rows fit.
    cap = (2 * before_z + len(lines[index])) // (2 * custody.RECEIPT_SIZE_FACTOR)
    assert server._chainsaw_ctx.store.data_path(baseline["manifest_handle"]).stat().st_size <= cap
    monkeypatch.setattr(custody, "MAX_MANIFEST_BYTES", cap)
    result = validate(scoped, baseline)
    receipt = rows(server, result["validation_handle"])
    assert result["truncated"] and not any(row.get("path") == "z" for row in receipt)
    written = [row for row in receipt if row["kind"] == "entry"]
    assert result["matched_files"] == 0
    assert result["metadata_changed"] == sum(row.get("metadata_changed", 0) for row in written)
    assert result["counts"]["matched"] == 1 and result["counts"]["unexpected"] == 41


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores permission bits")
def test_unreadable_paths_are_recorded_without_aborting_validation(case):
    server, root, _ = case
    (root / "sub").mkdir()
    (root / "sub/inner.txt").write_text("inner")
    baseline = manifest(case)
    (root / "Security.evtx").write_bytes(b"changed evidence")
    (root / "sub").chmod(0)
    (root / "notes.md").chmod(0)
    try:
        result = validate(case, baseline)
    finally:
        (root / "sub").chmod(0o700)
        (root / "notes.md").chmod(0o600)
    assert result["status"] == "incomplete" and result["mismatches_found"]
    assert result["counts"]["unreadable"] == 3 and "error" not in result["counts"]
    statuses = {
        row["path"]: row["status"]
        for row in rows(server, result["validation_handle"])
        if row["kind"] == "entry"
    }
    assert statuses["sub"] == statuses["sub/inner.txt"] == statuses["notes.md"] == "unreadable"
    assert statuses["Security.evtx"] == "changed" and statuses["café.bin"] == "matched"


def test_path_scope_context_and_missing_signing_key_fail_closed(settings, case):
    server, root, _ = case
    assert call(build_server(settings), "chainsaw_evidence_manifest", {"path": str(root)}).is_error
    for args in (
        {"path": str(root.parent.parent / "outside")},
        {"path": str(root / "Security.evtx")},
        {"path": str(root), "context": {"unknown_field": "unsupported"}},
        {"path": str(root), "context": {"previous_manifest_sha256": "invalid"}},
    ):
        assert call(server, "chainsaw_evidence_manifest", args).is_error
    configured = load_settings(
        {"CHAINSAW_HOME": str(root.parent.parent), "CHAINSAW_CUSTODY_TRUSTED_KEYS_DIR": "keys"}
    )
    assert configured.custody_trusted_keys_dir == root.parent.parent / "keys"


def test_result_storage_cannot_pollute_the_evidence_inventory(case):
    server, root, _ = case
    nested = build_server(replace(server._chainsaw_ctx.settings, output_dir=root / "results"))
    result = call(nested, "chainsaw_evidence_manifest", {"path": str(root)})
    assert result.is_error and "outside" in result.content[0].text
