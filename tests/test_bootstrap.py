"""Offline bootstrap trust-boundary tests using synthetic release archives."""

import hashlib
import io
import stat
import zipfile

import pytest

from chainsaw_mcp import bootstrap


@pytest.fixture
def bundle(tmp_path, monkeypatch):
    binary = bootstrap.BINARIES[("Linux", "x86_64")]
    payload = b"test executable\n"
    archive = tmp_path / "release.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        for name, data in {
            binary: payload,
            "chainsaw_aarch64-unknown-linux-gnu": b"other platform",
            "rules/test.yml": b"title: test",
            "sigma/rules/test.yml": b"title: sigma",
            "sigma/tests/huge.txt": b"unused",
            "EVTX-ATTACK-SAMPLES/sample.evtx": b"unused",
            "mappings/test.yml": b"mapping",
        }.items():
            zf.writestr("chainsaw/" + name, data)
    monkeypatch.setattr(
        bootstrap, "BUNDLE_SHA256", hashlib.sha256(archive.read_bytes()).hexdigest()
    )
    monkeypatch.setattr(bootstrap, "BINARY_SHA256", {binary: hashlib.sha256(payload).hexdigest()})
    return archive, binary


@pytest.mark.parametrize("skip_sigma", [False, True])
def test_install_selects_host_binary_and_prunes_unused_trees(bundle, tmp_path, skip_sigma):
    archive, binary = bundle
    dest = tmp_path / "installed"
    bootstrap.install(archive, dest, skip_sigma=skip_sigma, binary_name=binary)
    assert (dest / "chainsaw").read_bytes() == b"test executable\n"
    assert (dest / "chainsaw").stat().st_mode & stat.S_IXUSR
    assert (dest / "rules/test.yml").is_file()
    assert (dest / "mappings/test.yml").is_file()
    assert (dest / "sigma/rules/test.yml").exists() is not skip_sigma
    assert not (dest / "sigma/tests").exists()
    assert not (dest / "EVTX-ATTACK-SAMPLES").exists()
    assert not (dest / "chainsaw_aarch64-unknown-linux-gnu").exists()


def test_main_verifies_local_bundle_before_install(bundle, tmp_path):
    archive, binary = bundle
    dest = tmp_path / "installed"
    assert bootstrap.main(["--bundle", str(archive), "--binary", binary, "--dest", str(dest)]) == 0
    assert (dest / "chainsaw").is_file()


def test_main_rejects_corrupted_bundle(bundle, tmp_path):
    archive, binary = bundle
    archive.write_bytes(archive.read_bytes() + b"tampered")
    dest = tmp_path / "installed"
    with pytest.raises(SystemExit, match="bundle checksum mismatch"):
        bootstrap.main(["--bundle", str(archive), "--binary", binary, "--dest", str(dest)])
    assert not (dest / "chainsaw").exists()


def test_existing_install_requires_explicit_force(bundle, tmp_path):
    archive, binary = bundle
    dest = tmp_path / "installed"
    dest.mkdir()
    (dest / "sentinel").write_text("keep")
    args = ["--bundle", str(archive), "--binary", binary, "--dest", str(dest)]
    assert bootstrap.main(args) == 1
    assert (dest / "sentinel").read_text() == "keep"
    assert bootstrap.main([*args, "--force"]) == 0
    assert not (dest / "sentinel").exists()


def test_install_rejects_binary_checksum_mismatch(bundle, tmp_path, monkeypatch):
    archive, binary = bundle
    monkeypatch.setattr(bootstrap, "BINARY_SHA256", {binary: "0" * 64})
    with pytest.raises(SystemExit, match="binary checksum mismatch"):
        bootstrap.install(archive, tmp_path / "installed", skip_sigma=False, binary_name=binary)


def test_install_rejects_archive_traversal(tmp_path):
    archive = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("chainsaw/../escaped", b"escape")
    with pytest.raises(SystemExit, match="suspicious archive member"):
        bootstrap.install(archive, tmp_path / "installed", skip_sigma=False, binary_name="unused")
    assert not (tmp_path / "escaped").exists()


def test_host_binary_rejects_unsupported_platform(monkeypatch):
    monkeypatch.setattr(bootstrap.platform, "system", lambda: "Unknown")
    with pytest.raises(SystemExit, match="no chainsaw binary"):
        bootstrap.host_binary()


def test_download_checks_expected_size(tmp_path, monkeypatch):
    monkeypatch.setattr(bootstrap.urllib.request, "urlopen", lambda *a, **kw: io.BytesIO(b"short"))
    with pytest.raises(SystemExit, match="size mismatch"):
        bootstrap.download(
            "https://example.invalid/release.zip", tmp_path / "download", expected_bytes=99
        )
