"""Remote clients authenticate and publish evidence without writing mounted evidence."""

import base64
import hashlib
import ssl
from pathlib import Path

import pytest
import uvicorn
from starlette.testclient import TestClient

from chainsaw_mcp.config import load_settings
from chainsaw_mcp.http import bearer_token, http_app, tls_options
from chainsaw_mcp.server import build_server
from chainsaw_mcp.transfers import sign_manifest, upload_manifest
from chainsaw_mcp.uploads import MAX_CHUNK_BYTES, UploadStore
from tests.test_server import call, payload


@pytest.fixture
def upload_settings(workspace, transfer_keys):
    return load_settings(
        {
            "CHAINSAW_HOME": str(workspace),
            "CHAINSAW_UPLOAD_DIR": str(workspace / "uploads"),
            "CHAINSAW_UPLOAD_MAX_BYTES": "500000",
            "CHAINSAW_UPLOAD_QUOTA_BYTES": "1000000",
            "CHAINSAW_UPLOAD_TRUSTED_KEYS_DIR": str(transfer_keys["directory"]),
        }
    )


def test_upload_resume_publish_and_use_as_evidence(upload_settings, transfer_keys):
    server = build_server(upload_settings)
    data = b'[{"Event":{"System":{"EventID":4104}}}]'
    started = payload(
        call(
            server,
            "chainsaw_upload_begin",
            {
                "name": "host's evidence.json",
                "size_bytes": len(data),
                "sha256": hashlib.sha256(data).hexdigest(),
                "signature": sign_manifest(
                    upload_manifest(
                        "host's evidence.json", len(data), hashlib.sha256(data).hexdigest()
                    ),
                    transfer_keys["key"],
                ),
            },
        )
    )
    handle = started["upload_id"]
    assert not started["complete"] and started["path"] is None
    assert list((upload_settings.upload_dir / "evidence").iterdir()) == []
    args = {"upload_id": handle, "offset": 0, "data_base64": base64.b64encode(data[:10]).decode()}
    assert payload(call(server, "chainsaw_upload_chunk", args))["next_offset"] == 10
    assert payload(call(server, "chainsaw_upload_chunk", args))["next_offset"] == 10
    # A new server process resumes the existing upload.
    server = build_server(upload_settings)
    assert (
        payload(
            call(
                server,
                "chainsaw_upload_finish",
                {
                    "upload_id": handle,
                    "action": "status",
                },
            )
        )["next_offset"]
        == 10
    )
    payload(
        call(
            server,
            "chainsaw_upload_chunk",
            {
                "upload_id": handle,
                "offset": 10,
                "data_base64": base64.b64encode(data[10:]).decode(),
            },
        )
    )
    finished = payload(call(server, "chainsaw_upload_finish", {"upload_id": handle}))
    path = Path(finished["path"])
    assert finished["complete"] and path.read_bytes() == data
    assert path.stat().st_mode & 0o222 == 0
    assert payload(call(server, "chainsaw_list_evidence", {"path": str(path)}))["total"] == 1
    assert payload(call(server, "chainsaw_upload_finish", {"upload_id": handle})) == finished
    assert call(server, "chainsaw_upload_chunk", args).is_error
    assert call(server, "chainsaw_upload_finish", {"upload_id": handle, "action": "abort"}).is_error


def test_upload_validation_and_quota(tmp_path, transfer_keys):
    store = UploadStore(
        tmp_path, max_bytes=10, quota_bytes=12, trusted_keys=transfer_keys["trusted"]
    )

    def begin(name, size):
        return store.begin(
            name,
            size,
            "0" * 64,
            sign_manifest(upload_manifest(name, size, "0" * 64), transfer_keys["key"]),
        )

    for name in ("../a", "/x", "a/b", "a\\b", ".hidden", "a\nlog"):
        with pytest.raises(ValueError, match="filename"):
            store.begin(name, 5, "0" * 64)
    with pytest.raises(ValueError, match="size_bytes"):
        store.begin("a", 11, "0" * 64)
    with pytest.raises(ValueError, match="sha256"):
        store.begin("a", 5, "bad")
    upload = begin("a", 8)["upload_id"]
    with pytest.raises(ValueError, match="quota"):
        begin("b", 5)
    with pytest.raises(ValueError, match="out of order"):
        store.append(upload, 1, "YWJj")
    with pytest.raises(ValueError, match="incomplete"):
        store.finish(upload)
    store.append(upload, 0, base64.b64encode(b"12345678").decode())
    with pytest.raises(ValueError, match="differ"):
        store.append(upload, 0, "YWJj")
    with pytest.raises(ValueError, match="SHA-256"):
        store.finish(upload)
    assert store.abort(upload)["aborted"]
    assert begin("b", 10)
    for invalid in ("../../secret", "upl_abc"):
        with pytest.raises(ValueError, match="Invalid upload"):
            store.status(invalid)
    for data in ("!", "x" * (MAX_CHUNK_BYTES * 4 // 3 + 1)):
        with pytest.raises(ValueError):
            store.append(upload, 0, data)


def test_disabled_uploads_and_overlapping_roots(settings, workspace):
    assert call(
        build_server(settings),
        "chainsaw_upload_begin",
        {
            "name": "a",
            "size_bytes": 1,
            "sha256": "0" * 64,
        },
    ).is_error
    with pytest.raises(ValueError, match="separate"):
        load_settings(
            {
                "CHAINSAW_HOME": str(workspace),
                "CHAINSAW_UPLOAD_DIR": str(workspace / "evidence" / "uploads"),
            }
        )


@pytest.fixture
def token_env(monkeypatch):
    for key in ("MCP_AUTH_TOKEN", "MCP_AUTH_TOKEN_FILE", "MCP_REQUIRE_AUTH"):
        monkeypatch.delenv(key, raising=False)
    return monkeypatch


def test_auth_configuration_fails_closed(token_env, tmp_path):
    with pytest.raises(ValueError, match="requires"):
        bearer_token()
    token_env.setenv("MCP_AUTH_TOKEN", "short")
    with pytest.raises(ValueError, match="at least 32"):
        bearer_token()
    secret = tmp_path / "token"
    secret.write_text("a" * 64 + "\n")
    secret.chmod(0o600)
    token_env.setenv("MCP_AUTH_TOKEN_FILE", str(secret))
    with pytest.raises(ValueError, match="only one"):
        bearer_token()
    token_env.delenv("MCP_AUTH_TOKEN")
    assert bearer_token() == "a" * 64
    secret.chmod(0o400)
    assert bearer_token() == "a" * 64


@pytest.mark.parametrize("value", ["false", "0", "true"])
def test_deprecated_require_auth_cannot_disable_authentication(token_env, caplog, value):
    token_env.setenv("MCP_REQUIRE_AUTH", value)
    with (
        caplog.at_level("WARNING", logger="chainsaw_mcp.http"),
        pytest.raises(ValueError, match="requires"),
    ):
        bearer_token()
    assert "MCP_REQUIRE_AUTH is deprecated and ignored" in caplog.text
    token_env.setenv("MCP_AUTH_TOKEN", "a" * 64)
    assert bearer_token() == "a" * 64


@pytest.mark.parametrize("mode", [0o640, 0o604, 0o644])
def test_auth_token_file_refuses_group_or_other_access(token_env, tmp_path, mode):
    secret = tmp_path / "token"
    secret.write_text("a" * 64 + "\n")
    secret.chmod(mode)
    token_env.setenv("MCP_AUTH_TOKEN_FILE", str(secret))
    with pytest.raises(ValueError, match="group or other"):
        bearer_token()


def test_http_auth_protects_catalog_and_keeps_host_checks(settings):
    app = http_app(
        build_server(settings),
        host="127.0.0.1",
        port=18098,
        path="/mcp",
        json_response=True,
        token="a" * 64,
    )
    body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}
    headers = {"Accept": "application/json, text/event-stream"}
    with TestClient(app, base_url="https://127.0.0.1:18098") as client:
        assert client.post("/mcp", json=body, headers=headers).status_code == 401
        headers["Authorization"] = "Bearer " + "b" * 64
        assert client.post("/mcp", json=body, headers=headers).status_code == 401
        headers["Authorization"] = "Bearer " + "a" * 64
        response = client.post("/mcp", json=body, headers=headers)
        assert response.status_code == 200
        assert any(t["name"] == "chainsaw_reproduce" for t in response.json()["result"]["tools"])
        headers["Host"] = "evil.example"
        assert client.post("/mcp", json=body, headers=headers).status_code == 421


def test_plaintext_and_spoofed_proxy_headers_rejected(settings):
    app = http_app(
        build_server(settings),
        host="127.0.0.1",
        port=18098,
        path="/mcp",
        json_response=True,
        token="a" * 64,
    )
    with TestClient(app, base_url="http://127.0.0.1:18098") as client:
        response = client.post(
            "/mcp", headers={"Authorization": "Bearer " + "a" * 64, "X-Forwarded-Proto": "https"}
        )
        assert response.status_code == 426


def test_tls_configuration_requires_certificate_pair(monkeypatch, tls_files):
    monkeypatch.delenv("MCP_TLS_CERT_FILE", raising=False)
    monkeypatch.delenv("MCP_TLS_KEY_FILE", raising=False)
    with pytest.raises(ValueError, match="HTTPS"):
        tls_options()
    monkeypatch.setenv("MCP_TLS_CERT_FILE", str(tls_files[0]))
    with pytest.raises(ValueError, match="HTTPS"):
        tls_options()
    monkeypatch.setenv("MCP_TLS_KEY_FILE", str(tls_files[1]))
    options = tls_options()
    assert options["proxy_headers"] is False


def test_served_tls_context_enforces_tls12_minimum(monkeypatch, tls_files):
    monkeypatch.setenv("MCP_TLS_CERT_FILE", str(tls_files[0]))
    monkeypatch.setenv("MCP_TLS_KEY_FILE", str(tls_files[1]))
    default = uvicorn.config.create_ssl_context

    def permissive(**kwargs):
        # A library or system default that still allows TLS 1.0 must not reach the listener.
        context = default(**kwargs)
        context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
        return context

    monkeypatch.setattr(uvicorn.config, "create_ssl_context", permissive)
    config = uvicorn.Config(lambda scope, receive, send: None, **tls_options())
    config.load()
    assert config.ssl is not None
    assert config.ssl.minimum_version >= ssl.TLSVersion.TLSv1_2
