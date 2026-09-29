"""CLI parsing and transport dispatch without binding production listeners."""

import json
from unittest.mock import Mock

import pytest

from chainsaw_mcp import __version__, cli


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch):
    for key in ("MCP_TRANSPORT", "MCP_HOST", "MCP_PORT", "MCP_PATH", "LOG_LEVEL"):
        monkeypatch.delenv(key, raising=False)


def test_defaults_bind_loopback_and_use_stdio():
    args = cli.parse_args([])
    assert (args.transport, args.host, args.port, args.path) == (
        "stdio",
        "127.0.0.1",
        18098,
        "/mcp",
    )


def test_explicit_options_override_environment(monkeypatch):
    monkeypatch.setenv("MCP_TRANSPORT", "streamable-http")
    monkeypatch.setenv("MCP_PORT", "19000")
    assert cli.parse_args([]).port == 19000
    args = cli.parse_args(["--transport", "stdio", "--port", "19001"])
    assert (args.transport, args.port) == ("stdio", 19001)


@pytest.mark.parametrize("args", [["--transport", "invalid"], ["--port", "invalid"]])
def test_invalid_arguments_exit_nonzero(args):
    with pytest.raises(SystemExit) as exc:
        cli.parse_args(args)
    assert exc.value.code == 2


def test_version_does_not_build_server(monkeypatch, capsys):
    server_builder = Mock(side_effect=AssertionError("must not create runtime"))
    monkeypatch.setattr(cli, "build_server", server_builder)
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"chainsaw-mcp {__version__}"
    server_builder.assert_not_called()


def test_stdio_dispatch(settings, monkeypatch):
    server = Mock()
    monkeypatch.setattr(cli, "load_settings", lambda: settings)
    monkeypatch.setattr(cli, "build_server", lambda value: server)
    assert cli.main([]) == 0
    server.run.assert_called_once_with(transport="stdio")


def test_http_dispatch_preserves_security(settings, monkeypatch, tls_files):
    import uvicorn

    cert, key = tls_files
    monkeypatch.setenv("MCP_TLS_CERT_FILE", str(cert))
    monkeypatch.setenv("MCP_TLS_KEY_FILE", str(key))
    monkeypatch.setenv("MCP_AUTH_TOKEN", "a" * 64)
    run = Mock()
    monkeypatch.setattr(uvicorn, "run", run)
    server = Mock()
    monkeypatch.setattr(cli, "load_settings", lambda: settings)
    monkeypatch.setattr(cli, "build_server", lambda value: server)
    assert (
        cli.main(
            [
                "--transport",
                "streamable-http",
                "--host",
                "127.0.0.1",
                "--port",
                "19001",
                "--path",
                "/custom",
                "--json-response",
            ]
        )
        == 0
    )
    kwargs = server.streamable_http_app.call_args.kwargs
    assert run.call_args.kwargs["port"] == 19001
    assert run.call_args.kwargs["ssl_certfile"] == str(cert)
    assert run.call_args.kwargs["ssl_keyfile"] == str(key)
    assert run.call_args.kwargs["proxy_headers"] is False
    assert kwargs["streamable_http_path"] == "/custom"
    assert kwargs["json_response"] is True
    assert kwargs["stateless_http"] is True
    assert kwargs["transport_security"].enable_dns_rebinding_protection is True
    assert "127.0.0.1:19001" in kwargs["transport_security"].allowed_hosts


def test_check_prints_real_status_without_starting_listener(settings, monkeypatch, capsys):
    monkeypatch.setattr(cli, "load_settings", lambda: settings)
    assert cli.main(["--check"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert "chainsaw" in data
    assert "rules" in data
