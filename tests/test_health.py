"""Exercise the deployment probe against a loopback JSON/SSE MCP peer."""

import importlib.util
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "mcp_health", Path(__file__).resolve().parents[1] / "scripts/mcp-health.py"
)
assert SPEC is not None and SPEC.loader is not None
health = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(health)


@pytest.fixture
def peer():
    state = {"sse": False, "failure": None, "requests": []}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass

        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            method = body["method"]
            state["requests"].append((method, dict(self.headers), self.path))
            if state["failure"] == "http":
                self.send_response(503)
                self.end_headers()
                return
            if method == "notifications/initialized":
                self.send_response(202)
                self.end_headers()
                return
            result = (
                {"protocolVersion": "2025-11-25"}
                if method == "initialize"
                else {"tools": [{"name": "status"}]}
            )
            response = {"jsonrpc": "2.0", "id": body["id"], "result": result}
            if state["failure"] == "initialize":
                response = {"jsonrpc": "2.0", "id": body["id"], "error": {"code": -32603}}
            if state["failure"] == "empty" and method == "tools/list":
                response["result"] = {"tools": []}
            payload = json.dumps(response).encode()
            if state["sse"]:
                payload = b": keepalive\n\ndata: " + payload + b"\n\n"
            self.send_response(200)
            self.send_header("Mcp-Session-Id", "test-session")
            self.send_header(
                "Content-Type", "text/event-stream" if state["sse"] else "application/json"
            )
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_DELETE(self):
            state["requests"].append(("DELETE", dict(self.headers), self.path))
            self.send_response(204)
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/mcp", state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@pytest.mark.parametrize("sse", [False, True])
def test_probe_negotiates_protocol_lists_tools_and_closes_session(peer, sse):
    url, state = peer
    state["sse"] = sse
    assert health.probe(url) == {"url": url, "tools": 1, "protocol": "2025-11-25"}
    requests = state["requests"]
    assert [r[0] for r in requests] == [
        "initialize",
        "notifications/initialized",
        "tools/list",
        "DELETE",
    ]
    assert requests[2][1]["Mcp-Session-Id"] == "test-session"
    assert requests[2][1]["MCP-Protocol-Version"] == "2025-11-25"


@pytest.mark.parametrize(
    "failure, message",
    [
        ("initialize", "initialization failed"),
        ("empty", "empty or invalid tool catalog"),
        ("http", "MCP HTTP 503"),
    ],
)
def test_probe_fails_closed_and_releases_established_sessions(peer, failure, message):
    url, state = peer
    state["failure"] = failure
    with pytest.raises(RuntimeError, match=message):
        health.probe(url)
    if failure != "http":
        assert state["requests"][-1][0] == "DELETE"


def test_probe_reads_bearer_from_file(peer, tmp_path):
    url, state = peer
    token = tmp_path / "token"
    token.write_text("test-only-secret\n")
    health.probe(url, bearer_token_file=token)
    assert all(r[1]["Authorization"] == "Bearer test-only-secret" for r in state["requests"])


@pytest.mark.parametrize("value", ["", "first\nsecond", "first\rsecond"])
def test_probe_rejects_invalid_token_before_connecting(tmp_path, value):
    token = tmp_path / "token"
    token.write_text(value)
    with pytest.raises(ValueError, match="Invalid MCP health token"):
        health.probe("http://127.0.0.1:1/mcp", bearer_token_file=token)


@pytest.mark.parametrize(
    "url", ["file:///etc/passwd", "http:///missing-host", "ftp://example.test"]
)
def test_probe_rejects_non_http_urls(url):
    with pytest.raises(ValueError, match="HTTP"):
        health.probe(url)


def test_main_retries_then_reports_failure(monkeypatch):
    attempts = []

    def fail(*args, **kwargs):
        attempts.append(1)
        raise RuntimeError("offline")

    monkeypatch.setattr(health, "probe", fail)
    monkeypatch.setattr(health.time, "sleep", lambda _: None)
    monkeypatch.setattr("sys.argv", ["mcp-health", "http://127.0.0.1/mcp", "--attempts", "2"])
    with pytest.raises(SystemExit, match="MCP health check failed: offline"):
        health.main()
    assert len(attempts) == 2
