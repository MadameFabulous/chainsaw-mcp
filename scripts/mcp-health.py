"""Read-only MCP handshake/catalog probe, compatible with JSON and SSE responses."""

import argparse
import contextlib
import http.client
import json
import time
from pathlib import Path
from urllib.parse import urlsplit


def probe(url, timeout=5, bearer_token_file=None):
    target = urlsplit(url)
    if target.scheme not in {"http", "https"} or not target.hostname:
        raise ValueError("Expected an HTTP(S) MCP URL")
    connection_type = (
        http.client.HTTPSConnection if target.scheme == "https" else http.client.HTTPConnection
    )
    headers = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
    if bearer_token_file:
        token = Path(bearer_token_file).expanduser().read_text().strip()
        if not token or "\n" in token or "\r" in token:
            raise ValueError("Invalid MCP health token file")
        headers["Authorization"] = "Bearer " + token
    path = target.path or "/mcp"

    def request(body=None, method="POST"):
        conn = connection_type(target.hostname, target.port, timeout=timeout)
        try:
            conn.request(method, path, body=json.dumps(body) if body else None, headers=headers)
            response = conn.getresponse()
            if not 200 <= response.status < 300:
                raise RuntimeError(f"MCP HTTP {response.status}")
            session = response.getheader("Mcp-Session-Id")
            if session:
                headers["Mcp-Session-Id"] = session
            if response.status in {202, 204}:
                return None
            if "text/event-stream" in response.getheader("Content-Type", ""):
                for _ in range(1000):
                    line = response.readline(2_000_000)
                    if not line:
                        break
                    if line.startswith(b"data:"):
                        data = json.loads(line[5:])
                        if isinstance(data, dict) and data.get("id") == body.get("id"):
                            return data
                raise RuntimeError("No JSON-RPC result in bounded SSE response")
            return json.loads(response.read(2_000_000))
        finally:
            conn.close()

    try:
        initialized = request(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-11-25",
                    "capabilities": {},
                    "clientInfo": {"name": "mcp-deploy-health", "version": "1"},
                },
            }
        )
        if "error" in initialized:
            raise RuntimeError("MCP initialization failed")
        headers["MCP-Protocol-Version"] = initialized["result"]["protocolVersion"]
        request({"jsonrpc": "2.0", "method": "notifications/initialized"})
        result = request({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        tools = result.get("result", {}).get("tools", [])
        if not tools:
            raise RuntimeError("MCP returned an empty or invalid tool catalog")
        return {"url": url, "tools": len(tools), "protocol": headers["MCP-Protocol-Version"]}
    finally:
        if "Mcp-Session-Id" in headers:
            with contextlib.suppress(Exception):
                request(method="DELETE")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url")
    parser.add_argument("--attempts", type=int, default=10)
    parser.add_argument("--bearer-token-file", help="Read the endpoint token from a local file")
    args = parser.parse_args()
    for attempt in range(args.attempts):
        try:
            print(json.dumps(probe(args.url, bearer_token_file=args.bearer_token_file)))
            return
        except Exception as exc:
            if attempt + 1 == args.attempts:
                raise SystemExit(f"MCP health check failed: {exc}") from exc
            time.sleep(1)


if __name__ == "__main__":
    main()
