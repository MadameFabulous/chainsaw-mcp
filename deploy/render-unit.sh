#!/bin/bash
# Render the mcp-chainsaw systemd user unit for this host. Run from the checkout root on the
# target; prints the unit to stdout. Overrides: CHAINSAW_MCP_HOME, MCP_HOST (default: this
# host's Tailscale IPv4), MCP_PORT, MCP_PATH, MCP_TS_FQDN (default: the Tailscale MagicDNS
# name, falling back to `hostname -f`).
set -euo pipefail
home="${CHAINSAW_MCP_HOME:-$(cd "$(dirname "$0")/.." && pwd)}"
host="${MCP_HOST:-$(tailscale ip -4)}"
port="${MCP_PORT:-18098}"
path="${MCP_PATH:-/mcp}"
fqdn="${MCP_TS_FQDN:-}"
memory_max="${MCP_MEMORY_MAX:-4G}"
if [[ -z $fqdn ]]; then
  fqdn=$(tailscale status --self --json 2>/dev/null \
    | python3 -c 'import json, sys; print(json.load(sys.stdin)["Self"]["DNSName"].rstrip("."))' 2>/dev/null \
    || true)
fi
if [[ -z $fqdn ]]; then
  fqdn=$(hostname -f 2>/dev/null || hostname)
fi
short="$(hostname)"
cat <<UNIT
[Unit]
Description=chainsaw-mcp streamable HTTP server (Chainsaw forensic hunting over MCP)
After=default.target

[Service]
Type=simple
WorkingDirectory=$home
EnvironmentFile=-$home/.env
Environment=PATH=$HOME/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Environment=CHAINSAW_HOME=$home
Environment=CHAINSAW_EVIDENCE_ROOTS=$home/evidence
Environment=CHAINSAW_OUTPUT_DIR=$home/.chainsaw-mcp/results
Environment="MCP_ALLOWED_HOSTS=$short,$short:*,$fqdn,$fqdn:*"
ExecStartPre=$home/.venv/bin/chainsaw-mcp --check
ExecStart=$home/.venv/bin/chainsaw-mcp --transport streamable-http --host $host --port $port --path $path
Restart=on-failure
RestartSec=5s
# Evidence is read-only for the service; results and custom rules are the only writable trees.
ReadOnlyPaths=$home/evidence
ReadWritePaths=$home/.chainsaw-mcp/results $home/custom-rules
# A user unit needs unprivileged user namespaces for filesystem sandboxing.
# Read-only (not hidden) home preserves the checkout, uv Python, bws and token access.
PrivateUsers=true
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
PrivateDevices=true
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
UMask=0077
NoNewPrivileges=true
# A runaway hunt must not take the host down with it.
MemoryMax=$memory_max
TasksMax=512

[Install]
WantedBy=default.target
UNIT
