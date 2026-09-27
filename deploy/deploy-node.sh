#!/bin/bash
# Deploy the committed tree to a remote host over ssh and (re)start mcp-chainsaw there.
# Ships HEAD via git archive (no rsync needed), then on the host runs deploy/install-node.sh:
# uv sync, bootstrap Chainsaw if missing, render unit, daemon-reload, restart, health check,
# automatic rollback on failure.
#
# Required:  CHAINSAW_DEPLOY_NODE   ssh host name of the target
#            CHAINSAW_DEPLOY_USER   remote user that owns the checkout and the user unit
# Optional:  CHAINSAW_DEPLOY_KEY    ssh identity file (default: ssh's own key selection)
#            CHAINSAW_DEPLOY_KNOWN_HOSTS  known_hosts file (default ~/.ssh/known_hosts)
#            CHAINSAW_DEPLOY_DEST   checkout path relative to the remote home (default chainsaw-mcp)
#            MCP_HOST MCP_PORT MCP_PATH MCP_TS_FQDN MCP_MEMORY_MAX
#                                   forwarded to render-unit.sh on the host
set -euo pipefail
repo="$(cd "$(dirname "$0")/.." && pwd)"
cd "$repo"
node="${CHAINSAW_DEPLOY_NODE:?set CHAINSAW_DEPLOY_NODE to the ssh host name of the target}"
user="${CHAINSAW_DEPLOY_USER:?set CHAINSAW_DEPLOY_USER to the remote service user}"
key="${CHAINSAW_DEPLOY_KEY:-}"
known="${CHAINSAW_DEPLOY_KNOWN_HOSTS:-$HOME/.ssh/known_hosts}"
dest="${CHAINSAW_DEPLOY_DEST:-chainsaw-mcp}"   # relative to the remote user's home
ssh_cmd=(ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -o UserKnownHostsFile="$known")
if [[ -n $key ]]; then
  ssh_cmd+=(-i "$key" -o IdentitiesOnly=yes)
fi
ssh_cmd+=("$user@$node")
# Restrict the relative path before embedding it in a remote shell command.
if [[ ! $dest =~ ^[a-zA-Z0-9_-]+(/[a-zA-Z0-9_-]+)*$ ]]; then
  echo 'CHAINSAW_DEPLOY_DEST must be a simple relative directory path' >&2
  exit 1
fi
# Listener and memory-cap overrides travel with the install so the rendered unit matches
# the request; ssh does not carry the workstation environment across on its own.
remote_env=""
for name in MCP_HOST MCP_PORT MCP_PATH MCP_TS_FQDN MCP_MEMORY_MAX; do
  if [[ -n ${!name:-} ]]; then
    printf -v quoted '%q' "${!name}"
    remote_env+="$name=$quoted "
  fi
done

if ! git diff --quiet || ! git diff --cached --quiet; then
  echo "Refusing to deploy: uncommitted tracked changes in $repo" >&2
  exit 1
fi
rev=$(git rev-parse HEAD)
echo "ship $rev -> $user@$node:~/$dest"

[[ $rev =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]]
# Unique staging avoids concurrent transfers overwriting one another. The installer locks
# the live checkout; no live change occurs until both sides of the archive pipeline pass.
stage=$("${ssh_cmd[@]}" "mkdir -p \"\$HOME/$(dirname "$dest")\"; mktemp -d \"\$HOME/$dest.incoming.XXXXXXXX\"")
printf -v quoted_stage '%q' "$stage"
cleanup() { "${ssh_cmd[@]}" "rm -rf -- $quoted_stage" || true; }
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
git archive --format=tar "$rev" | "${ssh_cmd[@]}" "tar -x -C $quoted_stage"
"${ssh_cmd[@]}" "env $remote_env bash $quoted_stage/deploy/install-node.sh \"\$HOME/$dest\" '$rev' $quoted_stage"
