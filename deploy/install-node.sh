#!/bin/bash
# Node-side installation of a fully transferred archive. Called by deploy-node.sh.
# Arguments: absolute checkout, Git revision, absolute staging directory.
set -Eeuo pipefail
umask 077
export PATH="$HOME/.local/bin:$PATH"
dest=${1:?checkout required}
rev=${2:?revision required}
incoming=${3:?staging directory required}
[[ $dest = /* && $incoming = /* && $dest != / && $incoming != "$dest" ]]
[[ $rev =~ ^[0-9a-f]{40}([0-9a-f]{24})?$ ]]
[[ -d $incoming && ! -L $dest && ! -L $incoming ]]
mkdir -p "$(dirname "$dest")" "$HOME/.config/systemd/user"
exec 9>"$dest.deploy.lock"
flock -n 9 || { echo 'Another deployment is running' >&2; exit 1; }
unit="$HOME/.config/systemd/user/mcp-chainsaw.service"
# Listener settings: render-unit.sh reads the same variables, so the probe matches the unit.
export MCP_HOST="${MCP_HOST:-$(tailscale ip -4)}"
export MCP_PORT="${MCP_PORT:-18098}"
export MCP_PATH="${MCP_PATH:-/mcp}"
probe_host=$MCP_HOST
if [[ $probe_host == *:* && $probe_host != \[* ]]; then probe_host="[$probe_host]"; fi
health_url="http://$probe_host:$MCP_PORT$MCP_PATH"
backup=$(mktemp -d "$dest.rollback.XXXXXXXX")
had_old=false
if [[ -d $dest ]]; then had_old=true; fi
if [[ -e $unit ]]; then cp -p "$unit" "$backup/unit"; fi
committed=false
stopping=false
rollback() {
  rc=$?
  trap - EXIT HUP INT TERM
  if $committed; then exit "$rc"; fi
  set +e
  echo "Deployment failed (status=$rc); restoring previous release" >&2
  failed=0
  if $stopping; then systemctl --user stop mcp-chainsaw.service || failed=1; fi
  cd "$(dirname "$dest")" || failed=1
  if [[ -d $backup/release ]]; then
    for keep in vendor evidence .chainsaw-mcp custom-rules .env; do
      if [[ ! -e $backup/release/$keep && -e $dest/$keep ]]; then
        mv "$dest/$keep" "$backup/release/$keep" || failed=1
      fi
    done
    # Keep failed candidate for diagnosis; never delete evidence on recovery failure.
    if [[ -e $dest ]]; then mv "$dest" "$backup/failed" || failed=1; fi
    mv "$backup/release" "$dest" || failed=1
  elif ! $had_old && [[ -e $dest ]]; then
    mv "$dest" "$backup/failed" || failed=1
  fi
  if [[ -f $backup/unit ]]; then cp -p "$backup/unit" "$unit" || failed=1
  else rm -f "$unit" || failed=1; fi
  systemctl --user daemon-reload || failed=1
  if $had_old && $stopping; then
    # The restored unit may listen elsewhere than the candidate: probe what it declares.
    # render-unit.sh always writes "--host X --port N --path P"; anything else keeps the
    # candidate's URL, which is what the probe used before this check existed.
    probe_url=$health_url
    if [[ -f $backup/unit ]] && [[ $(grep -m1 '^ExecStart=' "$backup/unit") =~ --host\ ([^\ ]+)\ --port\ ([0-9]+)\ --path\ ([^\ ]+) ]]; then
      previous_host=${BASH_REMATCH[1]}
      if [[ $previous_host == *:* && $previous_host != \[* ]]; then previous_host="[$previous_host]"; fi
      probe_url="http://$previous_host:${BASH_REMATCH[2]}${BASH_REMATCH[3]}"
    fi
    systemctl --user restart mcp-chainsaw.service || failed=1
    systemctl --user is-active --quiet mcp-chainsaw.service || failed=1
    (cd "$dest" && python3 scripts/mcp-health.py "$probe_url") || failed=1
    if [[ $failed = 0 ]]; then echo 'rollback healthy' >&2; fi
  fi
  if [[ $failed != 0 ]]; then echo "ROLLBACK FAILED; retained recovery files: $backup" >&2; fi
  exit "${rc:-1}"
}
trap rollback EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
stopping=true
systemctl --user stop mcp-chainsaw.service
if $had_old; then mv "$dest" "$backup/release"; fi
mv "$incoming" "$dest"
for keep in vendor evidence .chainsaw-mcp custom-rules .env; do
  if [[ -e $backup/release/$keep ]]; then
    rm -rf "$dest/$keep"
    mv "$backup/release/$keep" "$dest/$keep"
  fi
done
cd "$dest"
# Build at the final path: console-script shebangs and uv editable installs are absolute.
# Never mutate or reuse the previous release's venv.
uv sync --locked --no-dev
if [[ ! -x vendor/chainsaw/chainsaw ]]; then uv run --no-dev chainsaw-mcp-bootstrap; fi
mkdir -p evidence .chainsaw-mcp/results custom-rules
.venv/bin/chainsaw-mcp --check >/dev/null
bash deploy/render-unit.sh > "$backup/new-unit"
cp "$backup/new-unit" "$unit"
systemctl --user daemon-reload
systemctl --user enable mcp-chainsaw.service
systemctl --user restart mcp-chainsaw.service
pid=$(systemctl --user show mcp-chainsaw.service --property=MainPID --value)
[[ $pid =~ ^[1-9][0-9]*$ ]]
python3 scripts/mcp-health.py "$health_url"
systemctl --user is-active --quiet mcp-chainsaw.service
[[ $(systemctl --user show mcp-chainsaw.service --property=MainPID --value) == "$pid" ]]
# Identity check only after the probe: Type=simple reports "started" right after fork, and
# /proc/<pid>/cwd is empty until the child finishes sandbox setup and applies
# WorkingDirectory. Verified on the node: empty immediately, correct one second later.
[[ $(readlink -f "/proc/$pid/cwd") == "$dest" ]]
printf '%s\n' "$rev" > .deployed-revision
committed=true
if $had_old; then
  rm -rf "$dest.previous"
  mv "$backup/release" "$dest.previous"
  if [[ -f $backup/unit ]]; then cp "$backup/unit" "$dest.previous/.deployed-unit"; fi
fi
rm -rf "$backup"
echo "healthy mcp-chainsaw revision=$rev; verified process pid=$pid checkout=$dest"
