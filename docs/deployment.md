# Deployment

chainsaw-mcp runs anywhere a Python 3.11+ interpreter and the Chainsaw binary exist. For
local agent use the stdio transport in the README is enough. This guide covers running it as
a long-lived streamable HTTP service on a Linux host: a uv-managed virtual environment, a
hardened systemd user unit bound to a private (typically Tailscale) address, and a deploy
script that ships a committed tree over ssh with automatic rollback.

## Service layout on the target

| Item | Default |
|---|---|
| service user | any unprivileged user with `uv` in `~/.local/bin` and lingering enabled (`loginctl enable-linger <user>`) |
| checkout | `~/chainsaw-mcp` (`CHAINSAW_DEPLOY_DEST`, relative to the user's home) |
| systemd unit | `~/.config/systemd/user/mcp-chainsaw.service`, rendered by `deploy/render-unit.sh` |
| bind address | the host's Tailscale IPv4 from `tailscale ip -4` (`MCP_HOST` overrides it) |
| port / path | `18098` / `/mcp` (`MCP_PORT`, `MCP_PATH`) |
| health probe | `python3 scripts/mcp-health.py http://<host>:18098/mcp` (initialises a session and lists tools) |
| evidence root | `<checkout>/evidence`, read-only to the service; copy or mount artefacts here |
| writable state | `.chainsaw-mcp/results` (result store plus its `.mappings/` cache), `custom-rules/`, `.env` |
| Host allow-list | the short hostname and the Tailscale MagicDNS name, each with and without a port; DNS-rebinding protection is always on |

`render-unit.sh` resolves the address, hostname and home directory at render time, so no
checked-in file contains a host-specific value. `deploy/systemd/mcp-chainsaw.service` is a
reference copy with example values only.

## Deploying from a workstation

Set the target once and ship a committed tree:

```bash
export CHAINSAW_DEPLOY_NODE=mcp-host.example.ts.net   # ssh host name
export CHAINSAW_DEPLOY_USER=mcp                       # remote service user
export CHAINSAW_DEPLOY_KEY=~/.ssh/mcp-host            # optional; omit to use ssh's own key selection
git status --short      # must be clean; the script refuses uncommitted tracked changes
deploy/deploy-node.sh
```

The target must already be in the known_hosts file (`CHAINSAW_DEPLOY_KNOWN_HOSTS`, default
`~/.ssh/known_hosts`); the script never accepts a new host key. `MCP_HOST`, `MCP_PORT`,
`MCP_PATH`, `MCP_TS_FQDN` and `MCP_MEMORY_MAX` set in the workstation environment are
forwarded to the installer so the rendered unit and the health probe use the same
listener and the requested memory cap.

What `deploy/deploy-node.sh` does on the workstation:

1. Refuses to run with uncommitted tracked changes, then streams `git archive HEAD` over
   ssh into a unique `<dest>.incoming.XXXXXXXX` staging directory on the target (no rsync
   required). Only committed files ship, concurrent transfers cannot overwrite each other,
   and the staging directory is removed on exit whatever happens.
2. Runs `deploy/install-node.sh` from the staged tree with the checkout path, the commit
   and the staging path.

What `deploy/install-node.sh` does on the target:

1. Takes an exclusive `flock` on `<dest>.deploy.lock` so two installs cannot interleave,
   and copies the current unit file into a rollback directory.
2. Stops the service, moves the live checkout into the rollback directory, moves the
   staged tree into place, and moves per-host state (`vendor`, `evidence`, `.chainsaw-mcp`,
   `custom-rules`, `.env`) from the previous release into the new tree. The previous
   `.venv` is never reused: console-script shebangs are absolute, so the venv is rebuilt.
3. Runs `uv sync --locked --no-dev`, and `chainsaw-mcp-bootstrap` only if
   `vendor/chainsaw/chainsaw` is missing (48 MB download, sha256 verified).
4. Runs `chainsaw-mcp --check`, renders the unit with the host's home directory, bind
   address and hostname, then `daemon-reload`, `enable`, `restart`.
5. Verifies the running process: the main PID exists, `scripts/mcp-health.py` lists the
   tools, the unit is active, the PID has not changed during the probe (no restart loop),
   and the process's working directory is the new checkout. The directory check runs last
   on purpose: systemd reports a `Type=simple` unit as started right after forking, and
   `/proc/<pid>/cwd` stays empty until the child has finished sandbox setup. Only then does
   it write `.deployed-revision`, keep the previous release as `<dest>.previous` (with its
   unit as `.deployed-unit`) and delete the rollback directory.

### Automatic rollback

If any step before the final health check fails, the installer restores the previous
release and unit file, reloads systemd, restarts the service and re-runs the health probe
against the listener the restored unit declares (read from its `ExecStart` line in the
`--host X --port N --path P` form `render-unit.sh` writes), so a deployment that moved the
bind address, port or path still verifies the previous release correctly.
The failed candidate tree is kept as `<dest>.rollback.XXXXXXXX/failed` for diagnosis, and
per-host state is moved back with the previous release so evidence, results and `.env` are
never lost. If restoring fails, the script prints `ROLLBACK FAILED` with the path of the
retained recovery directory and exits non-zero; nothing is deleted. The behaviour is
exercised by `tests/test_deploy.py` with fake `systemctl`, `uv`, `tailscale`, `git` and
`ssh` commands.

Re-running the script is idempotent. To roll back deliberately, check out the previous
commit and run it again. `<dest>.previous` holds the last healthy release for manual
recovery if the target is unreachable from the workstation.

The CI workflow (`.github/workflows/quality.yml`) runs `scripts/quality-check.sh` and
`scripts/integration-check.sh` on every push. It is a quality gate on unprivileged
runners and never deploys.

## Manual equivalent on the target

```bash
ssh mcp@mcp-host.example.ts.net
cd ~/chainsaw-mcp
export PATH="$HOME/.local/bin:$PATH"
uv sync --locked --no-dev
uv run --no-dev chainsaw-mcp-bootstrap    # only when vendor/chainsaw/chainsaw is missing
mkdir -p evidence                          # copy or mount collected artefacts here
cp -n .env.example .env                    # optional: CHAINSAW_EVIDENCE_ROOTS, MCP_ALLOWED_HOSTS
bash deploy/render-unit.sh > ~/.config/systemd/user/mcp-chainsaw.service
systemctl --user daemon-reload
systemctl --user enable --now mcp-chainsaw.service
python3 scripts/mcp-health.py "http://$(tailscale ip -4):18098/mcp"
journalctl --user -u mcp-chainsaw -n 50 --no-pager
```

`render-unit.sh` accepts `CHAINSAW_MCP_HOME`, `MCP_HOST`, `MCP_PORT`, `MCP_PATH`,
`MCP_TS_FQDN` and `MCP_MEMORY_MAX` overrides. Without Tailscale, set `MCP_HOST` to a loopback or private
address and `MCP_TS_FQDN` to the name clients will use. Additional allowed Host headers go
in `.env` as `MCP_ALLOWED_HOSTS=host1,host2:*` (comma-separated); the unit's
`EnvironmentFile` loads it.

### Unit hardening

The rendered unit enforces the writable-tree policy described under Security notes rather
than only stating it:

| Setting | Effect |
|---|---|
| `ProtectSystem=strict`, `ProtectHome=read-only` | the whole filesystem, including the checkout, is read-only to the service |
| `ReadWritePaths=.chainsaw-mcp/results custom-rules` | the only writable trees; `ReadOnlyPaths=evidence` is kept for clarity |
| `PrivateUsers=true` | required for filesystem sandboxing in a user unit |
| `PrivateTmp=true`, `PrivateDevices=true` | no shared `/tmp`, no device access |
| `CapabilityBoundingSet=`, `AmbientCapabilities=`, `NoNewPrivileges=true`, `RestrictSUIDSGID=true` | no capabilities, no privilege escalation |
| `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6` | plain sockets only (the listener, and TypeSafe when Jev is enabled) |
| `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectControlGroups`, `LockPersonality` | standard kernel-surface reductions |
| `UMask=0077` | anything the service creates is private; the result store additionally enforces 0700/0600 itself |
| `MemoryMax=4G`, `TasksMax=512` | a runaway hunt is killed before it takes the host down; raise the memory cap with `MCP_MEMORY_MAX` when rendering |

`ProtectHome=read-only` rather than `yes` is deliberate: the checkout, uv's Python, the
`bws` binary and the Bitwarden token file all live under the home directory and must stay
readable. `tests/test_deploy.py::test_render_sandbox` checks that the rendered unit keeps
these settings.

## Enabling Jev on the target

`chainsaw_jev_triage` is disabled by default and stays disabled after a deploy unless the
target's `.env` enables it. The deploy script preserves `.env`, so set it once there:

```dotenv
CHAINSAW_JEV_ENABLED=true
CHAINSAW_JEV_BWS_SECRET_ID=<UUID of the Jev API key secret>
BWS_BINARY=/home/mcp/.local/bin/bws
BWS_TOKEN_FILE=/home/mcp/.config/bitwarden-sm/token
```

The `bws` CLI must be installed and the token file must be mode 0600 and owned by the
service user. Alternatively inject `TYPESAFE_API_KEY` from your own secret manager. Restart
with `systemctl --user restart mcp-chainsaw` and confirm with `chainsaw-mcp --check`,
which reports `jev.enabled`, `jev.credentials_configured` and `jev.credential_source`
(`env` or `bws`) without fetching the secret.
Anyone who can reach the endpoint can then submit selected evidence fields to TypeSafe and
consume API usage, so keep network reachability tight. Full variable reference and
workflow: [jev.md](jev.md).

## Upgrading Chainsaw itself

Bump `CHAINSAW_RELEASE` in `src/chainsaw_mcp/__init__.py` and the checksums in
`src/chainsaw_mcp/bootstrap.py`, commit, deploy, then on the target run
`uv run --no-dev chainsaw-mcp-bootstrap --force` and `systemctl --user restart mcp-chainsaw`.

## Security notes

- Tools only read from `CHAINSAW_EVIDENCE_ROOTS`; every client-supplied path is resolved
  and must stay inside a root, symlinks included. The unit also marks the evidence tree
  `ReadOnlyPaths`.
- Writable locations are `CHAINSAW_OUTPUT_DIR` (result JSONL, expired after 7 days, plus
  the content-addressed `.mappings/` cache holding the repaired default Sigma mapping,
  which the expiry sweep never touches) and `CHAINSAW_CUSTOM_RULES_DIR` (analyst rules).
  Nothing else is written, and the unit's `ProtectSystem=strict` makes that a
  kernel-enforced fact rather than a convention.
- The result store creates its directory 0700 and every data or metadata file 0600, fixes
  the modes of an existing tree at start-up, publishes results atomically (a handle is
  never visible half-written) and refuses expired handles on every read.
- Chainsaw runs as a subprocess with `CHAINSAW_TIMEOUT` (default 600 s) and no stdin.
- The service makes no outbound connections unless `CHAINSAW_JEV_ENABLED=true`, in which
  case `chainsaw_jev_triage` posts selected result rows to `api.typesafe.ai` over HTTPS
  with redirects disabled. Nothing else leaves the host.
- The endpoint has no authentication of its own; reachability is the access control.
  Bind to a loopback or private overlay address (a tailnet with a restrictive ACL works
  well). Never bind to `0.0.0.0` or a LAN address.
- Results can contain sensitive log content; treat the results directory like evidence.
