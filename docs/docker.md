# Remote Docker deployment

The image includes the Python server, Chainsaw v2.16.5, bundled Sigma and Chainsaw rules,
mappings, upstream licences and Chainsaw source. It needs no runtime bootstrap or network
access for investigations. Clients use Streamable HTTP at `/mcp`; no local Chainsaw
installation or SSH session is required to investigate, upload evidence, author rules,
plan commands, or download results.

## Start the server

On the Docker host, with Docker Compose v2 and BuildKit, complete the
[TLS and signing-key setup](secure-transfers.md) first, then:

```sh
docker compose up --build -d
docker compose ps
```

The default endpoint is `https://127.0.0.1:18098/mcp`. Supply
`Authorization: Bearer <token>` with every request; on the host, read it from the
`secrets/mcp_token.client` copy described in [secure transfers](secure-transfers.md). The container
requires a token and a TLS certificate/key pair. The mounted token must be owned by UID
10001 with mode 0400 or 0600 (`chown 10001:10001`, `chmod 0400`); the server refuses a
token file with group or other access. Use a client that supports custom HTTP headers; this is
a shared bearer token, not an OAuth discovery/registration server.

For another machine, set these Compose variables in `.env`, then recreate the container:

```dotenv
MCP_BIND_ADDRESS=100.64.0.10
MCP_ALLOWED_HOSTS=forensics.example.ts.net:*,100.64.0.10:*
CHAINSAW_EVIDENCE_PATH=/srv/cases
```

Use HTTPS, including on private overlays and on any reverse proxy's connection to the backend.
The container binds `0.0.0.0` internally; `MCP_BIND_ADDRESS` controls the published host
address. Allow the actual hostname your client sends, even behind a proxy. Browser
clients may also need `MCP_ALLOWED_ORIGINS=https://your-client.example`. Authentication
does not replace Host/Origin checks. The server terminates TLS and ignores forwarding headers
as proof of transport security. Configure certificate trust on the client and any gateway.

Example MCP client configuration (substitute the token using your client's secret support):

```json
{
  "mcpServers": {
    "chainsaw": {
      "type": "http",
      "url": "https://forensics.example/mcp",
      "headers": {"Authorization": "Bearer <token>"}
    }
  }
}
```

`docker compose` reads `.env` for interpolation; it does not forward arbitrary variables.
Add optional settings such as `CHAINSAW_JEV_ENABLED` and `TYPESAFE_API_KEY` explicitly to
the service environment if you need Jev. BWS is not bundled; inject its resolved API key.

## Mount evidence from another machine

The bind source is a path **on the Docker daemon host**, including when using a remote
Docker context. It cannot mount an arbitrary directory on an MCP client's computer.
The app reads mount contents; it never receives Docker socket or host mount privileges.

For an NFSv4 export, the included override lets the Docker host mount the share:

```sh
export NFS_SERVER=192.0.2.20
export NFS_EXPORT=/exports/investigations
docker compose -f compose.yaml -f deploy/compose.nfs.yaml up --build -d
```

The export must allow the Docker host to connect and UID/GID 10001 to read and traverse
files. Both the NFS mount and the container volume are read-only. Mount settings are
fixed when Docker creates the volume: Docker keeps the original `driver_opts`, so after
changing `NFS_SERVER` or `NFS_EXPORT` stop the service and remove the evidence volume
(`docker volume rm <project>_remote_evidence`) before starting it again. Do not remove the
`chainsaw_data` volume to change an evidence mount.

For SMB, mount on the Docker host first (requires its `cifs-utils` package), then bind it:

```sh
sudo mkdir -p /srv/cases
sudo mount -t cifs //fileserver/cases /srv/cases \
  -o credentials=/root/.smb-cases,ro,vers=3.1.1,uid=10001,gid=10001,file_mode=0440,dir_mode=0550
CHAINSAW_EVIDENCE_PATH=/srv/cases docker compose up -d
```

Keep SMB credentials on the host in a root-only file; do not bake them into the image or
send them through MCP. Use host mount management for persistent mounts. Additional shares
can be mounted at distinct container paths and added to colon-separated
`CHAINSAW_EVIDENCE_ROOTS` in the service environment.

## Upload evidence remotely

The container enables uploads under `/data/uploads`, separately from mounted evidence.
The MCP workflow is:

1. `chainsaw_upload_begin(name, size_bytes, sha256, signature)` verifies a trusted Ed25519
   attestation, reserves space and returns an upload ID.
2. `chainsaw_upload_chunk(upload_id, offset, data_base64)` sends up to 192 KiB of decoded
   bytes. Use the returned `next_offset`; identical retries are accepted.
3. `chainsaw_upload_finish(upload_id)` rechecks signature trust, exact size and checksum and publishes
   a new read-only file. Its absolute `path` works directly with investigation tools.

No extraction occurs: upload individual EVTX/hive/JSON files, not archives. Unfinished
bytes are outside evidence roots. Use finish with `action="status"` after a reconnect
or `action="abort"` to release an unfinished reservation. Published files cannot be
overwritten, aborted, or deleted through MCP.

For file transfer without putting bytes in an agent's context, run the supplied Python
client from a checkout on your workstation (only Python dependencies, no Chainsaw needed):

```sh
uv run python scripts/remote-client.py https://forensics.example/mcp \
  --token-file /private/mcp_token upload /cases/host1/Security.evtx \
  --signing-key /private/analyst-signing.key
# After interruption, add: --resume upl_<id-printed-at-start>
uv run python scripts/remote-client.py https://forensics.example/mcp \
  --token-file /private/mcp_token download res_<handle> investigation.jsonl \
  --trusted-key /private/server-signing.pem
```

Downloads verify a signed manifest and complete file before publishing the local file and
its `.signature.json` receipt. They refuse to overwrite existing files and remove temporary
files on failure. See [secure transfers](secure-transfers.md) for private CA trust, key
provisioning, offline verification and migration from unsigned uploads.
Defaults are 2 GiB per file and 10 GiB total reserved upload space. Set
`CHAINSAW_UPLOAD_MAX_BYTES` and `CHAINSAW_UPLOAD_QUOTA_BYTES` in the service environment to
change them. Completed uploads and incomplete reservations count toward the quota and
persist across restarts; there is no automatic evidence expiry. Operators manage retention
offline, including the matching `staging/upl_*.json` reservation records. An unreadable
reservation record blocks new uploads, naming the record, until the operator reconciles it. Empty
`CHAINSAW_UPLOAD_DIR` disables uploads outside the image. Result handles expire after
seven days, independently of uploaded evidence.

## Persistent state and operation

| Path | Contents | Access |
|---|---|---|
| `/evidence` | Host or network-mounted evidence | Read-only |
| `/data/uploads/evidence` | Verified client uploads | Published once; read-only to tools |
| `/data/uploads/staging` | Resumable transfers and reservations | Private |
| `/data/results` | Results, replay exports and derived mappings | Private |
| `/data/custom-rules` | Analyst-authored rules | Writable through rule tools |
| `/opt/chainsaw-mcp/vendor/chainsaw` | Binary, bundled rules and mappings | Image content |

The process runs as UID/GID 10001 with a read-only root filesystem, no capabilities,
no privilege escalation, a temporary `/tmp`, and a persistent named `/data` volume.
Bind-mounted state directories must be writable by UID 10001; evidence must be readable
by it. Back up the data volume. `docker compose down` preserves it;
`docker compose down -v` destroys the state and uploaded evidence.

The health check performs an authenticated MCP handshake and tool-catalog request.
Use `chainsaw_status` for binary/rule/evidence readiness. Clients sharing the token share
all evidence, rules and handles: this deployment is for one trusted investigation team,
not isolated tenants. Deploy separate instances and volumes for separate access scopes.

For updates, rebuild and recreate with `docker compose up --build -d`. Record the image
ID/digest with investigation exports. Builds use locked Python dependencies and a
checksummed Chainsaw bundle/source. Python, uv and the Dockerfile frontend are pinned by
multi-platform manifest digest. Retain the built image for exact replay. Linux amd64 and
arm64 use the upstream release binaries.

Run `bash scripts/container-check.sh` on a Docker-enabled development host to build and
test authentication, uploads, native analysis, planning and downloads. GitHub Actions runs
this gate on every push and pull request. Jobs run as a
non-root user with Docker access. The CI machine must be dedicated to trusted builds:
access to a rootful Docker socket grants control over that machine.

Set `CHAINSAW_BUILD_NETWORK=host` if a host's bridge MTU causes TLS failures during image
builds. Runtime containers retain their normal bridge network and loopback-only
published port. Builds use the default network unless this variable is set.
Each check uses its own image tag and removes its test image and container afterwards;
on failure it prints the container logs. The runner needs Docker Engine, Compose v2,
Buildx, Python, uv, Git, Node.js and OpenSSL. Verify the runner account can run `docker info`
and `docker compose version` before assigning container jobs to it.

For runners with systemd `PrivateTmp=true`, set `CHAINSAW_CONTAINER_TMPDIR` to a writable
directory visible at the same path to the runner and Docker daemon. Create a directory such
as `/var/lib/ci-runner/container-tmp` for this purpose, preserving the runner's private
`/tmp`. The check creates and removes a unique subdirectory there. Public trust directories
and certificates receive explicit traverse/read access; private keys stay owner-only.

## Refresh image pins

The comments beside the pins retain the upstream tags. Inspect the new multi-platform
index digests (not an individual platform image):

```sh
docker buildx imagetools inspect python:3.12-slim-bookworm
docker buildx imagetools inspect ghcr.io/astral-sh/uv:0.12.19
docker buildx imagetools inspect docker/dockerfile:1
```

Update both Python `FROM` digests together, the uv `COPY --from` digest and the frontend
`syntax` digest as appropriate; update tag comments when changing versions. Confirm the
indexes include linux/amd64 and linux/arm64. Run all three checks in `CONTRIBUTING.md`,
including a real container build/remote workflow, then submit the pin changes for review.
Record the resulting built image digest with investigation exports. Digest pins make
updates deliberate; schedule refreshes to pick up upstream security fixes.
