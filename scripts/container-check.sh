#!/usr/bin/env bash
# Build and exercise the real image over its remote MCP endpoint. Needs Docker and uv.
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
# A systemd runner's private /tmp is invisible to the host Docker daemon.
work=$(mktemp -d "${CHAINSAW_CONTAINER_TMPDIR:-${TMPDIR:-/tmp}}/chainsaw-container.XXXXXXXX")
image="chainsaw-mcp:check-$(basename "$work")"
container_id=
cleanup() {
    local status=$?
    if [[ -n "$container_id" ]]; then
        if ((status != 0)); then docker logs "$container_id" >&2 || true; fi
        docker rm -f "$container_id" >/dev/null || true
    fi
    docker image rm "$image" >/dev/null 2>&1 || true
    rm -rf "$work"
    exit "$status"
}
trap cleanup EXIT
mkdir "$work/evidence" "$work/upload-trust" "$work/secrets"
chmod 755 "$work" "$work/evidence" "$work/secrets" "$work/upload-trust"
python3 -c 'import secrets; print(secrets.token_hex(32))' > "$work/token"
chmod 600 "$work/token"
# The host keeps $work/token for clients; the server mounts a copy owned by its UID.
cp "$work/token" "$work/secrets/mcp_token"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
    -subj /CN=localhost -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
    -keyout "$work/tls.key" -out "$work/tls.crt" 2>/dev/null
uv run chainsaw-mcp-transfer keygen --private-key "$work/server.key" --public-key "$work/server.pem"
uv run chainsaw-mcp-transfer keygen --private-key "$work/client.key" \
    --public-key "$work/upload-trust/client.pem"
mv "$work/tls.key" "$work/server.key" "$work/secrets/"
chmod 644 "$work/upload-trust/client.pem" "$work/tls.crt"
export MCP_TLS_CERT_SOURCE="$work/tls.crt" MCP_TLS_KEY_SOURCE="$work/secrets/tls.key"
export MCP_TLS_CA_SOURCE="$work/tls.crt"
export CHAINSAW_TRANSFER_SIGNING_KEY_SOURCE="$work/secrets/server.key"
export CHAINSAW_UPLOAD_TRUST_SOURCE="$work/upload-trust"
CHAINSAW_EVIDENCE_PATH="$work/evidence" MCP_AUTH_TOKEN_SOURCE="$work/secrets/mcp_token" \
    docker compose --env-file /dev/null config --quiet
CHAINSAW_EVIDENCE_PATH="$work/evidence" MCP_AUTH_TOKEN_SOURCE="$work/secrets/mcp_token" \
    NFS_SERVER=192.0.2.20 NFS_EXPORT=/exports/cases \
    docker compose --env-file /dev/null -f compose.yaml -f deploy/compose.nfs.yaml config --quiet
# CI may use host networking for builds when the bridge MTU breaks registry TLS.
docker build --network "${CHAINSAW_BUILD_NETWORK:-default}" -t "$image" .
# Documented primary route: private files owned by the container UID, mode 0400. Running
# chown in a container also works under rootless Docker's user namespace.
docker run --rm --user 0:0 --network none --entrypoint sh \
    --mount "type=bind,src=$work/secrets,dst=/s" "$image" \
    -c 'chown 10001:10001 /s/* && chmod 0400 /s/*'
container_id=$(docker run -d --read-only --tmpfs /tmp:rw,noexec,nosuid,size=256m \
    --cap-drop ALL --security-opt no-new-privileges:true \
    -p 127.0.0.1::18098 \
    --mount "type=bind,src=$work/evidence,dst=/evidence,readonly" \
    --mount "type=bind,src=$work/secrets/mcp_token,dst=/run/secrets/mcp_token,readonly" \
    --mount "type=bind,src=$work/tls.crt,dst=/run/secrets/tls_cert,readonly" \
    --mount "type=bind,src=$work/secrets/tls.key,dst=/run/secrets/tls_key,readonly" \
    --mount "type=bind,src=$work/secrets/server.key,dst=/run/secrets/transfer_signing_key,readonly" \
    --mount "type=bind,src=$work/upload-trust,dst=/run/upload-trust,readonly" \
    --tmpfs /data:rw,uid=10001,gid=10001,mode=700 \
    -e MCP_AUTH_TOKEN_FILE=/run/secrets/mcp_token \
    -e MCP_TLS_CERT_FILE=/run/secrets/tls_cert -e MCP_TLS_KEY_FILE=/run/secrets/tls_key \
    -e MCP_TLS_CA_FILE=/run/secrets/tls_cert \
    -e CHAINSAW_TRANSFER_SIGNING_KEY_FILE=/run/secrets/transfer_signing_key \
    -e CHAINSAW_UPLOAD_TRUSTED_KEYS_DIR=/run/upload-trust "$image")
port=$(docker port "$container_id" 18098/tcp | sed 's/.*://')
uv run python scripts/mcp-health.py "https://127.0.0.1:$port/mcp" \
    --bearer-token-file "$work/token" --ca-file "$work/tls.crt" --attempts 30
uv run python scripts/remote-smoke.py "https://127.0.0.1:$port/mcp" "$work/token" \
    "$work/tls.crt" "$work/client.key" "$work/server.pem"
docker exec "$container_id" chainsaw --version
