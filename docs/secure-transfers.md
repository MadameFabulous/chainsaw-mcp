# Signed and encrypted file transfers

Remote MCP uses native HTTPS with TLS 1.2 or newer and bearer authentication. The supplied
transfer client verifies the certificate chain and hostname, refuses HTTP and redirects,
and has no insecure certificate-bypass option. Proxies must connect to the backend using
HTTPS too; the server does not trust `X-Forwarded-Proto` as proof of encryption. Plain
HTTP to the listener is rejected at the TLS handshake and receives no HTTP response.

Files have independent **Ed25519 signatures**. An upload signature binds its filename,
byte count and SHA-256. A download signature binds the result handle, stored format,
byte count and SHA-256. SHA-256 alone is a checksum, not a signature. TLS protects bytes
in transit; this feature does not encrypt stored evidence or results on disk.

## Establish keys and trust

Generate separate keys for the server and each uploading analyst. Keep private keys with
their owners; distribute public keys through an authenticated channel and compare the
printed key IDs out of band. Never accept a public key just because it accompanied a file.

On the server host, after `uv sync`:

```sh
mkdir -p secrets/upload-trust evidence
chmod 700 secrets
uv run chainsaw-mcp-transfer keygen \
  --private-key secrets/server-signing.key --public-key secrets/server-signing.pem
(umask 077 && openssl rand -hex 32 > secrets/mcp_token)
```

On an analyst workstation:

```sh
mkdir -p secrets
chmod 700 secrets
uv run chainsaw-mcp-transfer keygen \
  --private-key secrets/analyst-signing.key --public-key secrets/analyst-signing.pem
```

Install the approved analyst **public** key as `secrets/upload-trust/analyst.pem` on the
server. Install the server **public** key as `secrets/server-signing.pem` on the workstation.
The keygen command creates files with mode 0600 and refuses to overwrite either key.
It never places private keys in images, tool output or manifests.

For a local demonstration only, both pairs can be generated on one host; copy the analyst
public key into `secrets/upload-trust/`. Production analyst private keys stay on their
workstations. The server's upload trust directory contains only approved public `.pem` keys.

## Configure HTTPS

Supply `secrets/tls.crt` and `secrets/tls.key` from your certificate authority. The certificate
must cover the DNS names/IP addresses clients use. Compose's default health probe uses
`127.0.0.1`, so include that IP in the certificate's SANs, or override the health check to
use a resolvable certificate-covered name (see the commented example in `compose.yaml`). Set `MCP_TLS_CA_SOURCE` to the issuing CA bundle;
for a publicly trusted certificate a system CA bundle is also suitable. Do not substitute
a self-signed certificate for a managed production certificate without distributing trust.

For a local demonstration, generate a short-lived certificate and explicitly trust it:

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 7 \
  -subj /CN=localhost -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
  -keyout secrets/tls.key -out secrets/tls.crt
```

Compose defaults `MCP_TLS_CA_SOURCE` to this certificate for the local self-signed case.
Mount the signing key, TLS key and bearer token using the provided Compose secrets. Compose
bind-mounts secret files with their host ownership and mode, and the non-root container
UID 10001 must read them. Give the private files to that UID with mode 0400:

```sh
cp secrets/mcp_token secrets/mcp_token.client   # host-side copy for clients and probes
sudo chown 10001:10001 secrets/mcp_token secrets/tls.key secrets/server-signing.key
sudo chmod 0400 secrets/mcp_token secrets/tls.key secrets/server-signing.key
chmod 644 secrets/tls.crt
chmod 755 secrets/upload-trust
chmod 644 secrets/upload-trust/*.pem
docker compose up --build -d
uv run python scripts/mcp-health.py https://127.0.0.1:18098/mcp \
  --bearer-token-file secrets/mcp_token.client --ca-file secrets/tls.crt
```

With rootless Docker, run the `chown`/`chmod` inside the user namespace instead, e.g.
`docker run --rm --user 0 --entrypoint sh -v "$PWD/secrets:/s" chainsaw-mcp:local -c
'chown 10001:10001 /s/mcp_token /s/tls.key /s/server-signing.key && chmod 0400 /s/mcp_token
/s/tls.key /s/server-signing.key'` after the first build.

The server refuses a token file with any group or other permission bits, so the token has
no world-readable fallback. Only where ownership cannot be changed may `tls.key` and
`server-signing.key` fall back to `chmod 644` under the private mode-0700 `secrets/`
parent. For non-Compose deployments, make the token owned by the service user with mode
0400 or 0600, and use service-user ownership or group access instead of broadly readable
keys. Server settings are:

| Setting | Purpose |
|---|---|
| `MCP_AUTH_TOKEN_FILE` | Shared endpoint authentication; distinct from signing keys; mode 0400/0600 only |
| `MCP_TLS_CERT_FILE`, `MCP_TLS_KEY_FILE` | Required certificate chain and private key for the remote listener |
| `MCP_TLS_CA_FILE` | CA/certificate used by the health probe, not a client authentication certificate |
| `CHAINSAW_UPLOAD_TRUSTED_KEYS_DIR` | Trusted uploader public `.pem` keys; uploads reject missing or unknown signatures |
| `CHAINSAW_TRANSFER_SIGNING_KEY_FILE` | Server Ed25519 private PEM key; signed downloads fail closed if absent |
| `CHAINSAW_CUSTODY_TRUSTED_KEYS_DIR` | Optional additional custody manifest signer public `.pem` keys; separate from upload trust |

Local stdio does not use TLS. File signatures are still required for upload ingestion and
the signed-download workflow. Existing mounted evidence can still be investigated without
transfer keys. Removing an upload trust key takes effect after restart and prevents
publication of unfinished uploads signed by that key; it does not delete existing evidence.

## Upload and download

```sh
uv run python scripts/remote-client.py https://forensics.example/mcp \
  --token-file secrets/mcp_token.client upload /cases/host1/Security.evtx \
  --signing-key secrets/analyst-signing.key

uv run python scripts/remote-client.py https://forensics.example/mcp \
  --token-file secrets/mcp_token.client download res_<handle> investigation.jsonl \
  --trusted-key secrets/server-signing.pem
```

For a private CA/self-signed endpoint add `--ca-file /path/to/ca.pem` **before** `upload`
or `download`. After an interrupted upload use `--resume upl_<id>` with the same source
file and signing key. Final publication rechecks signer trust and the complete size/hash.
The server retains the upload attestation in its reservation metadata.

Downloads fetch `chainsaw_result_manifest`, verify its signature using the pinned server
key, then stream `chainsaw_result_chunk` to a private temporary file. They verify the
complete file before publishing it and a sibling `<filename>.signature.json` receipt.
Existing files/receipts are never overwritten. Failed transfers clean up temporary files;
a process or host crash can leave a private `.chainsaw-download-*` directory for removal.
Keep the receipt with the file and its trusted public key. Verify it offline with:

```sh
uv run chainsaw-mcp-transfer verify investigation.jsonl \
  --signature-file investigation.jsonl.signature.json --trusted-key secrets/server-signing.pem
```

A renamed download still verifies by bytes; the signed manifest identifies its original
result handle. Converting JSONL to CSV or redacting a file creates a new derivative, so
the original signature no longer verifies that derivative. Record the transformation and
retain the signed original. MCP pages and projected CSV exports are investigative views;
clients seeking a signed file must verify the complete stored bytes against the manifest.

## Signature format and limits

An attestation contains `algorithm: Ed25519`, `key_id`, `manifest`, and a base64 `signature`.
`key_id` is the SHA-256 of the raw 32-byte Ed25519 public key. Signed bytes are the ASCII
domain prefix `chainsaw-mcp-transfer-v1\n` followed by Python-compatible JSON with sorted
keys, compact separators, ASCII escaping and no non-finite numbers. The descriptor includes
`version: 1`, `purpose`, `size_bytes` and `sha256`. Transfer purposes are `upload` (also
binds `name`) and `download` (also binds `handle` and `format`). The
[custody tools](custody.md) use `evidence-manifest` and `evidence-validation` to sign complete
JSONL records containing scope, timestamps and declarations. Upload, download and custody
consumers enforce their expected purpose, so a signature for one purpose never verifies as
another. The offline `verify` command requires a purpose with `--purpose` (default
`download`; also `upload`, `evidence-manifest` or `evidence-validation`) and rejects
signatures made for anything else; it does not rescan an evidence directory. Use the packaged
functions when signing from Python to avoid serialization differences. A received envelope
cannot introduce trust.

Signatures establish that a trusted key signed those bytes and descriptor. They do not
establish acquisition time, freshness, chain of custody, or the truth of a report. Reusing
a valid upload attestation for the same named content is permitted. Protect and rotate
signing keys; retain historical public keys with archived evidence, and handle key compromise
through your organisation's trust/revocation procedure. Keys are loaded at server startup.

This protects the MCP transfer path. Host-mounted NFS/SMB traffic needs its own protection:
for example Kerberos privacy (`sec=krb5p`) for NFS or SMB 3 encryption (`seal`) with suitable
server policy. A read-only mount alone supplies neither encryption nor file signatures.

## Upgrade existing deployments

Configure TLS and signing trust before restarting the updated server; switch clients and
gateway backend URLs to `https://`. Gateways must validate the backend certificate too.
Older clients making unsigned uploads are rejected. Old unfinished unsigned uploads can
be inspected/aborted and re-uploaded with a signature; already published evidence is kept.
Historical files do not acquire uploader signatures retroactively. The server can sign a
current export of a retained result, with the provenance limits described above.
