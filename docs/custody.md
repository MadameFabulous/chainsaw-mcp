# Evidence manifests and chain-of-custody records

`chainsaw_evidence_manifest` creates a signed inventory of an evidence directory.
`chainsaw_evidence_validate` authenticates that inventory and compares a directory against
it, producing a signed validation receipt. Use them before/after copying evidence, handing
it to another custodian, or analysing a mounted collection. Both tools read evidence and
write new result artefacts outside the selected directory; they never repair evidence.

These records support chain-of-custody (CoC) activities. They establish what the server
observed and which trusted key signed the record. They do not establish acquisition time,
custodian identity, snapshot immutability, or an uninterrupted custody history. Timestamps
come from the server clock. Operator and handoff fields are explicitly labelled supplied
declarations. Keep collection records, authenticated handoff approvals and storage audit
logs alongside these artefacts.

## Configure signing and trust

Configure `CHAINSAW_TRANSFER_SIGNING_KEY_FILE` with the server's Ed25519 private key using
the [secure transfer setup](secure-transfers.md). Both tools require it so every published
manifest or validation receipt is signed. The current server key is automatically trusted
for validating its own manifests.

For manifests from another server or a previous signing key, configure
`CHAINSAW_CUSTODY_TRUSTED_KEYS_DIR` with independently approved Ed25519 public `.pem` keys.
Upload signer trust is separate: an approved uploader is not automatically a trusted
custody manifest signer. Keys load at startup; restart after trust changes. Keep trust
configuration outside the evidence mount, restrict who can change it, and compare public
key fingerprints through an authenticated channel. A public key delivered with evidence
does not establish trust by itself.

Compose already supplies the signing key. If additional custody signers are needed, place
approved public keys in `secrets/custody-trust/` and add a `compose.override.yaml`:

```yaml
services:
  chainsaw:
    environment:
      CHAINSAW_CUSTODY_TRUSTED_KEYS_DIR: /run/custody-trust
    volumes:
      - type: bind
        source: ./secrets/custody-trust
        target: /run/custody-trust
        read_only: true
        bind:
          create_host_path: false
```

Make the directory and public keys readable by container UID 10001. The server's private
key stays in its separate secret mount. Retain historical public keys under your trust
and revocation policy; restoring an old key to trust is an explicit operator decision.

## Create and validate

Call `chainsaw_evidence_manifest` with MCP arguments such as:

```json
{
  "path": "/evidence/IR-42/host-01",
  "context": {
    "case_id": "IR-42",
    "evidence_id": "E-001",
    "operator": "Analyst A",
    "action": "baseline before analysis",
    "snapshot_id": "storage-snapshot-42"
  }
}
```

The response includes `manifest_handle`, `signature_handle`, `sha256`, `size_bytes`,
`signer_key_id`, counts and completion time. The manifest covers **all** regular
files, including hidden files and unrecognised extensions, plus directories (including
empty directories and the root). Paths inside the inventory are relative, allowing a copy
to be validated at another location. Each file has SHA-256, size and modification time;
the header records the original absolute scope, server version and declarations.

Call `chainsaw_evidence_validate` using the returned handles and either the original
directory or a relocated copy:

```json
{
  "path": "/evidence/IR-42/received-host-01",
  "manifest": "res_<manifest_handle>",
  "signature": "res_<signature_handle>",
  "context": {
    "case_id": "IR-42",
    "evidence_id": "E-001",
    "operator": "Analyst B",
    "action": "verify received copy",
    "from_custodian": "Analyst A",
    "to_custodian": "Analyst B",
    "reason": "handoff for analysis"
  }
}
```

Replace the illustrative handles with actual returned values. Validation verifies the
signature, complete manifest bytes and schema before scanning the target. It returns
`validation_handle`, `signature_handle`, the receipt's digest/signer and one of:

| Status | Meaning |
|---|---|
| `match` | Every expected path/type and file size/hash matches, no unexpected entries, and stability checks passed. `valid: true`. |
| `mismatch` | Comparison completed and found changed, missing, unexpected or differently typed entries. `valid: false`. |
| `incomplete` | Read errors, unreadable paths, an observed change during validation, a truncated receipt, or resource limits prevented a reliable full comparison. `valid: false`. |

`mismatches_found` is true whenever changed, missing, unexpected or differently typed
entries were recorded, so an `incomplete` result still shows definite differences. A
directory or file the server cannot read gets an `unreadable` row (as do expected entries
beneath an unreadable directory); the comparison continues with the other paths. Receipts
may grow to four times the manifest size limit; beyond that, per-path rows stop, a
`truncated` diagnostic is written, `truncated` is true and the receipt is still signed.

Page `validation_handle` using `chainsaw_result_page` for per-path results. Modification
time differences are reported as `metadata_changed` separately; they do not invalidate a
content match. Size differences are reported without hashing that changed file. Unexpected
files are listed without hashing them. Permissions, ownership, ACLs, extended attributes,
alternate streams and hard-link relationships are outside the comparison contract.

Invalid signatures, malformed manifests, missing signing configuration or an unavailable
initial scope fail the tool without issuing a validation receipt. Manifest creation fails
without publishing a baseline if any entry cannot be inventoried/hashed reliably.

Both tools accept these optional `context` strings, each up to 2048 characters: `case_id`,
`evidence_id`, `operator`, `action`, `from_custodian`, `to_custodian`, `reason`, `snapshot_id`,
`notes`, `previous_manifest_sha256`. The last field must be a lowercase SHA-256 digest;
it records a reference to an earlier manifest but does not fetch or validate that history.
Preserve earlier artefacts and review their relationships when documenting a custody chain.

## Preserve and verify the records

Result handles normally expire after seven days. Download **both** the manifest and its
detached signature; also save each validation receipt and its signature. The signatures
are single-object JSONL files, readable as JSON. Preserve exact bytes: reformatting a
manifest or receipt invalidates its signature.

Use the [verified HTTPS client](secure-transfers.md#upload-and-download) to download each
handle separately, for example saving them as `manifest.jsonl` and `manifest-signature.json`.
The client's additional `.signature.json` files are download receipts. Those use the
`download` purpose; the custody signature returned by `chainsaw_evidence_manifest` uses
`evidence-manifest`. Supply the latter to `chainsaw_evidence_validate`.

Verify an archived manifest offline:

```sh
uv run chainsaw-mcp-transfer verify manifest.jsonl --purpose evidence-manifest \
  --signature-file manifest-signature.json --trusted-key secrets/server-signing.pem
```

The command defaults to `--purpose download` and rejects a signature made for another
purpose, so custody records need an explicit purpose. Verify a validation receipt against
its own detached signature with `--purpose evidence-validation`. Offline file verification authenticates the record's bytes; use
`chainsaw_evidence_validate` for a fresh comparison against the evidence directory.

After handles expire, `manifest` and `signature` can instead be saved file paths under an
allowed evidence root, including verified uploads. Store these records in a separate
sibling directory, outside the collection being compared, so they do not become unexpected
evidence entries. Archive the trusted signer identity, acquisition references and approval
records in the case store. The artefacts contain paths and supplied case details; apply
the case's access and retention controls to them.

## Mounted volumes and limits

Use a storage snapshot or immutable evidence copy and mount it read-only for analysis.
Docker `:ro` prevents container writes through that mount; the host or storage service may
still change the underlying files. The tools reject in-tree symlinks and special files,
open paths without following substituted links, and compare file/directory metadata before
and after observation. These checks detect observed changes; they cannot prove a hostile
host or storage service supplied an atomic view. A signature also cannot compensate for a
compromised signer. Keep signer keys and trusted public keys under separate access controls.

Default limits are 100,000 inventory entries (including directories/root), 64 GiB of bytes
to hash, and the configured `CHAINSAW_TIMEOUT` per evidence scan. `max_entries` can be
lowered; `max_total_bytes` can be adjusted. Large collections may need separate, explicitly
documented scopes and a longer server timeout. The timeout is cooperative and cannot
interrupt a kernel or network-filesystem read that blocks. Inventories also limit directory
depth to 128 and reject repeated directory identities; signed artefacts are limited to
64 MiB with 64 KiB rows. Nested mounts are traversed subject to these checks.

Hashing may update access times on a writable filesystem; read-only snapshots avoid that
side effect. HTTPS protects MCP transfers. NFS/SMB mounts need their own transport security,
such as NFS Kerberos privacy or SMB encryption. This feature does not encrypt files at rest.
