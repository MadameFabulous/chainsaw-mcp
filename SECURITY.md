# Security policy

## Reporting a vulnerability

Please do not open a public issue for security problems. Use the repository's private
vulnerability reporting form ("Report a vulnerability" under the Security tab) or contact
the maintainers directly. Include the affected version, reproduction steps and, where
possible, a minimal evidence sample. You will get an acknowledgement within a few days.

## What this server protects

chainsaw-mcp runs the Chainsaw binary against forensic artefacts on behalf of an MCP
client, usually an LLM agent. The security goals, in order:

1. **Existing evidence is never modified.** Every client-supplied path is resolved,
   symlinks included, and must stay inside allowed roots. Docker and systemd mount source
   evidence read-only. Remote uploads stage outside evidence roots and publish new files
   once a trusted Ed25519 signature, declared size and SHA-256 are verified. Uploads never
   overwrite existing files.
2. **No shell, no injection.** Chainsaw is executed as an argument list with `--` before
   evidence paths; user input never reaches a shell.
3. **Bounded output.** Results are stored as private (0700/0600) files under
   `CHAINSAW_OUTPUT_DIR`, expire after seven days, and are delivered through byte-budgeted
   pages so a hostile log cannot exhaust the client.
4. **No surprise egress.** The server makes no outbound connections except the checksummed
   bootstrap download and `chainsaw_jev_triage`, which is disabled unless
   `CHAINSAW_JEV_ENABLED=true` and sends only the rows and fields the caller selects.
5. **Verified supply chain.** The Chainsaw bundle is pinned by SHA-256 and byte count, the
   extracted Linux x86_64 binary by SHA-256, container source archive by SHA-256,
   Python/uv images and the Dockerfile frontend by manifest digest,
   Python dependencies by `uv.lock`, and CI actions by
   commit SHA.
6. **Signed, encrypted remote file transfers.** Native HTTPS requires TLS 1.2 or newer and
   bearer authentication. The supplied client validates certificate chains/hostnames and
   independently pinned Ed25519 file signatures. Downloads are published only after their
   signed size/hash match, with a receipt for offline verification. Missing trust or invalid
   signatures fail closed. See [transfer configuration](docs/secure-transfers.md).

## What it does not protect

- **Shared authentication is not tenant isolation.** Remote HTTPS requires a bearer token
  from `MCP_AUTH_TOKEN_FILE` or `MCP_AUTH_TOKEN`. Every authenticated client shares evidence, rules, results,
  upload quota and any enabled Jev API credit. Use separate deployments for separate
  access scopes. Use stdio for local access without TLS/authentication. DNS-rebinding checks
  remain enabled. The remote listener requires native TLS even behind a gateway.
- **Stored files are not encrypted by this application.** TLS protects the MCP network
  connection. Disk encryption and NFS/SMB transport protection are separate host controls.
  Signatures attest to bytes and descriptors signed by a trusted key; they do not establish
  acquisition time, chain of custody, truth of findings, or protection from a compromised
  signer. MCP pages/derived exports need their own verification if used instead of the
  signed complete-file transfer workflow. Keep public keys for archived signature receipts.
- **Availability depends on resource limits.** Uploads have a per-file limit and a shared
  quota that counts retained uploaded evidence plus incomplete reservations; incomplete
  uploads reserve space until aborted, and published evidence counts until the operator
  removes it and its `staging/upl_*.json` reservation record offline. An unreadable
  reservation record blocks new uploads until it is reconciled. Results and parser
  work can still consume disk, memory and CPU. Docker Compose supplies process/memory
  limits; operators must provision storage and manage retention.
- **Replay exports do not prove historical input identity.** Input hashes and mapping
  snapshots are taken at export time. Preserve immutable acquisition evidence, rule sets
  and the image digest. Exports contain paths and investigation filters and are sensitive.
  Unlike diagnostics and result metadata, which hide these locations, `chainsaw_reproduce` and
  `chainsaw_plan` scripts and manifests deliberately keep server-absolute Chainsaw binary,
  evidence-root and result-store paths in recorded argv and root defaults for provenance.
  Treat default exports as disclosing the server's filesystem layout. Opt-in
  `redact_paths=true` produces an explicitly labelled derivative without those configured
  paths or root defaults; relative names, filters and mapping content still need review
  before sharing. See [replay modes](docs/reproducibility.md).
- **Evidence content is untrusted but is still shown to the agent.** Event logs can
  contain prompt-injection text. The server bounds and structures the output; it does not
  sanitise log content, and the agent must treat it as data.
- **Stored results are as sensitive as the evidence.** Treat `CHAINSAW_OUTPUT_DIR` like
  the evidence directory and delete handles you no longer need.
- **Chainsaw itself** is an upstream GPL-3.0 binary. Vulnerabilities in its parsers should
  be reported to [WithSecure Labs](https://github.com/WithSecureLabs/chainsaw/security).

## Supported versions

Only the latest release on the `main` branch receives fixes.
