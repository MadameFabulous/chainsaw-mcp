# Security policy

## Reporting a vulnerability

Please do not open a public issue for security problems. Use the repository's private
vulnerability reporting form ("Report a vulnerability" under the Security tab) or contact
the maintainers directly. Include the affected version, reproduction steps and, where
possible, a minimal evidence sample. You will get an acknowledgement within a few days.

## What this server protects

chainsaw-mcp runs the Chainsaw binary against forensic artefacts on behalf of an MCP
client, usually an LLM agent. The security goals, in order:

1. **Evidence is never modified.** Every client-supplied path is resolved, symlinks
   included, and must stay inside `CHAINSAW_EVIDENCE_ROOTS`. The systemd unit additionally
   mounts the evidence tree read-only.
2. **No shell, no injection.** Chainsaw is executed as an argument list with `--` before
   evidence paths; user input never reaches a shell.
3. **Bounded output.** Results are stored as private (0700/0600) files under
   `CHAINSAW_OUTPUT_DIR`, expire after seven days, and are delivered through byte-budgeted
   pages so a hostile log cannot exhaust the client.
4. **No surprise egress.** The server makes no outbound connections except the checksummed
   bootstrap download and `chainsaw_jev_triage`, which is disabled unless
   `CHAINSAW_JEV_ENABLED=true` and sends only the rows and fields the caller selects.
5. **Verified supply chain.** The Chainsaw bundle is pinned by SHA-256 and byte count, the
   extracted Linux binary by SHA-256, Python dependencies by `uv.lock`, and CI actions by
   commit SHA.

## What it does not protect

- **The HTTP transport has no authentication.** Streamable HTTP is meant for a loopback
  or private overlay network (for example a tailnet) where reachability is the access
  control. DNS-rebinding protection is always on, but anyone who can reach the port can
  read the configured evidence and, if Jev is enabled, spend API credit. Never bind to
  `0.0.0.0` or a LAN address.
- **Evidence content is untrusted but is still shown to the agent.** Event logs can
  contain prompt-injection text. The server bounds and structures the output; it does not
  sanitise log content, and the agent must treat it as data.
- **Stored results are as sensitive as the evidence.** Treat `CHAINSAW_OUTPUT_DIR` like
  the evidence directory and delete handles you no longer need.
- **Chainsaw itself** is an upstream GPL-3.0 binary. Vulnerabilities in its parsers should
  be reported to [WithSecure Labs](https://github.com/WithSecureLabs/chainsaw/security).

## Supported versions

Only the latest release on the `main` branch receives fixes.
