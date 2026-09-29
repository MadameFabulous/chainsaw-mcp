# Container contents

The Python MCP wrapper is MIT licensed. The container also distributes:

- Chainsaw v2.16.5 (WithSecure Labs), GPL-3.0. Its licence is at
  `/opt/chainsaw-mcp/vendor/chainsaw/LICENCE`. The corresponding upstream source archive
  is included at `/usr/share/licenses/chainsaw/source-v2.16.5.tar.gz`; its README,
  Cargo.toml and Cargo.lock describe the Rust build (`cargo build --release --locked`).
  Source: <https://github.com/WithSecureLabs/chainsaw/tree/v2.16.5>.
- The Sigma rules shipped in the checksummed Chainsaw release bundle. See
  `/opt/chainsaw-mcp/vendor/chainsaw/sigma/LICENSE` for Detection Rule License 1.1 terms.
- Python dependencies installed from `uv.lock`; their distribution metadata and
  licences remain in `/opt/chainsaw-mcp/.venv/lib/python3.12/site-packages`.

Container distributors must preserve these notices and the relevant upstream licence
and source-distribution obligations. The wrapper's MIT licence does not relicense
Chainsaw or the detection rules.
