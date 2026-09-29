"""Turn recorded invocations into portable, quoted replay scripts and manifests.

Hashes describe files at export time. They cannot prove that mutable mounted evidence
or custom rules had the same bytes when an earlier command ran.
"""

from __future__ import annotations

import base64
import hashlib
import json
import shlex
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from .config import Settings
from .paths import resolve_under
from .results import ResultMeta

PATH_OPTIONS = {"--sigma", "--rule", "--mapping", "--amcache", "--software"}
PATH_INPUTS = {
    "paths",
    "mapping",
    "extra_rules",
    "system_hive",
    "amcache_hive",
    "srum_db",
    "software_hive",
}
NOTE = (
    "Commands are recorded invocations; hashes and mapping snapshots are measured at export "
    "time, not at investigation time. Preserve the original read-only evidence, rules and "
    "image digest. Successful replay does not establish parse completeness."
)
DERIVED_NOTE = (
    "Commands reproduce native Chainsaw output. MCP coverage aggregation, lineage host/GUID "
    "filtering, deduplication, traversal limits, previews and result summaries are Python "
    "post-processing, not standalone Chainsaw output; see recorded tool inputs."
)


def fingerprint(path: Path) -> dict[str, Any]:
    before = path.stat()
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    after = path.stat()
    if (before.st_size, before.st_mtime_ns, before.st_ino) != (
        after.st_size,
        after.st_mtime_ns,
        after.st_ino,
    ):
        raise ValueError("An input changed during hashing; export from a stable evidence snapshot")
    return {"sha256": digest.hexdigest(), "bytes": after.st_size}


class Reproduction:
    """One export: remap known path arguments while preserving every other argument."""

    def __init__(self, settings: Settings, *, redact_paths: bool = False) -> None:
        self.settings = settings
        self.redact_paths = redact_paths
        self.roots = [(f"EVIDENCE_{i}", p) for i, p in enumerate(settings.evidence_roots, 1)] + [
            ("CHAINSAW_RULES", settings.rules_dir),
            ("SIGMA_RULES", settings.sigma_dir),
            ("CUSTOM_RULES", settings.custom_rules_dir),
            ("MAPPINGS", settings.mappings_dir),
            ("DERIVED_MAPPINGS", settings.output_dir / ".mappings"),
        ]
        self.used: dict[str, Path] = {}
        self.dependencies: dict[Path, str] = {}
        self.snapshots: dict[Path, tuple[str, bytes]] = {}
        self.commands: list[dict[str, Any]] = []

    def redact(self, value: Any) -> Any:
        """Label configured paths in derivative metadata; never alter the stored record."""
        if isinstance(value, dict):
            return {self.redact(k): self.redact(v) for k, v in value.items()}
        if isinstance(value, list):
            return [self.redact(v) for v in value]
        if not isinstance(value, str):
            return value
        paths = self.roots + [("RESULTS", self.settings.output_dir)]
        if self.settings.binary:
            paths.append(("CHAINSAW_BIN", self.settings.binary))
        for label, path in sorted(paths, key=lambda pair: -len(str(pair[1]))):
            value = value.replace(str(path), "${" + label + "}")
        return value

    def _path(self, raw: str, *, snapshot: bool = False) -> str:
        path = resolve_under(raw, [p for _, p in self.roots], what="reproduction input")
        if snapshot:
            if not path.is_file() or path.stat().st_size > 2_000_000:
                raise ValueError("Mapping snapshot must be a file of at most 2 MB")
            if path not in self.snapshots:
                data = path.read_bytes()
                if self.redact_paths:
                    content = data.decode("utf-8")
                    if self.redact(content) != content:
                        raise ValueError(
                            "Mapping contains server paths; supply a sanitised mapping for "
                            "a redacted export"
                        )
                self.snapshots[path] = (f"mapping-{len(self.snapshots) + 1}.yml", data)
            name, _ = self.snapshots[path]
            expression = f'"${{OUTPUT_DIR}}/assets/{name}"'
        else:
            for variable, root in sorted(self.roots, key=lambda pair: -len(str(pair[1]))):
                if path.is_relative_to(root):
                    self.used[variable] = root
                    relative = str(path.relative_to(root))
                    expression = f'"${{{variable}}}"'
                    if relative != ".":
                        expression += "/" + shlex.quote(relative)
                    break
            else:  # resolve_under already checked containment
                raise ValueError("Unrecognised reproduction input")
        self.dependencies[path] = expression
        return expression

    def _redacted_inputs(self, inputs: dict[str, Any]) -> dict[str, Any]:
        def labelled(value: Any) -> Any:
            if isinstance(value, list):
                return [labelled(item) for item in value]
            if isinstance(value, str) and Path(value).expanduser().is_absolute():
                # Original tool inputs can retain aliases that the recorded argv resolved.
                # Resolve path fields only; filters and other literals retain their meaning.
                value = str(resolve_under(value, [p for _, p in self.roots]))
            return self.redact(value)

        return {
            key: labelled(value) if key in PATH_INPUTS else self.redact(value)
            for key, value in inputs.items()
        }

    def add(self, meta: ResultMeta) -> None:
        if meta.tool == "chainsaw_process_lineage" and not meta.commands:
            raise ValueError(
                "Legacy lineage result lacks its full command history; rerun the lineage pivot"
            )
        invocations = meta.commands or ([meta.argv] if meta.argv else [])
        if not invocations:
            raise ValueError(f"{meta.handle} has no recorded Chainsaw invocation")
        for original in invocations:
            if len(original) < 2 or not self.settings.binary:
                raise ValueError("No configured Chainsaw binary or invalid recorded command")
            # Only result-producing native commands are replayable.
            native = next((a for a in original[1:] if not a.startswith("--")), "")
            if native not in {"hunt", "search", "dump", "analyse"}:
                raise ValueError("This result does not contain a replayable investigation command")
            number = len(self.commands) + 1
            suffix = (
                "jsonl"
                if "--jsonl" in original
                else "json"
                if "--json" in original
                else meta.format
            )
            output = f'"${{OUTPUT_DIR}}/{number:03d}-{meta.handle}.{suffix}"'
            stderr = f'"$OUTPUT_DIR/{number:03d}-{meta.handle}.stderr.txt"'
            rendered = ['"${CHAINSAW_BIN}"']
            positionals = False
            has_output = False
            index = 1
            while index < len(original):
                arg = original[index]
                if positionals:
                    rendered.append(self._path(arg))
                elif arg == "--":
                    positionals = True
                    rendered.append("--")
                elif arg in PATH_OPTIONS or arg == "--output":
                    index += 1
                    if index >= len(original):
                        raise ValueError("Incomplete recorded path option")
                    rendered.append(arg)
                    if arg == "--output":
                        rendered.append(output)
                        has_output = True
                    else:
                        rendered.append(self._path(original[index], snapshot=arg == "--mapping"))
                else:
                    if self.redact_paths and self.redact(arg) != arg:
                        raise ValueError(
                            "A literal command argument contains server paths; sanitise the "
                            "argument before requesting a redacted export"
                        )
                    rendered.append(shlex.quote(arg))
                index += 1
            command = " ".join(rendered)
            # Always retain stdout and stderr, even for commands writing an output file.
            stdout = (
                f'"$OUTPUT_DIR/{number:03d}-{meta.handle}.stdout.txt"' if has_output else output
            )
            # Like live runs, replayed commands never read the caller's stdin.
            command += f" < /dev/null > {stdout} 2> {stderr}"
            self.commands.append(
                {
                    "kind": "command",
                    "handle": meta.handle,
                    "tool": meta.tool,
                    "created_iso": meta.public()["created_iso"],
                    "inputs": (
                        self._redacted_inputs(meta.inputs) if self.redact_paths else meta.inputs
                    ),
                    **(
                        # Remove shell quoting, retaining literal variable placeholders.
                        {"rebased_argv": [shlex.split(arg)[0] for arg in rendered]}
                        if self.redact_paths
                        else {"recorded_argv": original}
                    ),
                    "command": command,
                    "output": output,
                }
            )

    def manifest_inputs(self, hash_inputs: bool) -> Iterator[dict[str, Any]]:
        # Overlapping dependencies (a directory and files or directories inside it) list
        # each replay expression once. Overlapping roots can reach one file through several
        # independently relocatable expressions; each is checked, but hashed only once.
        digests: dict[Path, dict[str, Any]] = {}
        seen: set[str] = set()
        for path, expression in self.dependencies.items():
            files = sorted(path.rglob("*")) if path.is_dir() else [path]
            for file in files:
                if not file.is_file():
                    continue
                portable = expression
                if file != path:
                    portable += "/" + shlex.quote(str(file.relative_to(path)))
                if portable in seen:
                    continue
                seen.add(portable)
                checked = resolve_under(str(file), [p for _, p in self.roots])
                if checked not in digests:
                    if len(digests) >= 100_000:
                        raise ValueError(
                            "More than 100000 input files; export a narrower investigation"
                        )
                    if file in self.snapshots:
                        data = self.snapshots[file][1]
                        digests[checked] = {
                            "sha256": hashlib.sha256(data).hexdigest(),
                            "bytes": len(data),
                        }
                    elif hash_inputs:
                        digests[checked] = fingerprint(checked)
                    else:
                        digests[checked] = {"bytes": checked.stat().st_size, "sha256": None}
                row: dict[str, Any] = {
                    "kind": "input",
                    "path": self.redact(str(file)) if self.redact_paths else str(file),
                    "shell_path": portable,
                }
                row.update(digests[checked])
                yield row

    def script(self, checks: list[str], binary_digest: str) -> str:
        lines = [
            "#!/bin/sh",
            "set -eu",
            "umask 077",
            "export NO_COLOR=1",
            "# " + NOTE,
            "# " + DERIVED_NOTE,
            "# Requires Chainsaw and GNU-style base64 -d and sha256sum (not stock macOS).",
            "# Override roots to relocate inputs.",
            ': "${CHAINSAW_BIN:=chainsaw}"',
            "# A fresh directory prevents replay from overwriting earlier output or evidence.",
            'OUTPUT_DIR=$(mktemp -d "${OUTPUT_PARENT:-${TMPDIR:-/tmp}}/chainsaw-replay.XXXXXXXX")',
            'mkdir "$OUTPUT_DIR/assets"',
        ]
        for variable, root in self.used.items():
            if self.redact_paths:
                lines.append(f': "${{{variable}:?Set {variable} to the relocated input root}}"')
                continue
            # No expansion of a server path as shell syntax, including literal $ or backticks.
            lines.append(
                f'if [ -z "${{{variable}:-}}" ]; then {variable}={shlex.quote(str(root))}; fi'
            )
        expected = shlex.quote(binary_digest + "  -")
        lines += [
            'CHAINSAW_BIN=$(command -v "$CHAINSAW_BIN") || {',
            '  printf "chainsaw-replay: Chainsaw binary not found\\n" >&2',
            "  exit 1",
            "}",
            f'if [ "$(sha256sum < "$CHAINSAW_BIN")" != {expected} ]; then',
            '  printf "chainsaw-replay: Chainsaw binary digest mismatch: %s\\n" \\',
            '    "$CHAINSAW_BIN" >&2',
            "  exit 1",
            "fi",
        ]
        for name, data in self.snapshots.values():
            encoded = base64.b64encode(data).decode("ascii")
            lines.append(
                f'printf %s {shlex.quote(encoded)} | base64 -d > "$OUTPUT_DIR/assets/{name}"'
            )
        lines.extend(checks)
        for entry in self.commands:
            lines.append(f"# {entry['handle']} ({entry['tool']})")
            lines.append(entry["command"])
        lines.append('printf "Replay output: %s\\n" "$OUTPUT_DIR"')
        return "\n".join(lines) + "\n"


def checksum_check(row: dict[str, Any]) -> str:
    # stdin hashing avoids sha256sum filename escaping (newlines and backslashes).
    path = row["shell_path"]
    return (
        f'if [ "$(sha256sum < {path})" != {shlex.quote(row["sha256"] + "  -")} ]; then '
        f'printf "chainsaw-replay: input checksum mismatch: %s\\n" {path} >&2; exit 1; fi'
    )


def json_line(data: dict[str, Any]) -> str:
    return json.dumps(data, ensure_ascii=True) + "\n"
