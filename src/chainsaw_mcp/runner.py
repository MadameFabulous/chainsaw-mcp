"""Run the chainsaw binary with argument lists only; never through a shell."""

from __future__ import annotations

import os
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

# Any CSI escape sequence (colours, cursor movement), not only the SGR "...m" form.
_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
# Chainsaw needs nothing else from the server's environment. Credentials such as
# TYPESAFE_API_KEY or BWS_ACCESS_TOKEN must never reach the subprocess.
_ENV_PASSTHROUGH = (
    "PATH",
    "HOME",
    "TMPDIR",
    "TMP",
    "TEMP",
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    "SYSTEMROOT",
)


def environment() -> dict[str, str]:
    """Minimal allow-listed environment for the chainsaw subprocess."""
    env = {name: os.environ[name] for name in _ENV_PASSTHROUGH if name in os.environ}
    env["NO_COLOR"] = "1"
    return env


class ChainsawError(RuntimeError):
    """Chainsaw exited non-zero, timed out, or is not installed."""


@dataclass(frozen=True)
class RunResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str
    duration_seconds: float

    @property
    def messages(self) -> list[str]:
        """Chainsaw's informational lines with colour codes removed."""
        return [
            _ANSI.sub("", line).strip()
            for line in self.stderr.splitlines()
            if _ANSI.sub("", line).strip()
        ]


class Runner:
    def __init__(self, binary: Path | None, *, timeout: int, threads: int | None = None) -> None:
        self.binary = binary
        self.timeout = timeout
        self.threads = threads

    def require(self) -> Path:
        if self.binary is None or not self.binary.is_file():
            raise ChainsawError(
                "chainsaw binary not found; run `chainsaw-mcp-bootstrap` or set CHAINSAW_BIN"
            )
        return self.binary

    def run(self, args: list[str], *, cwd: Path | None = None) -> RunResult:
        """Run one chainsaw command.

        Chainsaw's ``-q`` flag is deliberately never passed: it also silences the
        ``[!] failed to load file`` and ``[x] Failed to hunt through file`` lines that tell
        an analyst which evidence was skipped, so every run keeps its full message stream.
        """
        binary = self.require()
        argv = [str(binary), "--no-banner"]
        if self.threads:
            argv.append(f"--num-threads={self.threads}")
        args = list(args)
        argv.extend(args)
        start = time.monotonic()
        try:
            proc = subprocess.run(  # noqa: S603 - argv list, no shell, binary is configured
                argv,
                capture_output=True,
                text=True,
                errors="replace",
                timeout=self.timeout,
                cwd=str(cwd) if cwd else None,
                stdin=subprocess.DEVNULL,
                env=environment(),
            )
        except subprocess.TimeoutExpired as exc:
            raise ChainsawError(
                f"chainsaw {args[0]} exceeded the {self.timeout}s timeout; "
                "narrow the paths or time window"
            ) from exc
        result = RunResult(
            argv=argv,
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            duration_seconds=round(time.monotonic() - start, 3),
        )
        if proc.returncode != 0:
            detail = [m for m in result.messages if m.startswith(("[x]", "error", "Error"))]
            if not detail:
                detail = result.messages[-3:] or [proc.stdout.strip()[-500:]]
            raise ChainsawError(f"chainsaw {args[0]} failed: " + " | ".join(detail))
        return result

    def version(self) -> str:
        out = self.run(["--version"]).stdout.strip()
        return out.removeprefix("chainsaw").strip()
