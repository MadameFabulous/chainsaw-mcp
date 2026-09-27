"""Environment-driven settings. Every path is resolved once at startup."""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path

DEFAULT_MAPPING = "sigma-event-logs-all.yml"
DEFAULT_TIMEOUT = 600
DEFAULT_MAX_PAGE = 500
DEFAULT_PREVIEW = 20
DEFAULT_EVIDENCE_DIRS = ("evidence",)


def _int(raw: str, default: int, name: str, *, minimum: int = 1) -> int:
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from exc
    if value < minimum:
        raise ValueError(f"{name} must be >= {minimum}")
    return value


def _resolve(home: Path, raw: str) -> Path:
    path = Path(os.path.expanduser(raw))
    if not path.is_absolute():
        path = home / path
    return path.resolve()


@dataclass(frozen=True)
class Settings:
    home: Path
    binary: Path | None
    rules_dir: Path
    sigma_dir: Path
    mappings_dir: Path
    custom_rules_dir: Path
    evidence_roots: tuple[Path, ...]
    output_dir: Path
    timeout: int = DEFAULT_TIMEOUT
    threads: int | None = None
    max_page: int = DEFAULT_MAX_PAGE
    preview: int = DEFAULT_PREVIEW
    extra: dict[str, str] = field(default_factory=dict)
    jev_enabled: bool = False
    jev_api_key: str = field(default="", repr=False)
    jev_bws_secret_id: str = ""
    jev_model: str = "jev-latest"
    jev_timeout: int = 30
    bws_binary: str = "bws"
    bws_access_token: str = field(default="", repr=False)
    bws_token_file: str = "~/.config/bitwarden-sm/token"

    @property
    def vendor_dir(self) -> Path:
        return self.home / "vendor" / "chainsaw"

    def describe(self) -> dict[str, object]:
        """Effective configuration, safe to show to clients."""
        return {
            "home": str(self.home),
            "binary": str(self.binary) if self.binary else None,
            "binary_present": bool(self.binary and self.binary.is_file()),
            "rules_dir": str(self.rules_dir),
            "sigma_dir": str(self.sigma_dir),
            "mappings_dir": str(self.mappings_dir),
            "custom_rules_dir": str(self.custom_rules_dir),
            "evidence_roots": [str(p) for p in self.evidence_roots],
            "output_dir": str(self.output_dir),
            "timeout_seconds": self.timeout,
            "threads": self.threads,
            "max_page": self.max_page,
            "default_preview": self.preview,
            "jev": {
                "enabled": self.jev_enabled,
                "credentials_configured": bool(self.jev_api_key or self.jev_bws_secret_id),
                "credential_source": (
                    "env" if self.jev_api_key else "bws" if self.jev_bws_secret_id else None
                ),
                "model": self.jev_model,
                "timeout_seconds": self.jev_timeout,
                "endpoint": "https://api.typesafe.ai/v1/systemone",
            },
        }


def load_settings(env: dict[str, str] | None = None) -> Settings:
    e = os.environ if env is None else env

    def get(name: str, default: str = "") -> str:
        return e.get(name, default) or default

    home = Path(os.path.expanduser(get("CHAINSAW_HOME", os.getcwd()))).resolve()
    vendor = home / "vendor" / "chainsaw"

    binary: Path | None
    raw_bin = get("CHAINSAW_BIN")
    if raw_bin:
        binary = _resolve(home, raw_bin)
    elif (vendor / "chainsaw").is_file():
        binary = vendor / "chainsaw"
    else:
        found = shutil.which("chainsaw")
        binary = Path(found).resolve() if found else None

    roots_raw = get("CHAINSAW_EVIDENCE_ROOTS")
    if roots_raw:
        roots = tuple(_resolve(home, p) for p in roots_raw.split(":") if p.strip())
    else:
        roots = tuple(
            (home / name).resolve() for name in DEFAULT_EVIDENCE_DIRS if (home / name).is_dir()
        )

    threads_raw = get("CHAINSAW_THREADS")
    threads = _int(threads_raw, 0, "CHAINSAW_THREADS") if threads_raw else None
    jev_enabled = get("CHAINSAW_JEV_ENABLED", "false").lower()
    if jev_enabled not in ("true", "false"):
        raise ValueError("CHAINSAW_JEV_ENABLED must be true or false")

    return Settings(
        home=home,
        binary=binary,
        rules_dir=_resolve(home, get("CHAINSAW_RULES_DIR", str(vendor / "rules"))),
        sigma_dir=_resolve(home, get("CHAINSAW_SIGMA_DIR", str(vendor / "sigma"))),
        mappings_dir=_resolve(home, get("CHAINSAW_MAPPINGS_DIR", str(vendor / "mappings"))),
        custom_rules_dir=_resolve(home, get("CHAINSAW_CUSTOM_RULES_DIR", "custom-rules")),
        evidence_roots=roots,
        output_dir=_resolve(home, get("CHAINSAW_OUTPUT_DIR", ".chainsaw-mcp/results")),
        timeout=_int(get("CHAINSAW_TIMEOUT"), DEFAULT_TIMEOUT, "CHAINSAW_TIMEOUT"),
        threads=threads,
        max_page=_int(get("CHAINSAW_MAX_PAGE"), DEFAULT_MAX_PAGE, "CHAINSAW_MAX_PAGE"),
        preview=_int(get("CHAINSAW_PREVIEW"), DEFAULT_PREVIEW, "CHAINSAW_PREVIEW"),
        jev_enabled=jev_enabled == "true",
        jev_api_key=get("TYPESAFE_API_KEY").strip(),
        jev_bws_secret_id=get("CHAINSAW_JEV_BWS_SECRET_ID").strip(),
        jev_model=get("JEV_MODEL", "jev-latest"),
        jev_timeout=_int(get("CHAINSAW_JEV_TIMEOUT"), 30, "CHAINSAW_JEV_TIMEOUT"),
        bws_binary=get("BWS_BINARY", "bws"),
        bws_access_token=get("BWS_ACCESS_TOKEN").strip(),
        bws_token_file=get("BWS_TOKEN_FILE", "~/.config/bitwarden-sm/token"),
    )
