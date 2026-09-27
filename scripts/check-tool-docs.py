"""Compare generated tool docs without overwriting the checked-in source."""

import difflib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
expected = (ROOT / "docs/tools.md").read_text()
actual = subprocess.check_output(
    [sys.executable, str(ROOT / "scripts/gen-tool-docs.py")], cwd=ROOT, text=True
)
if actual != expected:
    sys.stderr.writelines(
        difflib.unified_diff(
            expected.splitlines(keepends=True),
            actual.splitlines(keepends=True),
            fromfile="docs/tools.md",
            tofile="generated tools.md",
        )
    )
    raise SystemExit(
        "Tool docs drift: regenerate with uv run --locked python scripts/gen-tool-docs.py"
    )
print("Generated tool docs match.")
