"""Smoke-check wheel contents and entry points independently of the editable install."""

import configparser
import subprocess
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
wheels = list((ROOT / "dist").glob("*.whl"))
sources = list((ROOT / "dist").glob("*.tar.gz"))
if len(wheels) != 1 or len(sources) != 1:
    raise SystemExit("Expected exactly one wheel and one sdist; clean dist/ before rebuilding")
with zipfile.ZipFile(wheels[0]) as wheel, tempfile.TemporaryDirectory() as temp:
    names = wheel.namelist()
    for required in ("bootstrap.py", "cli.py", "server.py", "jev.py", "tools/jev.py"):
        assert f"chainsaw_mcp/{required}" in names, required
    assert not any(n.startswith(("tests/", "vendor/", "evidence/")) for n in names)
    entry_name = next(n for n in names if n.endswith(".dist-info/entry_points.txt"))
    entries = configparser.ConfigParser()
    entries.read_string(wheel.read(entry_name).decode())
    assert entries["console_scripts"]["chainsaw-mcp"] == "chainsaw_mcp.cli:main"
    assert entries["console_scripts"]["chainsaw-mcp-bootstrap"] == "chainsaw_mcp.bootstrap:main"
    wheel.extractall(temp)
    # Insert wheel files ahead of the editable install, with an unrelated working directory.
    code = (
        f"import sys; sys.path.insert(0, {temp!r}); "
        "from chainsaw_mcp.cli import main; main(['--version'])"
    )
    subprocess.run([sys.executable, "-c", code], cwd=temp, check=True)
with tarfile.open(sources[0]) as source:
    names = source.getnames()
    assert any(n.endswith("/pyproject.toml") for n in names)
    assert any(n.endswith("/src/chainsaw_mcp/server.py") for n in names)
print("Wheel, sdist, and packaged entry points verified.")
