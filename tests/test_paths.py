from pathlib import Path

import pytest

from chainsaw_mcp.paths import PathError, display_path, iter_artefacts, resolve_under


def test_relative_path_resolves_inside_root(workspace: Path):
    root = workspace / "evidence"
    assert resolve_under("host1/Security.evtx", [root]) == root / "host1" / "Security.evtx"
    assert resolve_under(".", [root]) == root


def test_absolute_inside_root_is_allowed(workspace: Path):
    root = workspace / "evidence"
    target = root / "host1"
    assert resolve_under(str(target), [root]) == target


@pytest.mark.parametrize("raw", ["../outside/secret.evtx", "/etc/passwd", "host1/../../outside"])
def test_escapes_are_rejected(workspace: Path, raw: str):
    with pytest.raises(PathError):
        resolve_under(raw, [workspace / "evidence"])


def test_symlink_escape_is_rejected(workspace: Path):
    root = workspace / "evidence"
    (root / "link").symlink_to(workspace / "outside")
    with pytest.raises(PathError):
        resolve_under("link/secret.evtx", [root])


def test_missing_path_is_rejected(workspace: Path):
    with pytest.raises(PathError):
        resolve_under("host1/missing.evtx", [workspace / "evidence"])


def test_iter_artefacts_filters_and_limits(workspace: Path):
    files = iter_artefacts(workspace / "evidence")
    names = {f["relative"] for f in files}
    assert "host1/Security.evtx" in names
    assert "host1/notes.txt" not in names
    assert iter_artefacts(workspace / "evidence", pattern="nomatch") == []
    assert len(iter_artefacts(workspace / "evidence", limit=1)) == 1


def test_display_path_is_relative_to_root(workspace: Path):
    root = workspace / "evidence"
    assert display_path(root / "host1" / "Security.evtx", [root]) == "evidence/host1/Security.evtx"
