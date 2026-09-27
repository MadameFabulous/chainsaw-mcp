import json
import stat
from pathlib import Path

import pytest

from chainsaw_mcp.results import ResultError, ResultStore, get_path, summarize

ROWS = [
    {
        "name": "Rule A",
        "level": "high",
        "source": "sigma",
        "timestamp": "2021-12-07T17:33:01+00:00",
        "tags": ["attack.t1003"],
        "document": {
            "path": "/x/a.evtx",
            "data": {
                "Event": {"System": {"Computer": "DC01", "Channel": "Security", "EventID": 4624}}
            },
        },
    },
    {
        "name": "Rule B",
        "level": "critical",
        "source": "chainsaw",
        "timestamp": "2021-12-07T18:00:00+00:00",
        "document": {
            "path": "/x/b.evtx",
            "data": {
                "Event": {"System": {"Computer": "WS02", "Channel": "System", "EventID": 104}}
            },
        },
    },
]


def _store(tmp_path: Path) -> tuple[ResultStore, str]:
    store = ResultStore(tmp_path / "results")
    handle, path = store.reserve(".jsonl")
    path.write_text("".join(json.dumps(r) + "\n" for r in ROWS))
    store.commit(handle, tool="chainsaw_hunt", argv=["chainsaw"], inputs={"paths": ["x"]})
    return store, handle


def test_commit_counts_rows_and_pages(tmp_path: Path):
    store, handle = _store(tmp_path)
    assert store.meta(handle).count == 2
    page = store.page(handle, offset=1, limit=5, fields=["name", "level"])
    assert page["total"] == 2
    assert page["rows"] == [{"name": "Rule B", "level": "critical"}]
    assert page["next_offset"] is None


def test_handles_are_validated(tmp_path: Path):
    store, _ = _store(tmp_path)
    with pytest.raises(ResultError):
        store.meta("../../etc/passwd")
    with pytest.raises(ResultError):
        store.meta("res_0000000000000000")


def test_list_and_delete(tmp_path: Path):
    store, handle = _store(tmp_path)
    assert [r["handle"] for r in store.list()] == [handle]
    assert store.delete(handle) is True
    assert store.list() == []
    assert store.delete(handle) is False


def test_expire_removes_old_results(tmp_path: Path):
    store, handle = _store(tmp_path)
    store.ttl = 0
    import time

    time.sleep(0.01)
    assert store.expire() >= 1
    assert store.list() == []


def test_get_path_and_summarize():
    assert get_path(ROWS[0], "document.data.Event.System.Computer") == "DC01"
    assert get_path(ROWS[0], "document.missing.x") is None
    summary = summarize(iter(ROWS))
    assert summary["total"] == 2
    assert summary["shape"] == "detections"
    assert {v["value"] for v in summary["by_level"]} == {"high", "critical"}
    assert summary["time_range"]["first"].startswith("2021-12-07T17:33")


def test_private_allocation_and_existing_tree(tmp_path):
    root = tmp_path / "results"
    root.mkdir(mode=0o755)
    old = root / "old.txt"
    old.write_text("secret")
    store = ResultStore(root)
    handle, path = store.reserve()
    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert stat.S_IMODE(old.stat().st_mode) == 0o600
    assert path.exists()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    path.write_text("{}\n")
    store.commit(handle, tool="test", argv=[], inputs={})
    assert stat.S_IMODE(store.meta_path(handle).stat().st_mode) == 0o600


@pytest.mark.parametrize(
    "read",
    [
        lambda s, h: s.meta(h),
        lambda s, h: list(s.rows(h)),
        lambda s, h: s.page(h),
        lambda s, h: s.text(h),
    ],
)
def test_expiry_is_enforced_on_every_read(tmp_path, read):
    store, handle = _store(tmp_path)
    store.ttl = 0
    with pytest.raises(ResultError, match="expired"):
        read(store, handle)


def test_atomic_publication_and_failure_cleanup(tmp_path, monkeypatch):
    store = ResultStore(tmp_path / "results")
    handle, path = store.reserve()
    path.write_text("{}\n")
    assert not store.data_path(handle).exists()
    assert store.list() == []
    import os

    replace = os.replace

    def fail_metadata(src, dst):
        if str(dst).endswith(".meta.json"):
            raise OSError("publication failed")
        replace(src, dst)

    monkeypatch.setattr(os, "replace", fail_metadata)
    with pytest.raises(OSError, match="publication failed"):
        store.commit(handle, tool="test", argv=[], inputs={})
    assert store.list() == []
    assert not path.exists()
    assert not store.data_path(handle).exists()


def test_orphan_cleanup_preserves_active_writer_across_stores(tmp_path):
    import os

    store = ResultStore(tmp_path / "results", ttl_seconds=1)
    handle, active = store.reserve()
    active.write_text("{}\n")
    os.utime(active, (1, 1))
    orphan = store.directory / "res_0000000000000000.jsonl"
    orphan.write_text("orphan")
    os.utime(orphan, (1, 1))
    cleaner = ResultStore(store.directory, ttl_seconds=1)
    cleaner.expire()
    assert active.exists()
    assert not orphan.exists()
    store.commit(handle, tool="test", argv=[], inputs={})
    assert cleaner.page(handle)["returned"] == 1


def test_text_read_is_byte_bounded_with_explicit_truncation(tmp_path, monkeypatch):
    store = ResultStore(tmp_path / "results")
    handle, path = store.reserve(".txt")
    path.write_bytes("ééé".encode())
    store.commit(handle, tool="test", argv=[], inputs={}, fmt="txt")
    original_open = Path.open
    reads = []

    class BoundedReader:
        def __init__(self, fh):
            self.fh = fh

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.fh.close()

        def read(self, size=-1):
            assert 0 <= size <= 5
            reads.append(size)
            return self.fh.read(size)

    def bounded_open(path, *args, **kwargs):
        fh = original_open(path, *args, **kwargs)
        return BoundedReader(fh) if args and args[0] == "rb" else fh

    monkeypatch.setattr(Path, "open", bounded_open)
    result = store.text_result(handle, max_bytes=4)
    assert reads == [5]
    assert result == {"content": "éé", "bytes": 6, "returned_bytes": 4, "truncated": True}
    assert store.text(handle, max_bytes=4) == "éé"


def test_store_owns_filtered_views_and_exports(tmp_path):
    store, handle = _store(tmp_path)
    assert store.page(handle, fields=["rule"], where={"computer": "dc01"})["rows"] == [
        {"rule": "Rule A"}
    ]
    assert store.summary(handle, group_by=["computer"])["total"] == 2
    assert store.fields(handle)["sampled"] == 2
    assert store.export(handle, format="jsonl", max_rows=1)["truncated"] is True
    handle, path = store.reserve(".txt")
    path.write_text("abcdef")
    store.commit(handle, tool="test", argv=[], inputs={}, fmt="txt")
    exported = store.export(handle, max_bytes=512)
    assert exported["content"] == "abcdef"
    assert exported["next_byte_offset"] is None
    assert exported["returned_bytes"] == 6
