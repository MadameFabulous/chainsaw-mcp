import os

import pytest

from chainsaw_mcp.config import Settings
from chainsaw_mcp.rules import RuleCatalog, RuleError, mapping_summary
from tests.conftest import MINIMAL_RULE


def test_index_and_search(settings: Settings):
    catalog = RuleCatalog(settings)
    stats = catalog.stats()
    assert stats["chainsaw"]["count"] == 1
    assert stats["sigma"]["count"] == 1
    hits = catalog.search("mimikatz", kinds=["sigma"], level="critical")
    assert hits["total"] == 1
    assert hits["rules"][0]["tags"] == ["attack.credential-access", "attack.t1003.001"]
    assert catalog.search("nothing-matches")["total"] == 0
    assert catalog.search("", tag="t1003")["total"] == 1


def test_read_rule_and_directory(settings: Settings):
    catalog = RuleCatalog(settings)
    data = catalog.read("chainsaw", "evtx/test/test_rule.yml")
    assert data["summary"]["title"] == "Test Rule"
    assert "filter:" in data["yaml"]
    listing = catalog.read("chainsaw", "evtx")
    assert listing["directory"] is True
    assert "evtx/test" in listing["children"]


@pytest.mark.parametrize("change", ["edit", "add", "delete"])
def test_index_detects_changes_with_preserved_timestamps(settings: Settings, change):
    catalog = RuleCatalog(settings)
    root = settings.rules_dir
    path = root / "evtx/test/test_rule.yml"
    directories = [root, *[p for p in root.rglob("*") if p.is_dir()]]
    stamps = {p: p.stat() for p in [*directories, path]}
    assert catalog.search("Test Rule", kinds=["chainsaw"])["total"] == 1
    if change == "edit":
        path.write_text(MINIMAL_RULE.replace("Test Rule", "Next Rule"))
        os.utime(path, ns=(stamps[path].st_atime_ns, stamps[path].st_mtime_ns))
    elif change == "add":
        (path.parent / "added.yaml").write_text(MINIMAL_RULE.replace("Test Rule", "Next Rule"))
    else:
        path.unlink()
    for directory in directories:
        stamp = stamps[directory]
        os.utime(directory, ns=(stamp.st_atime_ns, stamp.st_mtime_ns))
    expected_count = {"edit": 1, "add": 2, "delete": 0}[change]
    assert catalog.stats()["chainsaw"]["count"] == expected_count
    assert catalog.search("Next Rule", kinds=["chainsaw"])["total"] == (change != "delete")


@pytest.mark.parametrize("bad", ["../evtx", "/etc/passwd", "evtx/../../x.yml", "missing.yml"])
def test_resolve_rejects_escapes(settings: Settings, bad: str):
    with pytest.raises(RuleError):
        RuleCatalog(settings).resolve("chainsaw", bad)


def test_custom_rule_lifecycle(settings: Settings):
    catalog = RuleCatalog(settings)
    path = catalog.save_custom_rule("my_rule", MINIMAL_RULE)
    assert path.name == "my_rule.yml"
    assert path.parent == settings.custom_rules_dir
    with pytest.raises(RuleError):
        catalog.save_custom_rule("my_rule", MINIMAL_RULE)
    catalog.save_custom_rule("my_rule", MINIMAL_RULE, overwrite=True)
    assert catalog.stats()["custom"]["count"] == 1
    assert catalog.rule_dirs_for_hunt(["custom"]) == [settings.custom_rules_dir]
    assert catalog.delete_custom_rule("my_rule") is True
    assert catalog.delete_custom_rule("my_rule") is False


def test_failed_atomic_overwrite_preserves_rule_and_index(settings, monkeypatch):
    catalog = RuleCatalog(settings)
    target = catalog.save_custom_rule("my_rule", MINIMAL_RULE)
    catalog.index("custom")

    def fail_replace(source, destination):
        assert target.read_text() == MINIMAL_RULE
        raise OSError("simulated publish failure")

    monkeypatch.setattr(os, "replace", fail_replace)
    with pytest.raises(OSError, match="publish failure"):
        catalog.save_custom_rule(
            "my_rule", MINIMAL_RULE.replace("Test Rule", "Next Rule"), overwrite=True
        )
    assert target.read_text() == MINIMAL_RULE
    assert catalog.index("custom")[0].title == "Test Rule"
    assert list(target.parent.iterdir()) == [target]


@pytest.mark.parametrize(
    "name,content",
    [
        ("../escape", MINIMAL_RULE),
        ("bad name!", MINIMAL_RULE),
        ("ok", "title: only\n"),
        ("ok", ": not yaml ["),
    ],
)
def test_custom_rule_validation(settings: Settings, name: str, content: str):
    with pytest.raises(RuleError):
        RuleCatalog(settings).save_custom_rule(name, content)


def test_sigma_dirs_and_mapping(settings: Settings):
    catalog = RuleCatalog(settings)
    assert catalog.sigma_dirs(None) == [settings.sigma_dir / "rules"]
    assert catalog.sigma_dirs(["rules/windows"]) == [settings.sigma_dir / "rules" / "windows"]
    with pytest.raises(RuleError):
        catalog.sigma_dirs(["../outside"])
    with pytest.raises(RuleError):
        catalog.sigma_dirs(["rules-dfir"])  # not installed in the fixture
    assert catalog.mapping(None).name == "sigma-event-logs-all.yml"
    with pytest.raises(RuleError):
        catalog.mapping("../x.yml")
    summary = mapping_summary(catalog.mapping(None))
    assert summary["groups"][0]["name"] == "Sigma"
