"""Tests for PolicyLoader: pack discovery, policy loading, rule filtering, annotation parsing."""

from __future__ import annotations

from pathlib import Path

import pytest

from vectimus.engine.config import VectimusConfig
from vectimus.engine.loader import PolicyLoader, parse_rules_from_cedar

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_CEDAR = """\
@id("test-001")
@description("Block dangerous command")
@incident("test-incident-2025")
@suggested_alternative("Use a safer command")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    context.command like "*rm -rf /*"
};

@id("test-002")
@description("Block secret reads")
@controls("SOC2-CC6.1")
forbid (
    principal,
    action == Vectimus::Action::"file_read",
    resource
) when {
    context.file_path like "*.env"
};
"""

SECOND_CEDAR = """\
@id("extra-001")
@description("Block npm publish")
forbid (
    principal,
    action == Vectimus::Action::"package_operation",
    resource
) when {
    context.command like "*npm publish*"
};
"""


@pytest.fixture()
def pack_dir(tmp_path: Path) -> Path:
    """Create a temporary policy directory with two packs."""
    # base pack
    base_dir = tmp_path / "policies" / "base"
    base_dir.mkdir(parents=True)
    (base_dir / "pack.toml").write_text(
        '[pack]\nname = "base"\nversion = "0.1.0"\n'
        'description = "Base rules"\nauthor = "Test"\nlicense = "Apache-2.0"\n'
    )
    (base_dir / "test_rules.cedar").write_text(SAMPLE_CEDAR)

    # extra pack
    extra_dir = tmp_path / "policies" / "extra"
    extra_dir.mkdir(parents=True)
    (extra_dir / "pack.toml").write_text(
        '[pack]\nname = "extra"\nversion = "0.2.0"\ndescription = "Extra rules"\nauthor = "Test"\n'
    )
    (extra_dir / "extra_rules.cedar").write_text(SECOND_CEDAR)

    return tmp_path / "policies"


@pytest.fixture()
def config_path(tmp_path: Path) -> str:
    """Return path to a temporary config file."""
    return str(tmp_path / "config.toml")


# ---------------------------------------------------------------------------
# Annotation parsing
# ---------------------------------------------------------------------------


class TestParseRules:
    """Test Cedar annotation parsing."""

    def test_parses_two_rules(self) -> None:
        rules = parse_rules_from_cedar(SAMPLE_CEDAR)
        assert len(rules) == 2

    def test_extracts_id(self) -> None:
        rules = parse_rules_from_cedar(SAMPLE_CEDAR)
        assert rules[0].rule_id == "test-001"
        assert rules[1].rule_id == "test-002"

    def test_extracts_description(self) -> None:
        rules = parse_rules_from_cedar(SAMPLE_CEDAR)
        assert rules[0].description == "Block dangerous command"

    def test_extracts_incident(self) -> None:
        rules = parse_rules_from_cedar(SAMPLE_CEDAR)
        assert rules[0].incident == "test-incident-2025"

    def test_extracts_suggested_alternative(self) -> None:
        rules = parse_rules_from_cedar(SAMPLE_CEDAR)
        assert rules[0].suggested_alternative == "Use a safer command"

    def test_extracts_controls(self) -> None:
        rules = parse_rules_from_cedar(SAMPLE_CEDAR)
        assert rules[1].controls == "SOC2-CC6.1"

    def test_cedar_text_preserved(self) -> None:
        rules = parse_rules_from_cedar(SAMPLE_CEDAR)
        assert "forbid" in rules[0].cedar_text
        assert '@id("test-001")' in rules[0].cedar_text

    def test_pack_name_set(self) -> None:
        rules = parse_rules_from_cedar(SAMPLE_CEDAR, pack_name="base")
        assert rules[0].pack_name == "base"


# ---------------------------------------------------------------------------
# Pack discovery
# ---------------------------------------------------------------------------


class TestDiscoverPacks:
    """Test pack discovery from directory structure."""

    def test_finds_two_packs(self, pack_dir: Path, config_path: str) -> None:
        loader = PolicyLoader(
            policy_dirs=[str(pack_dir)],
            config_path=config_path,
        )
        packs = loader.discover_packs()
        names = {p.name for p in packs}
        assert "base" in names
        assert "extra" in names

    def test_pack_metadata(self, pack_dir: Path, config_path: str) -> None:
        loader = PolicyLoader(
            policy_dirs=[str(pack_dir)],
            config_path=config_path,
        )
        packs = loader.discover_packs()
        base = next(p for p in packs if p.name == "base")
        assert base.version == "0.1.0"
        assert base.description == "Base rules"

    def test_pack_rule_count(self, pack_dir: Path, config_path: str) -> None:
        loader = PolicyLoader(
            policy_dirs=[str(pack_dir)],
            config_path=config_path,
        )
        packs = loader.discover_packs()
        base = next(p for p in packs if p.name == "base")
        assert base.rule_count == 2
        extra = next(p for p in packs if p.name == "extra")
        assert extra.rule_count == 1

    def test_packs_enabled_by_default(self, pack_dir: Path, config_path: str) -> None:
        loader = PolicyLoader(
            policy_dirs=[str(pack_dir)],
            config_path=config_path,
        )
        packs = loader.discover_packs()
        assert all(p.enabled for p in packs)

    def test_disabled_pack_reflected(self, pack_dir: Path, config_path: str) -> None:
        cfg = VectimusConfig(config_path)
        cfg.set_pack_enabled("extra", False)

        loader = PolicyLoader(
            policy_dirs=[str(pack_dir)],
            config_path=config_path,
        )
        packs = loader.discover_packs()
        extra = next(p for p in packs if p.name == "extra")
        assert extra.enabled is False

    def test_empty_dir_returns_no_packs(self, tmp_path: Path, config_path: str) -> None:
        empty = tmp_path / "empty"
        empty.mkdir()
        loader = PolicyLoader(
            policy_dirs=[str(empty)],
            config_path=config_path,
        )
        assert loader.discover_packs() == []


# ---------------------------------------------------------------------------
# Policy loading and rule filtering
# ---------------------------------------------------------------------------


class TestLoadActivePolicies:
    """Test policy loading with pack/rule filtering."""

    def test_loads_all_rules(self, pack_dir: Path, config_path: str) -> None:
        loader = PolicyLoader(
            policy_dirs=[str(pack_dir)],
            config_path=config_path,
        )
        text = loader.load_active_policies()
        assert "test-001" in text
        assert "test-002" in text
        assert "extra-001" in text

    def test_disabled_pack_excluded(self, pack_dir: Path, config_path: str) -> None:
        cfg = VectimusConfig(config_path)
        cfg.set_pack_enabled("extra", False)

        loader = PolicyLoader(
            policy_dirs=[str(pack_dir)],
            config_path=config_path,
        )
        text = loader.load_active_policies()
        assert "test-001" in text
        assert "extra-001" not in text

    def test_disabled_rule_excluded(self, pack_dir: Path, config_path: str) -> None:
        cfg = VectimusConfig(config_path)
        cfg.disable_rule("test-002")

        loader = PolicyLoader(
            policy_dirs=[str(pack_dir)],
            config_path=config_path,
        )
        text = loader.load_active_policies()
        assert "test-001" in text
        assert "test-002" not in text

    def test_list_rules_shows_disabled_status(self, pack_dir: Path, config_path: str) -> None:
        cfg = VectimusConfig(config_path)
        cfg.disable_rule("test-002")

        loader = PolicyLoader(
            policy_dirs=[str(pack_dir)],
            config_path=config_path,
        )
        rules = loader.list_rules()
        r002 = next(r for r in rules if r["rule_id"] == "test-002")
        assert r002["enabled"] is False

    def test_list_packs_output(self, pack_dir: Path, config_path: str) -> None:
        loader = PolicyLoader(
            policy_dirs=[str(pack_dir)],
            config_path=config_path,
        )
        packs = loader.list_packs()
        assert len(packs) == 2
        assert all("name" in p for p in packs)
        assert all("enabled" in p for p in packs)

    def test_get_rule(self, pack_dir: Path, config_path: str) -> None:
        loader = PolicyLoader(
            policy_dirs=[str(pack_dir)],
            config_path=config_path,
        )
        rule = loader.get_rule("test-001")
        assert rule is not None
        assert rule.rule_id == "test-001"
        assert rule.pack_name == "base"

    def test_get_rule_not_found(self, pack_dir: Path, config_path: str) -> None:
        loader = PolicyLoader(
            policy_dirs=[str(pack_dir)],
            config_path=config_path,
        )
        assert loader.get_rule("nonexistent") is None

    def test_get_pack(self, pack_dir: Path, config_path: str) -> None:
        loader = PolicyLoader(
            policy_dirs=[str(pack_dir)],
            config_path=config_path,
        )
        pack = loader.get_pack("base")
        assert pack is not None
        assert pack.name == "base"

    def test_get_pack_not_found(self, pack_dir: Path, config_path: str) -> None:
        loader = PolicyLoader(
            policy_dirs=[str(pack_dir)],
            config_path=config_path,
        )
        assert loader.get_pack("nonexistent") is None


# ---------------------------------------------------------------------------
# Integration with built-in policies
# ---------------------------------------------------------------------------


class TestExternalPacksDir:
    """Test that ~/.vectimus/packs/ is scanned as an additional directory."""

    def test_external_pack_discovered(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A pack dropped into ~/.vectimus/packs/ is found by the default loader."""
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        monkeypatch.setenv("HOME", str(fake_home))
        # Also patch Path.home() directly for platforms that don't use $HOME.
        monkeypatch.setattr(Path, "home", staticmethod(lambda: fake_home))

        ext_dir = fake_home / ".vectimus" / "packs" / "custom"
        ext_dir.mkdir(parents=True)
        (ext_dir / "pack.toml").write_text(
            '[pack]\nname = "custom"\nversion = "1.0.0"\ndescription = "External pack"\n'
        )
        (ext_dir / "rules.cedar").write_text(SECOND_CEDAR)

        config_path = str(tmp_path / "config.toml")
        loader = PolicyLoader(config_path=config_path)
        packs = loader.discover_packs()
        names = [p.name for p in packs]
        assert "custom" in names
        assert len(packs) >= 2  # custom + at least one built-in

    def test_missing_external_dir_is_harmless(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """If ~/.vectimus/packs/ does not exist, the loader still works."""
        fake_home = tmp_path / "home"
        fake_home.mkdir()
        monkeypatch.setenv("HOME", str(fake_home))
        monkeypatch.setattr(Path, "home", staticmethod(lambda: fake_home))

        config_path = str(tmp_path / "config.toml")
        loader = PolicyLoader(config_path=config_path)
        packs = loader.discover_packs()
        # Should still find built-in packs without error.
        assert len(packs) > 0


class TestBuiltinPolicies:
    """Test that built-in packs have pack.toml manifests and load correctly."""

    def test_builtin_packs_discovered(self) -> None:
        loader = PolicyLoader()
        packs = loader.discover_packs()
        assert len(packs) > 0, "At least one built-in pack should be discovered"

    def test_builtin_packs_have_rules(self) -> None:
        loader = PolicyLoader()
        packs = loader.discover_packs()
        for pack in packs:
            assert pack.rule_count > 0, f"Pack '{pack.name}' should have rules"

    def test_builtin_policies_load(self) -> None:
        loader = PolicyLoader()
        text = loader.load_active_policies()
        assert len(text) > 0, "Loaded policy text should not be empty"
        # Verify at least one forbid rule is present.
        assert "forbid" in text


# ---------------------------------------------------------------------------
# Per-project disabled rules
# ---------------------------------------------------------------------------


class TestProjectSpecificDisabling:
    """Test that project-specific disabled rules are excluded from loaded policies."""

    def test_project_disabled_rule_excluded(
        self, pack_dir: Path, config_path: str, tmp_path: Path
    ) -> None:
        project = tmp_path / "my-project"
        project.mkdir()

        cfg = VectimusConfig(config_path)
        cfg.disable_rule_for_project("test-002", project)

        loader = PolicyLoader(
            policy_dirs=[str(pack_dir)],
            config_path=config_path,
            project_path=project,
        )
        text = loader.load_active_policies()
        assert "test-001" in text
        assert "test-002" not in text

    def test_project_disabled_rule_still_present_for_other_project(
        self, pack_dir: Path, config_path: str, tmp_path: Path
    ) -> None:
        project_a = tmp_path / "proj-a"
        project_b = tmp_path / "proj-b"
        project_a.mkdir()
        project_b.mkdir()

        cfg = VectimusConfig(config_path)
        cfg.disable_rule_for_project("test-002", project_a)

        # project_b should still have test-002.
        loader = PolicyLoader(
            policy_dirs=[str(pack_dir)],
            config_path=config_path,
            project_path=project_b,
        )
        text = loader.load_active_policies()
        assert "test-002" in text

    def test_no_project_path_loads_all(
        self, pack_dir: Path, config_path: str, tmp_path: Path
    ) -> None:
        project = tmp_path / "proj"
        project.mkdir()

        cfg = VectimusConfig(config_path)
        cfg.disable_rule_for_project("test-002", project)

        # Without project_path, test-002 should still load.
        loader = PolicyLoader(
            policy_dirs=[str(pack_dir)],
            config_path=config_path,
        )
        text = loader.load_active_policies()
        assert "test-002" in text
