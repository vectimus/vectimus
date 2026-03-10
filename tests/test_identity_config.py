"""Tests for configurable identity fields (Phase 2)."""

from __future__ import annotations

from pathlib import Path

import pytest
import tomli_w

from vectimus.core.config import VectimusConfig, project_local_config_path
from vectimus.core.evaluator import PolicyEngine
from vectimus.core.models import (
    ActionInfo,
    ActionType,
    ContextInfo,
    IdentityInfo,
    SourceInfo,
    VectimusEvent,
)


@pytest.fixture()
def config_path(tmp_path: Path) -> str:
    return str(tmp_path / "config.toml")


class TestGetPersona:
    def test_default(self, config_path: str) -> None:
        cfg = VectimusConfig(config_path)
        assert cfg.get_persona() == "default"

    def test_from_config(self, config_path: str) -> None:
        path = Path(config_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            tomli_w.dump({"identity": {"persona": "platform-team"}}, f)
        cfg = VectimusConfig(config_path)
        assert cfg.get_persona() == "platform-team"

    def test_env_override(self, config_path: str, monkeypatch: pytest.MonkeyPatch) -> None:
        path = Path(config_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            tomli_w.dump({"identity": {"persona": "from-config"}}, f)
        cfg = VectimusConfig(config_path)

        monkeypatch.setenv("VECTIMUS_PERSONA", "from-env")
        assert cfg.get_persona() == "from-env"

    def test_project_config_overrides_global(self, config_path: str, tmp_path: Path) -> None:
        path = Path(config_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            tomli_w.dump({"identity": {"persona": "global-persona"}}, f)
        cfg = VectimusConfig(config_path)

        project = tmp_path / "my-project"
        project.mkdir()
        local_path = project_local_config_path(project)
        local_path.parent.mkdir(parents=True, exist_ok=True)
        with open(local_path, "wb") as f:
            tomli_w.dump({"identity": {"persona": "project-persona"}}, f)

        assert cfg.get_persona(project) == "project-persona"


class TestGetGroups:
    def test_default_empty(self, config_path: str) -> None:
        cfg = VectimusConfig(config_path)
        assert cfg.get_groups() == []

    def test_from_config(self, config_path: str) -> None:
        path = Path(config_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            tomli_w.dump({"identity": {"groups": ["engineering", "platform"]}}, f)
        cfg = VectimusConfig(config_path)
        assert cfg.get_groups() == ["engineering", "platform"]

    def test_comma_separated_env(self, config_path: str, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = VectimusConfig(config_path)
        monkeypatch.setenv("VECTIMUS_GROUPS", "admin, ops, dev")
        assert cfg.get_groups() == ["admin", "ops", "dev"]


class TestGetIdentityType:
    def test_default(self, config_path: str) -> None:
        cfg = VectimusConfig(config_path)
        assert cfg.get_identity_type() == "human"

    def test_from_config(self, config_path: str) -> None:
        path = Path(config_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            tomli_w.dump({"identity": {"identity_type": "agent"}}, f)
        cfg = VectimusConfig(config_path)
        assert cfg.get_identity_type() == "agent"

    def test_env_override(self, config_path: str, monkeypatch: pytest.MonkeyPatch) -> None:
        cfg = VectimusConfig(config_path)
        monkeypatch.setenv("VECTIMUS_IDENTITY_TYPE", "agent")
        assert cfg.get_identity_type() == "agent"


class TestGroupsInCedarEntities:
    def test_groups_passed_to_cedar_entities(self) -> None:
        engine = PolicyEngine()
        event = VectimusEvent(
            source=SourceInfo(tool="claude-code"),
            identity=IdentityInfo(
                principal="test@example.com",
                groups=["engineering", "platform"],
            ),
            action=ActionInfo(
                action_type=ActionType.SHELL_COMMAND,
                raw_tool_name="Bash",
                command="ls",
            ),
            context=ContextInfo(cwd="/tmp"),
        )
        entities = engine._build_cedar_entities(event)
        principal_entity = entities[0]
        assert "groups" in principal_entity["attrs"]
        assert "engineering" in principal_entity["attrs"]["groups"]
        assert "platform" in principal_entity["attrs"]["groups"]
