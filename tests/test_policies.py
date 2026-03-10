"""Tests that validate Cedar policy files parse correctly."""

from __future__ import annotations

from pathlib import Path

import pytest


def _policy_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "src" / "vectimus" / "policies" / "base"


def _policy_files() -> list[Path]:
    return sorted(_policy_dir().glob("*.cedar"))


def test_policy_files_exist() -> None:
    """At least six policy files should be present."""
    files = _policy_files()
    assert len(files) >= 6


@pytest.mark.parametrize("cedar_file", _policy_files(), ids=lambda p: p.name)
def test_policy_has_id_annotations(cedar_file: Path) -> None:
    """Every policy file must have at least one @id annotation."""
    import re

    text = cedar_file.read_text()
    ids = re.findall(r'@id\("([^"]+)"\)', text)
    assert len(ids) > 0, f"{cedar_file.name} has no @id annotations"


@pytest.mark.parametrize("cedar_file", _policy_files(), ids=lambda p: p.name)
def test_policy_has_description_annotations(cedar_file: Path) -> None:
    """Every policy file must have at least one @description annotation."""
    import re

    text = cedar_file.read_text()
    descriptions = re.findall(r'@description\("([^"]+)"\)', text)
    assert len(descriptions) > 0, f"{cedar_file.name} has no @description annotations"


def test_policy_ids_unique() -> None:
    """All @id values across all policy files must be unique."""
    import re

    all_ids: list[str] = []
    for cedar_file in _policy_files():
        text = cedar_file.read_text()
        ids = re.findall(r'@id\("([^"]+)"\)', text)
        all_ids.extend(ids)
    assert len(all_ids) == len(set(all_ids)), f"Duplicate policy IDs: {all_ids}"


def test_cedarpy_validates_policies() -> None:
    """If cedarpy is available, validate that all policies parse cleanly."""
    try:
        import cedarpy
    except ImportError:
        pytest.skip("cedarpy not available")

    policy_text = ""
    for cedar_file in _policy_files():
        policy_text += cedar_file.read_text() + "\n\n"

    from vectimus.core.schemas import CEDAR_SCHEMA_JSON

    result = cedarpy.validate_policies(policy_text, CEDAR_SCHEMA_JSON)
    assert result is not None
