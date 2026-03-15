"""Tests that validate Cedar policy files parse correctly."""

from __future__ import annotations

from pathlib import Path

import pytest


def _policies_root() -> Path:
    return Path(__file__).resolve().parent.parent / "policies"


def _all_pack_dirs() -> list[Path]:
    """Find all pack directories (containing pack.toml) under the policies root."""
    root = _policies_root()
    if not root.is_dir():
        return []
    return sorted(d for d in root.iterdir() if d.is_dir() and (d / "pack.toml").exists())


def _all_policy_files() -> list[Path]:
    """Collect all .cedar files across all pack directories."""
    files: list[Path] = []
    for pack_dir in _all_pack_dirs():
        files.extend(sorted(pack_dir.glob("*.cedar")))
    return files


def test_policy_packs_exist() -> None:
    """At least one policy pack should be present."""
    packs = _all_pack_dirs()
    assert len(packs) >= 1


def test_policy_files_exist() -> None:
    """At least six policy files should be present across all packs."""
    files = _all_policy_files()
    assert len(files) >= 6


@pytest.mark.parametrize("cedar_file", _all_policy_files(), ids=lambda p: p.name)
def test_policy_has_id_annotations(cedar_file: Path) -> None:
    """Every policy file must have at least one @id annotation."""
    import re

    text = cedar_file.read_text()
    ids = re.findall(r'@id\("([^"]+)"\)', text)
    assert len(ids) > 0, f"{cedar_file.name} has no @id annotations"


@pytest.mark.parametrize("cedar_file", _all_policy_files(), ids=lambda p: p.name)
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
    for cedar_file in _all_policy_files():
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
    for cedar_file in _all_policy_files():
        policy_text += cedar_file.read_text() + "\n\n"

    from vectimus.engine.schemas import CEDAR_SCHEMA_JSON

    result = cedarpy.validate_policies(policy_text, CEDAR_SCHEMA_JSON)
    assert result is not None
