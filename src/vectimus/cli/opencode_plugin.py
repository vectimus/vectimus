"""Install and remove the OpenCode plugin file.

OpenCode has no hooks config to merge into: a plugin is a whole file that
OpenCode picks up by scanning ``{plugin,plugins}/*.{ts,js}`` in every config
directory.  So instead of merging JSON, Vectimus owns one file and marks it,
and every write is guarded by that marker:

* No marker means the file is not ours -- leave it alone and say so.
* Our marker plus the exact bytes of a version we shipped means it is safe to
  replace.
* Our marker with bytes we never shipped means a human edited it; refuse,
  because silently reverting someone's changes to a security control is worse
  than leaving it stale.

Writes go through a temp file in the destination directory and a rename, so a
crash mid-write cannot leave OpenCode loading half a plugin (which, under the
plugin's own contract, would block every tool call).
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from vectimus.templates import OPENCODE_PLUGIN

PLUGIN_FILENAME = "vectimus.ts"

# Bumped whenever the shipped template changes.  The digest below must be
# updated in the same commit -- ``test_opencode.py`` fails otherwise.
PLUGIN_VERSION = 1

# sha256 of every plugin version Vectimus has shipped, so an older managed file
# can still be recognised as unmodified and replaced.  Never remove an entry:
# dropping one turns an untouched old install into a "user-modified" refusal.
SHIPPED_PLUGIN_DIGESTS: dict[int, str] = {
    1: "b9cc19fc9515c93a404beb2c67cd8c2de0e8a4d2349da69d6a6c60c361fd282d",
}

_MARKER_RE = re.compile(r"VECTIMUS-MANAGED\s+plugin-version:\s*(\d+)")


class InstallStatus(StrEnum):
    """Outcome of an attempted plugin install."""

    INSTALLED = "installed"
    UPDATED = "updated"
    UNCHANGED = "unchanged"
    REFUSED_UNMANAGED = "refused_unmanaged"
    REFUSED_MODIFIED = "refused_modified"
    REFUSED_NEWER = "refused_newer"
    FAILED = "failed"


@dataclass
class InstallResult:
    """What ``install_plugin`` did, and why."""

    status: InstallStatus
    path: Path
    message: str

    @property
    def ok(self) -> bool:
        return self.status in (
            InstallStatus.INSTALLED,
            InstallStatus.UPDATED,
            InstallStatus.UNCHANGED,
        )


def opencode_config_dir() -> Path:
    """Return OpenCode's global config directory.

    Mirrors OpenCode's own resolution (``xdg-basedir`` in
    ``packages/core/src/global.ts``): ``$XDG_CONFIG_HOME/opencode``, falling
    back to ``~/.config/opencode``.
    """
    xdg = os.environ.get("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "opencode"


def global_plugin_path() -> Path:
    """Path of the user-level Vectimus plugin."""
    return opencode_config_dir() / "plugin" / PLUGIN_FILENAME


def project_plugin_path(project_root: Path | None = None) -> Path:
    """Path of the project-level Vectimus plugin."""
    root = project_root if project_root is not None else Path.cwd()
    return root / ".opencode" / "plugin" / PLUGIN_FILENAME


def template_text() -> str:
    """Return the packaged plugin source."""
    return OPENCODE_PLUGIN.read_text(encoding="utf-8")


def marker_version(text: str) -> int | None:
    """Return the plugin version declared in *text*, or ``None`` if unmarked."""
    match = _MARKER_RE.search(text)
    if match is None:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def is_managed(path: Path) -> bool:
    """Return whether *path* is a Vectimus-managed OpenCode plugin."""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return marker_version(text) is not None


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _atomic_write(path: Path, text: str) -> None:
    """Write *text* to *path* via a temp file in the same directory.

    Same directory so the rename stays on one filesystem and is therefore
    atomic; a partially written plugin would block every tool call.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.vectimus-tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except OSError:
        tmp.unlink(missing_ok=True)
        raise


def install_plugin(path: Path) -> InstallResult:
    """Install or update the Vectimus plugin at *path*.

    Never overwrites a file Vectimus did not write, and never overwrites a
    managed file whose contents do not match a version Vectimus shipped.
    """
    shipped = template_text()

    if path.exists():
        try:
            existing = path.read_text(encoding="utf-8")
        except OSError as exc:
            return InstallResult(
                InstallStatus.FAILED, path, f"could not read existing plugin: {exc}"
            )

        version = marker_version(existing)
        if version is None:
            return InstallResult(
                InstallStatus.REFUSED_UNMANAGED,
                path,
                f"{path} exists and was not written by Vectimus (no VECTIMUS-MANAGED "
                "marker).  Move it aside and re-run to install.",
            )

        if existing == shipped:
            return InstallResult(
                InstallStatus.UNCHANGED, path, f"already at plugin version {PLUGIN_VERSION}"
            )

        if version > PLUGIN_VERSION:
            return InstallResult(
                InstallStatus.REFUSED_NEWER,
                path,
                f"{path} is plugin version {version}, newer than the version "
                f"{PLUGIN_VERSION} this Vectimus ships.  Leaving it alone.",
            )

        if _digest(existing) != SHIPPED_PLUGIN_DIGESTS.get(version):
            return InstallResult(
                InstallStatus.REFUSED_MODIFIED,
                path,
                f"{path} carries the Vectimus marker but has been edited.  "
                "Delete it and re-run to install the shipped plugin.",
            )

        try:
            _atomic_write(path, shipped)
        except OSError as exc:
            return InstallResult(InstallStatus.FAILED, path, f"could not write plugin: {exc}")
        return InstallResult(
            InstallStatus.UPDATED,
            path,
            f"updated plugin version {version} -> {PLUGIN_VERSION}",
        )

    try:
        _atomic_write(path, shipped)
    except OSError as exc:
        return InstallResult(InstallStatus.FAILED, path, f"could not write plugin: {exc}")
    return InstallResult(
        InstallStatus.INSTALLED, path, f"installed plugin version {PLUGIN_VERSION}"
    )


def remove_plugin(path: Path) -> bool:
    """Delete *path* if Vectimus wrote it.  Returns whether it was removed."""
    if not is_managed(path):
        return False
    try:
        path.unlink()
    except OSError:
        return False

    # Tidy up the empty plugin/ directory, and stop there.  Its parent is
    # OpenCode's own config directory, which OpenCode creates and owns.
    try:
        if path.parent.is_dir() and not any(path.parent.iterdir()):
            path.parent.rmdir()
    except OSError:
        pass
    return True


def installed_plugin_paths(project_root: Path | None = None) -> list[Path]:
    """Return the managed plugin files present, global first.

    Both can exist at once: OpenCode's config directories are a union, not a
    fallback chain, so a global and a project plugin both load and both run.
    """
    return [p for p in (global_plugin_path(), project_plugin_path(project_root)) if is_managed(p)]
