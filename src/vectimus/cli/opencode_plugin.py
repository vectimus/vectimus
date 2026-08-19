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
    1: "5ea6af7dceb969ab65c20d3c82161deed77fbc8ba751b604b4c8a11027753ba7",
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


def unloadable_scope_reason(*, project: bool) -> str | None:
    """Return why OpenCode would never load a plugin installed at this scope.

    A guard OpenCode does not load is worse than no guard: the install
    reports success, ``vectimus status`` finds the file, and every tool call
    runs unchecked.  Two environments do that, and neither is visible from
    the installed file, so they are checked before writing rather than
    discovered later.

    Returns ``None`` when the scope is fine, otherwise the message to refuse
    with.  Both are refusals rather than a silent fallback to the other
    scope: installing somewhere the caller did not ask for is its own kind
    of surprise, and the fix is one environment variable either way.
    """
    if project:
        if _project_config_disabled():
            return (
                "OPENCODE_DISABLE_PROJECT_CONFIG is set, so OpenCode ignores every "
                "project .opencode directory and would never load a plugin installed "
                "there -- the install would report success and guard nothing.  Unset "
                "it, or re-run without --project to install globally."
            )
        return None

    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg and not Path(xdg).is_absolute():
        return (
            f"XDG_CONFIG_HOME is the relative path {xdg!r}, so the global plugin "
            f"directory resolves against whatever the current directory happens to "
            f"be rather than a fixed location OpenCode looks in.  Set it to an "
            f"absolute path, or unset it to use ~/.config, and re-run."
        )
    return None


def _project_config_disabled() -> bool:
    """Whether OpenCode is set to ignore project ``.opencode`` directories.

    ``ConfigPaths.directories`` tests the variable for JS truthiness, so an
    empty value does not disable anything but ``0`` or ``false`` do.  Matched
    here rather than second-guessed: the point is to agree with OpenCode
    about which directories it reads.
    """
    return bool(os.environ.get("OPENCODE_DISABLE_PROJECT_CONFIG"))


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
