"""Install and remove the Pi extension file.

Pi has no hooks config to merge into: an extension is a whole file that Pi
picks up by scanning ``extensions/*.ts`` in its config directories.  So, as
with OpenCode, Vectimus owns one file and marks it, and every write is
guarded by that marker:

* No marker means the file is not ours -- leave it alone and say so.
* Our marker plus the exact bytes of a version we shipped means it is safe to
  replace.
* Our marker with bytes we never shipped means a human edited it; refuse,
  because silently reverting someone's changes to a security control is worse
  than leaving it stale.

Writes go through a temp file in the destination directory and a rename, so a
crash mid-write cannot leave Pi loading half an extension.
"""

from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path

from vectimus.templates import PI_EXTENSION

EXTENSION_FILENAME = "vectimus.ts"

# Bumped whenever the shipped template changes.  The digest below must be
# updated in the same commit -- ``test_pi.py`` fails otherwise.
EXTENSION_VERSION = 1

# sha256 of every extension version Vectimus has shipped, so an older managed
# file can still be recognised as unmodified and replaced.  Never remove an
# entry: dropping one turns an untouched old install into a "user-modified"
# refusal.
SHIPPED_EXTENSION_DIGESTS: dict[int, str] = {
    1: "fa7232e8e6078c27a0f6bdfad063e55863369f26a8af25222b49fa522dc7f5cc",
}

_MARKER_RE = re.compile(r"VECTIMUS-MANAGED\s+extension-version:\s*(\d+)")


class InstallStatus(StrEnum):
    """Outcome of an attempted extension install."""

    INSTALLED = "installed"
    UPDATED = "updated"
    UNCHANGED = "unchanged"
    REFUSED_UNMANAGED = "refused_unmanaged"
    REFUSED_MODIFIED = "refused_modified"
    REFUSED_NEWER = "refused_newer"
    FAILED = "failed"


@dataclass
class InstallResult:
    """What ``install_extension`` did, and why."""

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


def pi_config_dir() -> Path:
    """Return Pi's global config directory.

    Pi's ``piConfig.configDir`` is ``.pi``, and the agent's own files live
    under an ``agent`` subdirectory -- the documented global extension path is
    ``~/.pi/agent/extensions/``, not ``~/.pi/extensions/``.
    """
    return Path.home() / ".pi" / "agent"


def global_extension_path() -> Path:
    """Path of the user-level Vectimus extension."""
    return pi_config_dir() / "extensions" / EXTENSION_FILENAME


def project_extension_path(project_root: Path | None = None) -> Path:
    """Path of the project-level Vectimus extension.

    Note the project directory is ``.pi/extensions/`` with no ``agent``
    segment; only the global location has one.
    """
    root = project_root if project_root is not None else Path.cwd()
    return root / ".pi" / "extensions" / EXTENSION_FILENAME


def template_text() -> str:
    """Return the packaged extension source."""
    return PI_EXTENSION.read_text(encoding="utf-8")


def marker_version(text: str) -> int | None:
    """Return the extension version declared in *text*, or ``None``."""
    match = _MARKER_RE.search(text)
    if match is None:
        return None
    try:
        return int(match.group(1))
    except ValueError:
        return None


def is_managed(path: Path) -> bool:
    """Return whether *path* is a Vectimus-managed Pi extension."""
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
    atomic; Pi loading a half-written extension would be a syntax error at
    startup rather than a guard.
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


def install_extension(path: Path) -> InstallResult:
    """Install or update the Vectimus extension at *path*.

    Never overwrites a file Vectimus did not write, and never overwrites a
    managed file whose contents do not match a version Vectimus shipped.
    """
    shipped = template_text()

    if path.exists():
        try:
            existing = path.read_text(encoding="utf-8")
        except OSError as exc:
            return InstallResult(
                InstallStatus.FAILED, path, f"could not read existing extension: {exc}"
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
                InstallStatus.UNCHANGED,
                path,
                f"already at extension version {EXTENSION_VERSION}",
            )

        if version > EXTENSION_VERSION:
            return InstallResult(
                InstallStatus.REFUSED_NEWER,
                path,
                f"{path} is extension version {version}, newer than the version "
                f"{EXTENSION_VERSION} this Vectimus ships.  Leaving it alone.",
            )

        if _digest(existing) != SHIPPED_EXTENSION_DIGESTS.get(version):
            return InstallResult(
                InstallStatus.REFUSED_MODIFIED,
                path,
                f"{path} carries the Vectimus marker but has been edited.  "
                "Delete it and re-run to install the shipped extension.",
            )

        try:
            _atomic_write(path, shipped)
        except OSError as exc:
            return InstallResult(InstallStatus.FAILED, path, f"could not write extension: {exc}")
        return InstallResult(
            InstallStatus.UPDATED,
            path,
            f"updated extension version {version} -> {EXTENSION_VERSION}",
        )

    try:
        _atomic_write(path, shipped)
    except OSError as exc:
        return InstallResult(InstallStatus.FAILED, path, f"could not write extension: {exc}")
    return InstallResult(
        InstallStatus.INSTALLED, path, f"installed extension version {EXTENSION_VERSION}"
    )


def remove_extension(path: Path) -> bool:
    """Delete *path* if Vectimus wrote it.  Returns whether it was removed."""
    if not is_managed(path):
        return False
    try:
        path.unlink()
    except OSError:
        return False

    # Tidy up the empty extensions/ directory, and stop there.  Its parent is
    # Pi's own config directory, which Pi creates and owns.
    try:
        if path.parent.is_dir() and not any(path.parent.iterdir()):
            path.parent.rmdir()
    except OSError:
        pass
    return True


def installed_extension_paths(project_root: Path | None = None) -> list[Path]:
    """Return the managed extension files present, global first.

    Both can exist at once: Pi's extension directories are a union, not a
    fallback chain, so a global and a project extension both load and both
    receive ``tool_call``.
    """
    return [
        p for p in (global_extension_path(), project_extension_path(project_root)) if is_managed(p)
    ]
