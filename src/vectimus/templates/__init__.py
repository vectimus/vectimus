"""Editor and agent integration files that ``vectimus init`` installs.

These are shipped as package data, not generated at install time, so the
file on disk can be compared byte for byte against the version that
shipped -- that is how ``vectimus init`` tells an unmodified managed file
from one a user has edited.
"""

from __future__ import annotations

from pathlib import Path

TEMPLATES_DIR = Path(__file__).resolve().parent

OPENCODE_PLUGIN = TEMPLATES_DIR / "opencode_plugin.ts"
PI_EXTENSION = TEMPLATES_DIR / "pi_extension.ts"


def read_template(path: Path) -> str:
    """Return the text of a packaged template, or raise ``FileNotFoundError``."""
    return path.read_text(encoding="utf-8")
