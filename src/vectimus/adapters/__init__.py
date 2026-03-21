"""Thin hook translators for AI coding tools.

Each adapter module registers a normaliser function that converts
tool-specific JSON payloads into canonical VectimusEvent objects.
No external dependencies beyond the standard library and the Vectimus engine.
"""

from vectimus.adapters import claude, copilot, cursor, gemini, opencode  # noqa: F401
