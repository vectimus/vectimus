"""Vectimus: Deterministic governance for AI coding tools and autonomous agents.

Intercepts agent actions, evaluates them against Cedar policies and returns
allow/deny/escalate decisions before execution.
"""

from importlib.metadata import version as _pkg_version

__version__ = _pkg_version("vectimus")
