"""Manages ~/.vectimus/config.toml read and write operations.

Handles pack enable/disable and rule enable/disable state.  Writes are
atomic (write to temp file then rename) to prevent corruption if the
process is interrupted.
"""

from __future__ import annotations

import os
import tempfile
import tomllib
from pathlib import Path
from typing import Any

import structlog
import tomli_w

logger = structlog.get_logger(__name__)


def _safe_int(value: Any, *, default: int, minimum: int = 0) -> int:
    """Convert value to int with bounds checking and error handling.

    Returns *default* if the value cannot be parsed as an integer.
    Clamps the result to at least *minimum* to prevent disabling limits
    via zero or negative values.
    """
    try:
        result = int(value)
    except (TypeError, ValueError):
        logger.warning("invalid_int_value", value=str(value)[:64], default=default)
        return default
    return max(result, minimum)


def _default_config_path() -> Path:
    """Return the default config file path."""
    return Path.home() / ".vectimus" / "config.toml"


def project_local_config_path(project_path: Path) -> Path:
    """Return the path to the project-local config: <project>/.vectimus/config.toml."""
    return project_path / ".vectimus" / "config.toml"


class VectimusConfig:
    """Manages ~/.vectimus/config.toml read and write operations."""

    def __init__(self, config_path: str | None = None) -> None:
        """Load config from *config_path*.  Defaults to ~/.vectimus/config.toml."""
        self._path = Path(config_path) if config_path else _default_config_path()
        self._data: dict = {}
        self._load()

    @property
    def path(self) -> Path:
        """Return the config file path."""
        return self._path

    @property
    def data(self) -> dict:
        """Return the raw config data."""
        return self._data

    # -- Pack management ----------------------------------------------------

    def is_pack_enabled(self, pack_name: str) -> bool:
        """Check if a pack is enabled.  Default is True if not mentioned."""
        packs = self._data.get("packs", {})
        pack_cfg = packs.get(pack_name, {})
        if isinstance(pack_cfg, dict):
            return pack_cfg.get("enabled", True)
        return True

    def set_pack_enabled(self, pack_name: str, enabled: bool) -> None:
        """Update pack status in config and write to disk."""
        self._data.setdefault("packs", {})
        self._data["packs"][pack_name] = {"enabled": enabled}
        self._write()

    # -- Rule management ----------------------------------------------------

    def is_rule_disabled(self, rule_id: str, project_path: Path | None = None) -> bool:
        """Check if a specific rule is disabled globally or for the project."""
        rules = self._data.get("rules", {})
        disabled = rules.get("disabled", [])
        if rule_id in disabled:
            return True
        if project_path is not None:
            return rule_id in self.load_project_overrides(project_path)
        return False

    def disabled_rules(self) -> list[str]:
        """Return the list of disabled rule IDs."""
        rules = self._data.get("rules", {})
        return list(rules.get("disabled", []))

    def disable_rule(self, rule_id: str) -> None:
        """Add rule to disabled list and write to disk."""
        self._data.setdefault("rules", {})
        disabled = self._data["rules"].setdefault("disabled", [])
        if rule_id not in disabled:
            disabled.append(rule_id)
        self._write()

    def enable_rule(self, rule_id: str) -> None:
        """Remove rule from disabled list and write to disk."""
        rules = self._data.get("rules", {})
        disabled = rules.get("disabled", [])
        if rule_id in disabled:
            disabled.remove(rule_id)
            self._data["rules"]["disabled"] = disabled
            self._write()

    # -- Per-project overrides ----------------------------------------------

    def load_project_overrides(self, project_path: Path) -> set[str]:
        """Load disabled rule IDs from project config.

        Reads from ``.vectimus/config.toml`` in the project root.
        Returns empty set if the file does not exist.
        """
        local_path = project_local_config_path(project_path)
        if not local_path.exists():
            return set()
        try:
            with open(local_path, "rb") as f:
                data = tomllib.load(f)
            return set(data.get("rules", {}).get("disabled", []))
        except tomllib.TOMLDecodeError as exc:
            logger.warning(
                "project_local_config_parse_error",
                path=str(local_path),
                error=str(exc),
            )
            return set()

    def effective_disabled_rules(self, project_path: Path | None = None) -> set[str]:
        """Return the union of globally disabled rules and project-specific disabled rules."""
        global_disabled = set(self.disabled_rules())
        if project_path is None:
            return global_disabled
        project_disabled = self.load_project_overrides(project_path)
        return global_disabled | project_disabled

    def disable_rule_for_project(self, rule_id: str, project_path: Path) -> None:
        """Add a rule to the project-specific disabled list.

        Writes to ``.vectimus/config.toml`` in the project root.
        Creates the file and directory if they do not exist.
        """
        local_path = project_local_config_path(project_path)
        local_path.parent.mkdir(parents=True, exist_ok=True)

        data: dict = {}
        if local_path.exists():
            try:
                with open(local_path, "rb") as f:
                    data = tomllib.load(f)
            except tomllib.TOMLDecodeError:
                data = {}

        data.setdefault("rules", {})
        disabled = data["rules"].setdefault("disabled", [])
        if rule_id not in disabled:
            disabled.append(rule_id)

        self._write_to_path(local_path, data)

    def enable_rule_for_project(self, rule_id: str, project_path: Path) -> None:
        """Remove a rule from the project-specific disabled list.

        Reads from ``.vectimus/config.toml`` in the project root.
        """
        local_path = project_local_config_path(project_path)
        if not local_path.exists():
            return

        try:
            with open(local_path, "rb") as f:
                data = tomllib.load(f)
        except tomllib.TOMLDecodeError:
            return

        disabled = data.get("rules", {}).get("disabled", [])
        if rule_id in disabled:
            disabled.remove(rule_id)
            data["rules"]["disabled"] = disabled
            self._write_to_path(local_path, data)

    def list_project_overrides(self, project_path: Path) -> list[str]:
        """List all disabled rules for a specific project."""
        return sorted(self.load_project_overrides(project_path))

    def project_config_path(self, project_path: Path) -> Path:
        """Return the project config path: <project>/.vectimus/config.toml."""
        return project_local_config_path(project_path)

    # -- Enforcement overrides -----------------------------------------------

    _VALID_ENFORCEMENT_LEVELS = ("deny", "escalate", "observe")

    def get_enforcement_override(
        self, rule_id: str, project_path: Path | None = None
    ) -> str | None:
        """Return the enforcement override for a rule, or None if not overridden.

        Resolution: project-local > global.
        """
        if project_path is not None:
            local_path = project_local_config_path(project_path)
            if local_path.exists():
                try:
                    with open(local_path, "rb") as f:
                        data = tomllib.load(f)
                    project_level = data.get("rules", {}).get("enforcement", {}).get(rule_id)
                    if project_level in self._VALID_ENFORCEMENT_LEVELS:
                        return project_level
                except tomllib.TOMLDecodeError:
                    pass

        global_level = self._data.get("rules", {}).get("enforcement", {}).get(rule_id)
        if global_level in self._VALID_ENFORCEMENT_LEVELS:
            return global_level
        return None

    def set_enforcement_override(
        self, rule_id: str, level: str, project_path: Path | None = None
    ) -> None:
        """Set an enforcement level override for a rule.

        If *project_path* is given, writes to the project-local config.
        Otherwise writes to the global config.
        """
        if level not in self._VALID_ENFORCEMENT_LEVELS:
            raise ValueError(f"Invalid enforcement level: {level!r}")

        if project_path is not None:
            local_path = project_local_config_path(project_path)
            local_path.parent.mkdir(parents=True, exist_ok=True)

            data: dict = {}
            if local_path.exists():
                try:
                    with open(local_path, "rb") as f:
                        data = tomllib.load(f)
                except tomllib.TOMLDecodeError:
                    data = {}

            data.setdefault("rules", {}).setdefault("enforcement", {})[rule_id] = level
            self._write_to_path(local_path, data)
        else:
            self._data.setdefault("rules", {}).setdefault("enforcement", {})[rule_id] = level
            self._write()

    def clear_enforcement_override(self, rule_id: str, project_path: Path | None = None) -> None:
        """Remove an enforcement level override for a rule."""
        if project_path is not None:
            local_path = project_local_config_path(project_path)
            if not local_path.exists():
                return
            try:
                with open(local_path, "rb") as f:
                    data = tomllib.load(f)
            except tomllib.TOMLDecodeError:
                return
            enforcement = data.get("rules", {}).get("enforcement", {})
            if rule_id in enforcement:
                del enforcement[rule_id]
                self._write_to_path(local_path, data)
        else:
            enforcement = self._data.get("rules", {}).get("enforcement", {})
            if rule_id in enforcement:
                del enforcement[rule_id]
                self._write()

    def effective_enforcement_overrides(self, project_path: Path | None = None) -> dict[str, str]:
        """Return merged enforcement overrides (project-local wins over global)."""
        global_overrides = {
            k: v
            for k, v in self._data.get("rules", {}).get("enforcement", {}).items()
            if v in self._VALID_ENFORCEMENT_LEVELS
        }
        if project_path is None:
            return global_overrides

        local_path = project_local_config_path(project_path)
        if not local_path.exists():
            return global_overrides

        try:
            with open(local_path, "rb") as f:
                data = tomllib.load(f)
            project_overrides = {
                k: v
                for k, v in data.get("rules", {}).get("enforcement", {}).items()
                if v in self._VALID_ENFORCEMENT_LEVELS
            }
        except tomllib.TOMLDecodeError:
            return global_overrides

        # Project overrides take precedence.
        return {**global_overrides, **project_overrides}

    # -- MCP server allowlist ------------------------------------------------

    def mcp_allowed_servers(self) -> list[str]:
        """Return the list of approved MCP server names.

        Reads from config.toml ``[mcp] allowed_servers``.  Can be extended
        via the ``VECTIMUS_MCP_ALLOWED`` environment variable (comma-separated
        server names).  The env var merges with the config file list.
        """
        from_config = list(self._data.get("mcp", {}).get("allowed_servers", []))
        env_val = os.environ.get("VECTIMUS_MCP_ALLOWED", "").strip()
        if env_val:
            from_env = [s.strip() for s in env_val.split(",") if s.strip()]
            # Merge, preserving order, no duplicates.
            seen = set(from_config)
            for s in from_env:
                if s not in seen:
                    from_config.append(s)
                    seen.add(s)
        return from_config

    def mcp_allow_server(self, server: str) -> None:
        """Add an MCP server to the approved list.

        Raises ValueError if the server name contains characters that are
        unsafe for Cedar policy interpolation.
        """
        import re

        safe_re = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")
        if not safe_re.match(server) or len(server) > 128:
            raise ValueError(
                f"Invalid MCP server name: {server!r}. "
                "Names must match [a-zA-Z0-9][a-zA-Z0-9._-]* and be <= 128 chars."
            )
        self._data.setdefault("mcp", {})
        allowed = self._data["mcp"].setdefault("allowed_servers", [])
        if server not in allowed:
            allowed.append(server)
        self._write()

    def mcp_deny_server(self, server: str) -> None:
        """Remove an MCP server from the approved list."""
        mcp = self._data.get("mcp", {})
        allowed = mcp.get("allowed_servers", [])
        if server in allowed:
            allowed.remove(server)
            self._data["mcp"]["allowed_servers"] = allowed
            self._write()

    # -- Auto-sync -----------------------------------------------------------

    def is_auto_sync_enabled(self) -> bool:
        """Check if automatic policy sync is enabled.  Default is False.

        Reads from ``[updates] auto_sync`` in config.toml.  Can be overridden
        by the ``VECTIMUS_AUTO_SYNC`` environment variable.
        """
        env = os.environ.get("VECTIMUS_AUTO_SYNC", "").lower()
        if env in ("1", "true", "yes"):
            return True
        if env in ("0", "false", "no"):
            return False
        return bool(self._data.get("updates", {}).get("auto_sync", False))

    def get_sync_url(self) -> str:
        """Return the policy sync URL.  Defaults to https://api.vectimus.com."""
        env = os.environ.get("VECTIMUS_SYNC_URL")
        if env:
            return env
        return self._data.get("updates", {}).get("sync_url", "https://api.vectimus.com")

    def get_sync_interval_hours(self) -> int:
        """Return the sync check interval in hours.  Defaults to 24."""
        env = os.environ.get("VECTIMUS_SYNC_INTERVAL")
        if env:
            return _safe_int(env, default=24, minimum=1)
        return _safe_int(
            self._data.get("updates", {}).get("sync_interval_hours", 24),
            default=24,
            minimum=1,
        )

    # -- Server URL ----------------------------------------------------------

    def get_server_url(self) -> str | None:
        """Return the server URL.  Resolution: env > config > None."""
        env = os.environ.get("VECTIMUS_SERVER_URL")
        if env:
            return env
        return self._data.get("server", {}).get("url") or None

    def set_server_url(self, url: str | None) -> None:
        """Set or clear the server URL in config and write to disk."""
        if url:
            self._data.setdefault("server", {})
            self._data["server"]["url"] = url
        else:
            server = self._data.get("server", {})
            server.pop("url", None)
            if not server:
                self._data.pop("server", None)
        self._write()

    # -- Observe mode --------------------------------------------------------

    def is_observe_mode(self) -> bool:
        """Check if observe mode is enabled.  Logs decisions but always allows."""
        return bool(self._data.get("mode", {}).get("observe", False))

    def set_observe_mode(self, enabled: bool) -> None:
        """Enable or disable observe mode and write to disk."""
        self._data.setdefault("mode", {})
        self._data["mode"]["observe"] = enabled
        self._write()

    # -- Effective config merging -------------------------------------------

    def _load_project_local_data(self, project_path: Path) -> dict:
        """Load the project-local config, returning empty dict if not found."""
        local_path = project_local_config_path(project_path)
        if not local_path.exists():
            return {}
        try:
            with open(local_path, "rb") as f:
                return tomllib.load(f)
        except tomllib.TOMLDecodeError as exc:
            logger.warning(
                "project_local_config_parse_error",
                path=str(local_path),
                error=str(exc),
            )
            return {}

    def effective_config(self, project_path: Path) -> dict:
        """Merge global config with project-local config, section by section.

        Project-local values override global values within each section.
        """
        result: dict = {}
        for key, value in self._data.items():
            if isinstance(value, dict):
                result[key] = dict(value)
            else:
                result[key] = value

        local = self._load_project_local_data(project_path)
        for key, value in local.items():
            if isinstance(value, dict) and isinstance(result.get(key), dict):
                result[key] = {**result[key], **value}
            else:
                result[key] = value

        return result

    # -- Identity accessors -------------------------------------------------

    def get_identity_resolver(self) -> str:
        """Return the identity resolver setting.  Defaults to 'git'."""
        return self._data.get("identity", {}).get("resolver", "git")

    def get_persona(self, project_path: Path | None = None) -> str:
        """Return the persona.  Resolution: env > project config > global config > default."""
        env = os.environ.get("VECTIMUS_PERSONA")
        if env:
            return env
        data = self.effective_config(project_path) if project_path else self._data
        return data.get("identity", {}).get("persona", "default")

    def get_groups(self, project_path: Path | None = None) -> list[str]:
        """Return the group list.  Resolution: env > project config > global config > default."""
        env = os.environ.get("VECTIMUS_GROUPS")
        if env:
            return [g.strip() for g in env.split(",") if g.strip()]
        data = self.effective_config(project_path) if project_path else self._data
        return list(data.get("identity", {}).get("groups", []))

    def get_identity_type(self, project_path: Path | None = None) -> str:
        """Return the identity type.  Resolution: env > project config > global config > default."""
        env = os.environ.get("VECTIMUS_IDENTITY_TYPE")
        if env:
            return env
        data = self.effective_config(project_path) if project_path else self._data
        return data.get("identity", {}).get("identity_type", "human")

    # -- Limits accessors ---------------------------------------------------

    def get_content_inspection_max_lines(self, project_path: Path | None = None) -> int:
        """Return the content inspection max lines limit."""
        env = os.environ.get("VECTIMUS_CONTENT_MAX_LINES")
        if env:
            return _safe_int(env, default=5000, minimum=100)
        data = self.effective_config(project_path) if project_path else self._data
        return _safe_int(
            data.get("limits", {}).get("content_inspection_max_lines", 5000),
            default=5000,
            minimum=100,
        )

    def get_excessive_turns_threshold(self, project_path: Path | None = None) -> int:
        """Return the excessive turns threshold."""
        env = os.environ.get("VECTIMUS_EXCESSIVE_TURNS")
        if env:
            return _safe_int(env, default=50, minimum=1)
        data = self.effective_config(project_path) if project_path else self._data
        return _safe_int(
            data.get("limits", {}).get("excessive_turns_threshold", 50), default=50, minimum=1
        )

    def get_session_spawn_limit(self, project_path: Path | None = None) -> int:
        """Return the session spawn limit."""
        env = os.environ.get("VECTIMUS_SESSION_SPAWN_LIMIT")
        if env:
            return _safe_int(env, default=10, minimum=1)
        data = self.effective_config(project_path) if project_path else self._data
        return _safe_int(
            data.get("limits", {}).get("session_spawn_limit", 10), default=10, minimum=1
        )

    def get_session_message_limit(self, project_path: Path | None = None) -> int:
        """Return the session message limit."""
        env = os.environ.get("VECTIMUS_SESSION_MESSAGE_LIMIT")
        if env:
            return _safe_int(env, default=50, minimum=1)
        data = self.effective_config(project_path) if project_path else self._data
        return _safe_int(
            data.get("limits", {}).get("session_message_limit", 50), default=50, minimum=1
        )

    def get_session_ttl_seconds(self, project_path: Path | None = None) -> int:
        """Return the session TTL in seconds."""
        env = os.environ.get("VECTIMUS_SESSION_TTL")
        if env:
            return _safe_int(env, default=3600, minimum=60)
        data = self.effective_config(project_path) if project_path else self._data
        return _safe_int(
            data.get("limits", {}).get("session_ttl_seconds", 3600), default=3600, minimum=60
        )

    def get_git_timeout_seconds(self, project_path: Path | None = None) -> int:
        """Return the git timeout in seconds."""
        env = os.environ.get("VECTIMUS_GIT_TIMEOUT")
        if env:
            return _safe_int(env, default=5, minimum=1)
        data = self.effective_config(project_path) if project_path else self._data
        return _safe_int(data.get("limits", {}).get("git_timeout_seconds", 5), default=5, minimum=1)

    def get_audit_max_file_size_mb(self, project_path: Path | None = None) -> int:
        """Return the max audit file size in MB."""
        env = os.environ.get("VECTIMUS_AUDIT_MAX_MB")
        if env:
            return _safe_int(env, default=100, minimum=1)
        data = self.effective_config(project_path) if project_path else self._data
        return _safe_int(data.get("audit", {}).get("max_file_size_mb", 100), default=100, minimum=1)

    def get_audit_log_dir(self, project_path: Path | None = None) -> str:
        """Return the audit log directory."""
        env = os.environ.get("VECTIMUS_LOG_DIR")
        if env:
            return env
        data = self.effective_config(project_path) if project_path else self._data
        default = str(Path.home() / ".vectimus" / "logs")
        return data.get("audit", {}).get("log_dir", default)

    def get_log_dir(self) -> str:
        """Return the logging directory.  Defaults to ~/.vectimus/logs."""
        default = str(Path.home() / ".vectimus" / "logs")
        return self._data.get("logging", {}).get("dir", default)

    # -- Internal -----------------------------------------------------------

    def _load(self) -> None:
        """Read config from disk if it exists."""
        if self._path.exists():
            try:
                with open(self._path, "rb") as f:
                    self._data = tomllib.load(f)
            except tomllib.TOMLDecodeError as exc:
                logger.warning("config_parse_error", path=str(self._path), error=str(exc))
                self._data = {}
        else:
            self._data = {}

    def _write(self) -> None:
        """Atomically write global config to disk."""
        self._write_to_path(self._path, self._data)

    @staticmethod
    def _write_to_path(path: Path, data: dict) -> None:
        """Atomically write data to a TOML file."""
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

        # Write to a temp file in the same directory, then rename.
        fd, tmp_path = tempfile.mkstemp(
            dir=path.parent,
            suffix=".tmp",
        )
        try:
            with os.fdopen(fd, "wb") as f:
                tomli_w.dump(data, f)
            # Atomic rename on POSIX.  On Windows, os.replace is atomic.
            os.replace(tmp_path, path)
        except BaseException:
            # Clean up temp file on failure.
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
            raise

    @classmethod
    def create_default(cls, config_path: str | None = None) -> VectimusConfig:
        """Create a config file with sensible defaults if it does not exist.

        Returns the VectimusConfig instance.
        """
        path = Path(config_path) if config_path else _default_config_path()
        if not path.exists():
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            default_data = {
                "packs": {},
                "rules": {"disabled": []},
                "identity": {
                    "resolver": "git",
                    "default_persona": "default",
                },
                "logging": {
                    "dir": str(Path.home() / ".vectimus" / "logs"),
                },
            }
            fd, tmp_path = tempfile.mkstemp(dir=path.parent, suffix=".tmp")
            try:
                with os.fdopen(fd, "wb") as f:
                    tomli_w.dump(default_data, f)
                os.replace(tmp_path, path)
            except BaseException:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise
        return cls(str(path))
