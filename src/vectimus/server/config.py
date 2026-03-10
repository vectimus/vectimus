"""Server configuration loaded from environment, config files and defaults.

Precedence (highest first):
1. Environment variables (VECTIMUS_*)
2. Project-level vectimus.toml
3. User-level ~/.vectimus/config.toml
4. Built-in defaults
"""

from __future__ import annotations

import os
import tomllib
from pathlib import Path

from pydantic import BaseModel


class ServerConfig(BaseModel):
    """Runtime configuration for the Vectimus server."""

    host: str = "127.0.0.1"
    port: int = 8420
    policy_dir: str | None = None
    log_dir: str = str(Path.home() / ".vectimus" / "logs")
    identity_resolver: str = "git"
    default_persona: str = "default"
    api_key: str | None = None
    observe: bool = False
    session_spawn_limit: int = 10
    session_message_limit: int = 50
    session_ttl_seconds: int = 3600
    mcp_allowed_servers: list[str] = []

    @classmethod
    def load(cls) -> ServerConfig:
        """Build config by merging TOML files with env overrides."""
        data: dict = {}

        # User-level config
        user_config = Path.home() / ".vectimus" / "config.toml"
        if user_config.exists():
            data = _load_toml(user_config)

        # Project-level config (overrides user-level)
        project_config = Path("vectimus.toml")
        if project_config.exists():
            project_data = _load_toml(project_config)
            data = _deep_merge(data, project_data)

        # Flatten nested sections
        flat: dict = {}
        if "server" in data:
            flat.update(data["server"])
        if "policies" in data:
            if "dir" in data["policies"]:
                flat["policy_dir"] = data["policies"]["dir"]
        if "logging" in data:
            if "dir" in data["logging"]:
                flat["log_dir"] = data["logging"]["dir"]
        if "identity" in data:
            if "resolver" in data["identity"]:
                flat["identity_resolver"] = data["identity"]["resolver"]
            if "default_persona" in data["identity"]:
                flat["default_persona"] = data["identity"]["default_persona"]
        if "mcp" in data:
            if "allowed_servers" in data["mcp"]:
                flat["mcp_allowed_servers"] = list(data["mcp"]["allowed_servers"])

        # Environment overrides
        env_map = {
            "VECTIMUS_HOST": "host",
            "VECTIMUS_PORT": "port",
            "VECTIMUS_POLICY_DIR": "policy_dir",
            "VECTIMUS_LOG_DIR": "log_dir",
            "VECTIMUS_API_KEY": "api_key",
        }
        int_env_map = {
            "VECTIMUS_SESSION_SPAWN_LIMIT": "session_spawn_limit",
            "VECTIMUS_SESSION_MESSAGE_LIMIT": "session_message_limit",
            "VECTIMUS_SESSION_TTL": "session_ttl_seconds",
        }
        for env_key, config_key in env_map.items():
            val = os.environ.get(env_key)
            if val is not None:
                if config_key == "port":
                    try:
                        flat[config_key] = int(val)
                    except (TypeError, ValueError):
                        pass  # Keep default
                else:
                    flat[config_key] = val
        for env_key, config_key in int_env_map.items():
            val = os.environ.get(env_key)
            if val is not None:
                try:
                    flat[config_key] = max(int(val), 1)
                except (TypeError, ValueError):
                    pass  # Keep default

        # MCP allowed servers from env (merges with TOML)
        mcp_env = os.environ.get("VECTIMUS_MCP_ALLOWED", "").strip()
        if mcp_env:
            from_env = [s.strip() for s in mcp_env.split(",") if s.strip()]
            existing = flat.get("mcp_allowed_servers", [])
            seen = set(existing)
            for s in from_env:
                if s not in seen:
                    existing.append(s)
                    seen.add(s)
            flat["mcp_allowed_servers"] = existing

        # Observe mode from env
        observe_val = os.environ.get("VECTIMUS_OBSERVE", "").lower()
        if observe_val in ("1", "true", "yes"):
            flat["observe"] = True

        return cls(**flat)


def _load_toml(path: Path) -> dict:
    """Read a TOML file and return a dict."""
    with open(path, "rb") as f:
        return tomllib.load(f)


def _deep_merge(base: dict, override: dict) -> dict:
    """Recursively merge *override* into *base*."""
    merged = dict(base)
    for key, val in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(val, dict):
            merged[key] = _deep_merge(merged[key], val)
        else:
            merged[key] = val
    return merged
