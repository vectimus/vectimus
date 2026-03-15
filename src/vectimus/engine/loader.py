"""Discovers, loads and filters Cedar policies based on pack and rule configuration.

Scans policy directories for pack.toml manifests, reads user configuration
to determine which packs and rules are active, then returns combined Cedar
policy text ready for cedarpy evaluation.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

import structlog

from vectimus.engine.config import VectimusConfig

try:
    from vectimus.engine.policy_sync import get_policy_cache_dir
except Exception:
    get_policy_cache_dir = lambda: None  # noqa: E731

logger = structlog.get_logger(__name__)


@dataclass
class RuleInfo:
    """Metadata for a single Cedar rule parsed from annotations."""

    rule_id: str
    description: str = ""
    incident: str = ""
    suggested_alternative: str = ""
    controls: str = ""
    enforcement: str = "deny"
    pack_name: str = ""
    source_file: str = ""
    cedar_text: str = ""
    enabled: bool = True


@dataclass
class PackInfo:
    """Metadata for a policy pack read from pack.toml."""

    name: str
    version: str = "0.0.0"
    description: str = ""
    author: str = ""
    license: str = ""
    requires: list[str] = field(default_factory=list)
    enterprise: bool = False
    path: Path = field(default_factory=lambda: Path("."))
    enabled: bool = True
    rule_count: int = 0


# ---------------------------------------------------------------------------
# Cedar annotation parser
# ---------------------------------------------------------------------------

_ANNOTATION_RE = re.compile(r'@(\w+)\("([^"]*)"\)')


def _split_cedar_rules(cedar_text: str) -> list[str]:
    """Split Cedar text into individual rule blocks.

    A rule block starts at an ``@id("...")`` annotation and ends just before
    the next ``@id("...")`` or at end of text.  This avoids needing to parse
    the full Cedar grammar.
    """
    # Find start positions of @id annotations (each marks a new rule).
    starts = [m.start() for m in re.finditer(r"@id\(", cedar_text)]
    if not starts:
        return []

    blocks: list[str] = []
    for i, start in enumerate(starts):
        end = starts[i + 1] if i + 1 < len(starts) else len(cedar_text)
        block = cedar_text[start:end].strip()
        if block:
            blocks.append(block)

    return blocks


def parse_rules_from_cedar(
    cedar_text: str,
    pack_name: str = "",
    source_file: str = "",
) -> list[RuleInfo]:
    """Parse Cedar text and return a list of RuleInfo for each rule block.

    Uses regex to extract @id, @description, @incident, @suggested_alternative
    and @controls annotations.  Does not attempt full Cedar parsing.
    """
    rules: list[RuleInfo] = []

    for block in _split_cedar_rules(cedar_text):
        annotations: dict[str, str] = {}
        for ann_match in _ANNOTATION_RE.finditer(block):
            annotations[ann_match.group(1)] = ann_match.group(2)

        rule_id = annotations.get("id", "")
        if not rule_id:
            continue

        raw_enforcement = annotations.get("enforcement", "deny")
        enforcement = (
            raw_enforcement if raw_enforcement in ("deny", "escalate", "observe") else "deny"
        )

        rules.append(
            RuleInfo(
                rule_id=rule_id,
                description=annotations.get("description", ""),
                incident=annotations.get("incident", ""),
                suggested_alternative=annotations.get("suggested_alternative", ""),
                controls=annotations.get("controls", ""),
                enforcement=enforcement,
                pack_name=pack_name,
                source_file=source_file,
                cedar_text=block.strip(),
            )
        )

    return rules


def _load_pack_manifest(pack_dir: Path) -> PackInfo | None:
    """Read pack.toml from a directory.  Returns None if not found."""
    manifest_path = pack_dir / "pack.toml"
    if not manifest_path.exists():
        return None

    try:
        with open(manifest_path, "rb") as f:
            data = tomllib.load(f)
    except tomllib.TOMLDecodeError as exc:
        logger.warning("pack_manifest_parse_error", path=str(manifest_path), error=str(exc))
        return None

    pack_data = data.get("pack", {})
    return PackInfo(
        name=pack_data.get("name", pack_dir.name),
        version=pack_data.get("version", "0.0.0"),
        description=pack_data.get("description", ""),
        author=pack_data.get("author", ""),
        license=pack_data.get("license", ""),
        requires=pack_data.get("requires", []),
        enterprise=pack_data.get("enterprise", False),
        path=pack_dir,
    )


# ---------------------------------------------------------------------------
# MCP server allowlist
# ---------------------------------------------------------------------------

# Rule ID for the MCP default-deny-all rule, which is rewritten with an
# allowlist when MCP servers are configured.
_MCP_ALLOWLIST_RULE_ID = "vectimus-mcp-001"

# MCP server names must match this pattern to prevent Cedar injection.
_SAFE_SERVER_NAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$")


def _validate_mcp_server_name(name: str) -> bool:
    """Return True if the server name is safe for Cedar interpolation."""
    return bool(_SAFE_SERVER_NAME_RE.match(name)) and len(name) <= 128


def _build_mcp_allowlist_cedar(allowed_servers: list[str], rule_id: str) -> str:
    """Generate Cedar policy text for the MCP default-deny rule with an allowlist.

    Produces a forbid rule with an ``unless`` clause that permits calls
    to the listed servers.  When no servers are configured, the static
    rule in mcp_tools.cedar blocks everything.

    Server names are validated against a strict pattern to prevent Cedar
    injection via crafted names containing quotes or policy syntax.
    """
    safe_servers: list[str] = []
    for s in allowed_servers:
        if _validate_mcp_server_name(s):
            safe_servers.append(s)
        else:
            logger.warning(
                "mcp_allowlist_invalid_name",
                name=s[:64],
                reason="name contains invalid characters or is too long",
            )

    if not safe_servers:
        # No valid servers: return the default deny-all rule.
        return (
            f'@id("{rule_id}")\n'
            '@description("Block MCP tool calls to servers not on the approved list")\n'
            '@incident("Clinejection: agent communicated with malicious MCP server that '
            'instructed it to publish backdoored packages, February 2026")\n'
            '@controls("OWASP-ASI02")\n'
            '@suggested_alternative("Add the MCP server to your approved list with: '
            'vectimus mcp allow <server-name>")\n'
            "forbid (\n"
            "    principal,\n"
            '    action == Vectimus::Action::"mcp_tool",\n'
            "    resource\n"
            ");"
        )

    conditions = " ||\n    ".join(f'context.mcp_server == "{s}"' for s in safe_servers)
    return (
        f'@id("{rule_id}")\n'
        '@description("Block MCP tool calls to servers not on the approved list")\n'
        '@incident("Clinejection: agent communicated with malicious MCP server that '
        'instructed it to publish backdoored packages, February 2026")\n'
        '@controls("OWASP-ASI02")\n'
        '@suggested_alternative("Add the MCP server to your approved list with: '
        'vectimus mcp allow <server-name>")\n'
        "forbid (\n"
        "    principal,\n"
        '    action == Vectimus::Action::"mcp_tool",\n'
        "    resource\n"
        ") unless {\n"
        f"    {conditions}\n"
        "};"
    )


# ---------------------------------------------------------------------------
# Policy Loader
# ---------------------------------------------------------------------------


class PolicyLoader:
    """Discovers, loads and filters Cedar policies based on pack and rule configuration."""

    def __init__(
        self,
        policy_dirs: list[str] | None = None,
        config_path: str | None = None,
        project_path: Path | None = None,
        mcp_allowed_override: list[str] | None = None,
    ) -> None:
        """Initialise with policy directories and optional config path.

        policy_dirs: list of directories to scan for pack subdirectories.
            If None, uses the built-in policies directory.
        config_path: path to config.toml.  Defaults to ~/.vectimus/config.toml.
        project_path: project root for per-project rule overrides.
        mcp_allowed_override: if provided, used as the MCP allowlist instead
            of reading from VectimusConfig.  Used by the server to pass its
            own MCP configuration through.
        """
        if policy_dirs is None:
            # Bundled policies always load as the baseline.
            builtin = Path(__file__).resolve().parent.parent / "policies"
            if not builtin.is_dir():
                # Development (editable install): policies at repo root
                builtin = Path(__file__).resolve().parent.parent.parent.parent / "policies"
            self._policy_dirs = [builtin]
            # API-downloaded cache supplements bundled policies (cache packs
            # take precedence for duplicate rule IDs during load).
            cache_dir = get_policy_cache_dir()
            if cache_dir is not None:
                self._policy_dirs.append(cache_dir)
            external = Path.home() / ".vectimus" / "packs"
            self._policy_dirs.append(external)
            if project_path is not None:
                project_packs = project_path / ".vectimus" / "packs"
                if project_packs.is_dir():
                    self._policy_dirs.append(project_packs)
        else:
            self._policy_dirs = [Path(d) for d in policy_dirs]

        self._config = VectimusConfig(config_path)
        self._project_path = project_path
        self._mcp_allowed_override = mcp_allowed_override
        self._packs: list[PackInfo] = []
        self._rules: list[RuleInfo] = []
        self._loaded = False

    @property
    def config(self) -> VectimusConfig:
        """Return the underlying VectimusConfig instance."""
        return self._config

    def discover_packs(self) -> list[PackInfo]:
        """Scan policy directories for pack.toml manifests.

        Returns metadata for all found packs with enabled/disabled status
        resolved from the user config.  When multiple directories contain a
        pack with the same name, later directories in ``_policy_dirs`` win
        (cache overrides bundled, project-local overrides both).
        """
        packs_by_name: dict[str, PackInfo] = {}

        for policy_dir in self._policy_dirs:
            if not policy_dir.is_dir():
                continue

            for subdir in sorted(policy_dir.iterdir()):
                if not subdir.is_dir():
                    continue

                pack_info = _load_pack_manifest(subdir)
                if pack_info is None:
                    continue

                pack_info.enabled = self._config.is_pack_enabled(pack_info.name)

                # Count rules in the pack.
                rule_count = 0
                for cedar_file in subdir.glob("*.cedar"):
                    text = cedar_file.read_text()
                    rule_count += len(parse_rules_from_cedar(text))
                pack_info.rule_count = rule_count

                # Later directories override earlier ones by pack name.
                packs_by_name[pack_info.name] = pack_info

        packs = list(packs_by_name.values())
        self._packs = packs
        return packs

    def load_active_policies(self) -> str:
        """Load and concatenate Cedar policy text from all enabled packs.

        Excludes any individually disabled rules.  Returns the combined Cedar
        policy text ready for cedarpy evaluation.
        """
        if not self._packs:
            self.discover_packs()

        # Validate pack dependencies.
        enabled_names = {p.name for p in self._packs if p.enabled}
        for pack in self._packs:
            if pack.enabled and pack.requires:
                missing = [r for r in pack.requires if r not in enabled_names]
                if missing:
                    logger.warning("pack_missing_dependency", pack=pack.name, missing=missing)

        disabled_rules = self._config.effective_disabled_rules(self._project_path)
        if self._mcp_allowed_override is not None:
            mcp_allowlist = self._mcp_allowed_override
        else:
            mcp_allowlist = self._config.mcp_allowed_servers()
        parts: list[str] = []
        all_rules: list[RuleInfo] = []
        seen_ids: dict[str, str] = {}  # rule_id -> source_file (for collision detection)

        for pack in self._packs:
            if not pack.enabled:
                continue

            for cedar_file in sorted(pack.path.glob("*.cedar")):
                text = cedar_file.read_text()
                rules = parse_rules_from_cedar(
                    text,
                    pack_name=pack.name,
                    source_file=str(cedar_file),
                )

                for rule in rules:
                    # Fail fast on duplicate @id values.
                    if rule.rule_id in seen_ids:
                        raise ValueError(
                            f"Duplicate policy ID '{rule.rule_id}' found in "
                            f"'{cedar_file}' (first seen in '{seen_ids[rule.rule_id]}'). "
                            f"Each @id must be unique across all policy packs."
                        )
                    seen_ids[rule.rule_id] = str(cedar_file)

                    if rule.rule_id in disabled_rules:
                        rule.enabled = False
                    else:
                        cedar_text = rule.cedar_text
                        # Rewrite MCP server allowlist rule with configured servers.
                        if rule.rule_id == _MCP_ALLOWLIST_RULE_ID and mcp_allowlist:
                            cedar_text = _build_mcp_allowlist_cedar(
                                mcp_allowlist, rule_id=rule.rule_id
                            )
                        parts.append(cedar_text)
                    all_rules.append(rule)

        self._rules = all_rules
        self._loaded = True

        logger.info(
            "policies_loaded",
            packs=len([p for p in self._packs if p.enabled]),
            rules_total=len(all_rules),
            rules_active=len(parts),
            rules_disabled=len(all_rules) - len(parts),
        )

        return "\n\n".join(parts)

    def list_packs(self) -> list[dict]:
        """Return pack metadata with enabled/disabled status for CLI display."""
        if not self._packs:
            self.discover_packs()

        return [
            {
                "name": p.name,
                "version": p.version,
                "description": p.description,
                "author": p.author,
                "license": p.license,
                "rule_count": p.rule_count,
                "enabled": p.enabled,
                "path": str(p.path),
            }
            for p in self._packs
        ]

    def list_rules(self) -> list[dict]:
        """Return all rules across active packs with their IDs, descriptions,
        pack membership and enabled/disabled status.
        """
        if not self._loaded:
            self.load_active_policies()

        return [
            {
                "rule_id": r.rule_id,
                "description": r.description,
                "pack": r.pack_name,
                "incident": r.incident,
                "suggested_alternative": r.suggested_alternative,
                "controls": r.controls,
                "enforcement": r.enforcement,
                "source_file": r.source_file,
                "enabled": r.enabled,
            }
            for r in self._rules
        ]

    def get_rule(self, rule_id: str) -> RuleInfo | None:
        """Return a single rule by ID, or None if not found."""
        if not self._loaded:
            self.load_active_policies()

        for rule in self._rules:
            if rule.rule_id == rule_id:
                return rule
        return None

    def get_pack(self, pack_name: str) -> PackInfo | None:
        """Return a single pack by name, or None if not found."""
        if not self._packs:
            self.discover_packs()

        for pack in self._packs:
            if pack.name == pack_name:
                return pack
        return None
