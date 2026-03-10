"""Cedar policy loading and evaluation.

Loads .cedar policy files from a directory, converts VectimusEvent objects into
Cedar authorisation requests and returns governance decisions.  Cedar via cedarpy
is the primary and only evaluation engine.
"""

from __future__ import annotations

import re
import time
from pathlib import Path

# Lazy import to avoid circular dependency.
from typing import TYPE_CHECKING, Any

import cedarpy
import structlog

from vectimus.core.models import ActionType, Decision, DecisionVerdict, VectimusEvent
from vectimus.core.schemas import CEDAR_SCHEMA_JSON

if TYPE_CHECKING:
    from vectimus.core.loader import PolicyLoader

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Policy metadata parsed from Cedar annotations
# ---------------------------------------------------------------------------


class _PolicyMeta:
    """Metadata extracted from Cedar policy annotations."""

    def __init__(
        self,
        policy_id: str,
        description: str = "",
        suggested_alternative: str = "",
        incident: str = "",
        controls: str = "",
    ) -> None:
        self.policy_id = policy_id
        self.description = description
        self.suggested_alternative = suggested_alternative
        self.incident = incident
        self.controls = controls


def _parse_policy_metadata(policy_text: str) -> tuple[dict[str, _PolicyMeta], list[str]]:
    """Parse @id, @description, @suggested_alternative, @incident, @controls from Cedar text.

    Returns a tuple of:
    - dict mapping policy ID to its metadata
    - list of policy IDs in document order (for mapping cedarpy's positional
      ``policyN`` reason identifiers back to real @id values)
    """
    metadata: dict[str, _PolicyMeta] = {}
    ordered_ids: list[str] = []

    # Match each policy block: annotations followed by forbid/permit.
    pattern = re.compile(
        r'((?:\s*@\w+\("[^"]*"\)\s*)+)\s*(?:forbid|permit)\s*\(',
        re.MULTILINE,
    )

    for match in pattern.finditer(policy_text):
        annotation_block = match.group(1)

        policy_id = ""
        description = ""
        suggested_alt = ""
        incident = ""
        controls = ""

        for ann_match in re.finditer(r'@(\w+)\("([^"]*)"\)', annotation_block):
            key = ann_match.group(1)
            value = ann_match.group(2)
            if key == "id":
                policy_id = value
            elif key == "description":
                description = value
            elif key == "suggested_alternative":
                suggested_alt = value
            elif key == "incident":
                incident = value
            elif key == "controls":
                controls = value

        ordered_ids.append(policy_id)
        if policy_id:
            metadata[policy_id] = _PolicyMeta(
                policy_id=policy_id,
                description=description,
                suggested_alternative=suggested_alt,
                incident=incident,
                controls=controls,
            )

    return metadata, ordered_ids


# ---------------------------------------------------------------------------
# Policy Engine
# ---------------------------------------------------------------------------


class PolicyEngine:
    """Loads Cedar policies and evaluates VectimusEvent objects against them.

    Cedar via cedarpy is the primary and only evaluation engine.  On any
    evaluation error the decision is DENY (fail closed).
    """

    def __init__(
        self,
        policy_dir: str | None = None,
        schema_path: str | None = None,
        *,
        loader: PolicyLoader | None = None,
        observe: bool = False,
    ) -> None:
        """Load policies from *policy_dir* or via a *loader*.

        If *loader* is provided it takes precedence.  The loader handles
        pack discovery, rule filtering and config-based enable/disable.

        If *policy_dir* is ``None`` and no loader is given, the built-in
        ``policies/base`` directory shipped with the package is used.

        If *observe* is True, all decisions are logged but enforcement is
        disabled (DENY decisions are downgraded to ALLOW).
        """
        self._policy_dir = policy_dir
        self._loader = loader
        self._observe = observe
        self._policies_text: str = ""
        self._policy_files: list[Path] = []
        self._policy_metadata: dict[str, _PolicyMeta] = {}
        self._policy_index: dict[str, str] = {}  # "policyN" -> real @id
        self._schema = CEDAR_SCHEMA_JSON

        self.reload()

    # -- public API ---------------------------------------------------------

    def evaluate(self, event: VectimusEvent) -> Decision:
        """Evaluate an event against loaded Cedar policies.

        Returns a Decision.  On any internal error the decision is DENY
        (fail closed).  In observe mode DENY decisions are downgraded to
        ALLOW while preserving the matched policy info for audit logging.
        """
        start = time.perf_counter()
        try:
            decision = self._evaluate_cedar(event)

            # Double evaluation: inspect file/script content against
            # shell_command policies when the primary evaluation allows.
            # Cedar's `like` does not match across newlines, so we check
            # each line individually.
            if decision.decision == DecisionVerdict.ALLOW:
                content = event.action.file_content or event.action.script_content
                if content:
                    for line in content.splitlines():
                        line = line.strip()
                        if not line:
                            continue
                        content_decision = self._evaluate_content(event, line)
                        if content_decision.decision == DecisionVerdict.DENY:
                            decision = content_decision
                            break

        except Exception as exc:
            logger.error("evaluation_error", error=str(exc))
            decision = Decision(
                decision=DecisionVerdict.DENY,
                reason="Evaluation error (fail closed)",
            )
        elapsed_ms = (time.perf_counter() - start) * 1000
        decision.evaluation_time_ms = round(elapsed_ms, 3)

        # Observe mode: log what would have been denied but allow everything.
        if self._observe and decision.decision == DecisionVerdict.DENY:
            logger.info(
                "observe_mode_would_deny",
                reason=decision.reason,
                matched_policies=decision.matched_policy_ids,
            )
            decision = Decision(
                decision=DecisionVerdict.ALLOW,
                reason=f"[observe] {decision.reason}",
                suggested_alternative=decision.suggested_alternative,
                matched_policy_ids=decision.matched_policy_ids,
                evaluation_time_ms=decision.evaluation_time_ms,
            )

        return decision

    def reload(self) -> None:
        """Reload policies from disk."""
        if self._loader is not None:
            self._load_from_loader()
        elif self._policy_dir is None:
            # Use built-in policies shipped with the package.
            pkg_dir = Path(__file__).resolve().parent.parent / "policies" / "base"
            self._load_from_dir(pkg_dir)
        else:
            self._load_from_dir(Path(self._policy_dir))

    def list_policies(self) -> list[dict[str, Any]]:
        """Return metadata for each loaded policy file."""
        result: list[dict[str, Any]] = []
        for pf in self._policy_files:
            text = pf.read_text()
            ids = re.findall(r'@id\("([^"]+)"\)', text)
            result.append(
                {
                    "file": pf.name,
                    "policy_ids": ids,
                    "size_bytes": len(text),
                }
            )
        return result

    # -- Cedar evaluation ---------------------------------------------------

    def _evaluate_cedar(self, event: VectimusEvent) -> Decision:
        """Evaluate using cedarpy.

        Cedar uses default-deny (no permit rule = deny).  Since our policies
        are forbid-only, we check ``diagnostics.reasons`` to see whether a
        forbid rule actually matched.  An empty reasons list means the deny
        is just the default and should be treated as allow.
        """
        request = self._build_cedar_request(event)
        entities = self._build_cedar_entities(event)

        result = cedarpy.is_authorized(
            request=request,
            policies=self._policies_text,
            entities=entities,
        )

        if result.decision == cedarpy.Decision.Allow:
            return Decision(decision=DecisionVerdict.ALLOW)

        # Check if a forbid rule actually matched.  Empty reasons means
        # this is just Cedar's default deny (no permit rule present).
        reasons = result.diagnostics.reasons if result.diagnostics else []
        if not reasons:
            return Decision(decision=DecisionVerdict.ALLOW)

        # cedarpy returns positional IDs like "policy0", "policy1".
        # Map them back to real @id annotation values.
        matched_ids: list[str] = []
        for reason in reasons:
            real_id = self._policy_index.get(reason, reason)
            matched_ids.append(real_id)

        # Find the first matched policy with metadata to get description
        # and suggested alternative.
        reason_text = f"Denied by Cedar policy: {', '.join(matched_ids)}"
        suggested_alt: str | None = None

        for pid in matched_ids:
            meta = self._policy_metadata.get(pid)
            if meta:
                reason_text = f"Blocked by policy {pid}: {meta.description}"
                if meta.suggested_alternative:
                    suggested_alt = meta.suggested_alternative
                break

        return Decision(
            decision=DecisionVerdict.DENY,
            reason=reason_text,
            suggested_alternative=suggested_alt,
            matched_policy_ids=matched_ids,
        )

    def _evaluate_content(self, event: VectimusEvent, content: str) -> Decision:
        """Run a second Cedar evaluation treating content as a shell command.

        Reuses all existing shell_command policies to inspect file contents
        and script bodies for dangerous patterns.
        """
        principal_type = (
            "Vectimus::Agent" if event.identity.identity_type == "agent" else "Vectimus::User"
        )
        context: dict[str, str] = {"command": content}
        if event.context.cwd:
            context["cwd"] = event.context.cwd

        request = {
            "principal": f'{principal_type}::"{event.identity.principal}"',
            "action": f'Vectimus::Action::"{ActionType.SHELL_COMMAND}"',
            "resource": f'Vectimus::Tool::"{event.action.raw_tool_name}"',
            "context": context,
        }
        entities = self._build_cedar_entities(event)

        result = cedarpy.is_authorized(
            request=request,
            policies=self._policies_text,
            entities=entities,
        )

        if result.decision == cedarpy.Decision.Allow:
            return Decision(decision=DecisionVerdict.ALLOW)

        reasons = result.diagnostics.reasons if result.diagnostics else []
        if not reasons:
            return Decision(decision=DecisionVerdict.ALLOW)

        matched_ids: list[str] = []
        for reason in reasons:
            real_id = self._policy_index.get(reason, reason)
            matched_ids.append(real_id)

        reason_text = f"Denied by Cedar policy: {', '.join(matched_ids)}"
        suggested_alt: str | None = None

        source = "file content" if event.action.file_content else "script content"
        for pid in matched_ids:
            meta = self._policy_metadata.get(pid)
            if meta:
                reason_text = (
                    f"Blocked by policy {pid} (via {source} inspection): {meta.description}"
                )
                if meta.suggested_alternative:
                    suggested_alt = meta.suggested_alternative
                break

        return Decision(
            decision=DecisionVerdict.DENY,
            reason=reason_text,
            suggested_alternative=suggested_alt,
            matched_policy_ids=matched_ids,
        )

    def _build_cedar_request(self, event: VectimusEvent) -> dict[str, Any]:
        """Convert a VectimusEvent into a Cedar authorisation request."""
        principal_type = (
            "Vectimus::Agent" if event.identity.identity_type == "agent" else "Vectimus::User"
        )
        context: dict[str, str] = {}
        if event.action.command:
            context["command"] = event.action.command
        if event.action.file_path:
            context["file_path"] = event.action.file_path
        if event.action.url:
            context["url"] = event.action.url
        if event.action.mcp_server:
            context["mcp_server"] = event.action.mcp_server
        if event.action.mcp_tool:
            context["mcp_tool"] = event.action.mcp_tool
        if event.action.package_name:
            context["package_name"] = event.action.package_name
        if event.context.cwd:
            context["cwd"] = event.context.cwd

        return {
            "principal": f'{principal_type}::"{event.identity.principal}"',
            "action": f'Vectimus::Action::"{event.action.action_type}"',
            "resource": f'Vectimus::Tool::"{event.action.raw_tool_name}"',
            "context": context,
        }

    def _build_cedar_entities(self, event: VectimusEvent) -> list[dict[str, Any]]:
        """Build the entity list for a Cedar request."""
        principal_type = (
            "Vectimus::Agent" if event.identity.identity_type == "agent" else "Vectimus::User"
        )
        return [
            {
                "uid": {"type": principal_type, "id": event.identity.principal},
                "attrs": {
                    "persona": event.identity.persona,
                    "groups": list(event.identity.groups),
                },
                "parents": [],
            },
            {
                "uid": {"type": "Vectimus::Tool", "id": event.action.raw_tool_name},
                "attrs": {"name": event.action.raw_tool_name},
                "parents": [],
            },
        ]

    # -- Loading ------------------------------------------------------------

    def _load_from_loader(self) -> None:
        """Load policies via the PolicyLoader (pack/rule aware)."""
        if self._loader is None:
            raise RuntimeError("PolicyEngine._load_from_loader called without a loader")
        self._policies_text = self._loader.load_active_policies()
        self._policy_metadata, ordered_ids = _parse_policy_metadata(self._policies_text)

        # Build mapping from cedarpy's positional "policyN" to real @id values.
        self._policy_index = {}
        for idx, pid in enumerate(ordered_ids):
            if pid:
                self._policy_index[f"policy{idx}"] = pid

        # Populate _policy_files from loader's discovered packs for list_policies().
        self._policy_files = []
        for pack_info in self._loader.discover_packs():
            if pack_info.enabled:
                self._policy_files.extend(sorted(pack_info.path.glob("*.cedar")))

    def _load_from_dir(self, policy_dir: Path) -> None:
        """Load all .cedar files from *policy_dir*."""
        self._policy_files = []
        parts: list[str] = []

        if policy_dir.is_dir():
            for cedar_file in sorted(policy_dir.glob("*.cedar")):
                self._policy_files.append(cedar_file)
                parts.append(cedar_file.read_text())

        self._policies_text = "\n\n".join(parts)
        self._policy_metadata, ordered_ids = _parse_policy_metadata(self._policies_text)

        # Detect duplicate @id values.
        seen: dict[str, int] = {}
        for pid in ordered_ids:
            if not pid:
                continue
            if pid in seen:
                raise ValueError(
                    f"Duplicate policy ID '{pid}' found in {policy_dir}. "
                    f"Each @id must be unique across all policy files."
                )
            seen[pid] = 1

        # Build mapping from cedarpy's positional "policyN" to real @id values.
        self._policy_index = {}
        for idx, pid in enumerate(ordered_ids):
            if pid:
                self._policy_index[f"policy{idx}"] = pid

        logger.info(
            "policies_loaded",
            count=len(self._policy_files),
            rules=len(self._policy_metadata),
            directory=str(policy_dir),
        )
