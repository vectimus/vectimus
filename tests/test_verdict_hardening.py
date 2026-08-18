"""Only an explicit ALLOW may allow, on every evaluation path.

The hook has three ways to reach a verdict -- the remote server, the local
daemon and inline evaluation -- and each one used to treat "not a deny" as
"allow".  A truncated response, a verdict string from a newer server or a
missing key would therefore let the tool call through.  These tests pin the
fail-closed behaviour on all three paths, plus the missing-source paths on
the daemon and the server.
"""

from __future__ import annotations

import json
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from vectimus.cli.hook_cmd import hook_cmd
from vectimus.engine.models import Decision, DecisionVerdict

# Verdict values that must never allow: unknown strings, wrong types and the
# absent key itself (represented by _MISSING).
_MISSING = object()
_NON_ALLOW_VERDICTS = [
    _MISSING,
    None,
    "",
    "Allow",
    "ALLOW",
    "allowed",
    "permit",
    "unknown",
    True,
    0,
    {"decision": "allow"},
]


def _run_hook(source: str, payload: dict) -> tuple[int, str]:
    runner = CliRunner()
    result = runner.invoke(hook_cmd, ["--source", source], input=json.dumps(payload))
    return result.exit_code, result.output


def _extract_json(output: str) -> dict:
    for line in output.strip().splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
    raise ValueError(f"No JSON found in output: {output!r}")


def _payload(tmp_path) -> dict:
    return {
        "tool_name": "Bash",
        "tool_input": {"command": "echo hello"},
        "hook_event_name": "PreToolUse",
        "cwd": str(tmp_path),
    }


def _response(verdict: object, **extra: object) -> dict:
    response: dict = dict(extra)
    if verdict is not _MISSING:
        response["decision"] = verdict
    return response


def _assert_denied(exit_code: int, output: str) -> dict:
    assert exit_code == 0
    inner = _extract_json(output)["hookSpecificOutput"]
    assert inner["permissionDecision"] == "deny"
    return inner


class TestServerPathVerdicts:
    """Verdicts arriving from ``VECTIMUS_SERVER_URL``."""

    @staticmethod
    def _run(tmp_path, response: dict) -> tuple[int, str]:
        with (
            patch(
                "vectimus.engine.config.VectimusConfig.get_server_url",
                return_value="http://localhost:8080",
            ),
            patch("vectimus.cli.hook_cmd._post_to_server", return_value=response),
        ):
            return _run_hook("claude-code", _payload(tmp_path))

    @pytest.mark.parametrize("verdict", _NON_ALLOW_VERDICTS)
    def test_non_allow_verdict_denies(self, verdict: object, tmp_path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        exit_code, output = self._run(tmp_path, _response(verdict))
        inner = _assert_denied(exit_code, output)
        assert "fail closed" in inner["permissionDecisionReason"]

    def test_explicit_allow_allows(self, tmp_path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        exit_code, output = self._run(tmp_path, _response(DecisionVerdict.ALLOW))
        assert exit_code == 0
        assert "permissionDecision" not in output

    def test_deny_still_denies(self, tmp_path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        exit_code, output = self._run(
            tmp_path, _response(DecisionVerdict.DENY, reason="Blocked by policy")
        )
        inner = _assert_denied(exit_code, output)
        assert inner["permissionDecisionReason"] == "Blocked by policy"

    def test_escalate_still_denies(self, tmp_path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        exit_code, output = self._run(
            tmp_path, _response(DecisionVerdict.ESCALATE, reason="Needs approval")
        )
        inner = _assert_denied(exit_code, output)
        assert "[escalate]" in inner["permissionDecisionReason"]

    def test_unrecognised_verdict_denies_in_cursor_format(self, tmp_path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        payload = {
            "command": "echo hello",
            "hook_event_name": "beforeShellExecution",
            "cwd": str(tmp_path),
        }
        with (
            patch(
                "vectimus.engine.config.VectimusConfig.get_server_url",
                return_value="http://localhost:8080",
            ),
            patch("vectimus.cli.hook_cmd._post_to_server", return_value=_response("maybe")),
        ):
            runner = CliRunner()
            result = runner.invoke(hook_cmd, ["--source", "cursor"], input=json.dumps(payload))

        assert result.exit_code == 2
        assert _extract_json(result.output)["permission"] == "deny"

    def test_deny_verdict_with_smuggled_allow_payload_denies(self, tmp_path, monkeypatch) -> None:
        """A server payload whose inner decision contradicts the deny verdict
        must not be relayed -- the deny is rebuilt locally (fail closed)."""
        monkeypatch.chdir(tmp_path)
        exit_code, output = self._run(
            tmp_path,
            _response(
                DecisionVerdict.DENY,
                reason="Blocked by policy",
                hookSpecificOutput={
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "allow",
                        "permissionDecisionReason": "looks fine",
                    }
                },
            ),
        )
        inner = _assert_denied(exit_code, output)
        assert inner["permissionDecisionReason"] == "Blocked by policy"

    @pytest.mark.parametrize(
        "hook_output",
        [
            "not a dict",
            {},
            {"hookSpecificOutput": "not a dict"},
            {"hookSpecificOutput": {"permissionDecision": "allow"}},
            {"permissionDecision": "allow"},
        ],
    )
    def test_deny_verdict_with_non_denying_payload_denies(
        self, hook_output: object, tmp_path, monkeypatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        exit_code, output = self._run(
            tmp_path,
            _response(
                DecisionVerdict.DENY, reason="Blocked by policy", hookSpecificOutput=hook_output
            ),
        )
        inner = _assert_denied(exit_code, output)
        assert inner["permissionDecisionReason"] == "Blocked by policy"

    def test_deny_verdict_with_consistent_payload_is_relayed(self, tmp_path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        server_payload = {
            "hookSpecificOutput": {
                "hookEventName": "PreToolUse",
                "permissionDecision": "deny",
                "permissionDecisionReason": "Server says no",
            }
        }
        exit_code, output = self._run(
            tmp_path, _response(DecisionVerdict.DENY, hookSpecificOutput=server_payload)
        )
        assert exit_code == 0
        inner = _extract_json(output)["hookSpecificOutput"]
        assert inner["permissionDecision"] == "deny"
        assert inner["permissionDecisionReason"] == "Server says no"


class TestDaemonPathVerdicts:
    """Verdicts arriving from the local evaluation daemon."""

    @staticmethod
    def _run(tmp_path, response: dict) -> tuple[int, str]:
        with patch("vectimus.cli.daemon_client.daemon_evaluate", return_value=response):
            return _run_hook("claude-code", _payload(tmp_path))

    @pytest.mark.parametrize("verdict", _NON_ALLOW_VERDICTS)
    def test_non_allow_verdict_denies(self, verdict: object, tmp_path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        exit_code, output = self._run(tmp_path, _response(verdict))
        inner = _assert_denied(exit_code, output)
        assert "fail closed" in inner["permissionDecisionReason"]

    def test_explicit_allow_allows(self, tmp_path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        exit_code, output = self._run(tmp_path, _response(DecisionVerdict.ALLOW))
        assert exit_code == 0
        assert "permissionDecision" not in output

    def test_deny_still_denies(self, tmp_path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        exit_code, output = self._run(
            tmp_path,
            _response(DecisionVerdict.DENY, reason="Blocked by policy", matched_policy_ids=["p1"]),
        )
        inner = _assert_denied(exit_code, output)
        assert "Blocked by policy" in inner["permissionDecisionReason"]

    def test_escalate_still_denies(self, tmp_path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        exit_code, output = self._run(
            tmp_path, _response(DecisionVerdict.ESCALATE, reason="Needs approval")
        )
        inner = _assert_denied(exit_code, output)
        assert "[escalate]" in inner["permissionDecisionReason"]


class TestInlinePathVerdicts:
    """Verdicts produced by inline evaluation when no daemon is available."""

    @staticmethod
    def _run(tmp_path, decision: Decision) -> tuple[int, str]:
        with (
            patch("vectimus.cli.daemon_client.daemon_evaluate", return_value=None),
            patch("vectimus.cli.hook_cmd.PolicyEngine") as mock_engine_cls,
        ):
            mock_engine_cls.return_value.evaluate.return_value = decision
            return _run_hook("claude-code", _payload(tmp_path))

    @pytest.mark.parametrize("verdict", ["", "Allow", "allowed", "unknown"])
    def test_non_allow_verdict_denies(self, verdict: str, tmp_path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        exit_code, output = self._run(tmp_path, Decision(decision=verdict))
        inner = _assert_denied(exit_code, output)
        assert "fail closed" in inner["permissionDecisionReason"]

    def test_explicit_allow_allows(self, tmp_path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        exit_code, output = self._run(tmp_path, Decision(decision=DecisionVerdict.ALLOW))
        assert exit_code == 0
        assert "permissionDecision" not in output

    def test_deny_still_denies(self, tmp_path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        exit_code, output = self._run(
            tmp_path, Decision(decision=DecisionVerdict.DENY, reason="Blocked by policy")
        )
        inner = _assert_denied(exit_code, output)
        assert "Blocked by policy" in inner["permissionDecisionReason"]


class TestUnknownSource:
    """An unknown or missing source must never be normalised as a guess."""

    def test_hook_rejects_unregistered_source(self) -> None:
        runner = CliRunner()
        result = runner.invoke(hook_cmd, ["--source", "not-a-tool"], input="{}")
        assert result.exit_code != 0

    def test_daemon_denies_missing_source(self, tmp_path) -> None:
        from vectimus.engine.daemon import DaemonServer

        result = DaemonServer()._evaluate({"payload": _payload(tmp_path), "cwd": str(tmp_path)})
        assert result["decision"] == DecisionVerdict.DENY
        assert "Missing source" in result["reason"]

    @pytest.mark.parametrize("source", ["", None, 123, ["claude-code"]])
    def test_daemon_denies_non_string_source(self, source: object, tmp_path) -> None:
        from vectimus.engine.daemon import DaemonServer

        result = DaemonServer()._evaluate(
            {"source": source, "payload": _payload(tmp_path), "cwd": str(tmp_path)}
        )
        assert result["decision"] == DecisionVerdict.DENY

    def test_daemon_denies_unregistered_source(self, tmp_path) -> None:
        from vectimus.engine.daemon import DaemonServer

        result = DaemonServer()._evaluate(
            {"source": "not-a-tool", "payload": _payload(tmp_path), "cwd": str(tmp_path)}
        )
        assert result["decision"] == DecisionVerdict.DENY
        assert "Normalisation error" in result["reason"]

    async def test_server_denies_missing_source_header(self) -> None:
        pytest.importorskip("fastapi", reason="requires vectimus[server]")
        httpx = pytest.importorskip("httpx", reason="requires httpx (dev dependency)")

        from vectimus.server.app import create_app
        from vectimus.server.config import ServerConfig

        transport = httpx.ASGITransport(app=create_app(ServerConfig()))
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            response = await client.post(
                "/evaluate",
                json={"tool_name": "Bash", "tool_input": {"command": "echo hello"}},
            )

        assert response.status_code == 200
        assert response.json()["decision"] == DecisionVerdict.DENY
