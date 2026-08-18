"""Tests for the Pi adapter, extension install and hook wiring.

The adapter is deliberately stricter than the older ones, so most of these
tests assert that something is *refused*: everything Vectimus cannot map with
confidence has to end up blocked rather than allowed.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from vectimus.adapters.pi import PI_TOOL_MAP, PiNormalisationError
from vectimus.cli.hook_cmd import VALID_SOURCES, hook_cmd
from vectimus.cli.pi_extension import (
    EXTENSION_VERSION,
    SHIPPED_EXTENSION_DIGESTS,
    InstallStatus,
    global_extension_path,
    install_extension,
    is_managed,
    marker_version,
    project_extension_path,
    remove_extension,
    template_text,
)
from vectimus.engine.evaluator import PolicyEngine
from vectimus.engine.loader import PolicyLoader
from vectimus.engine.models import ActionType, DecisionVerdict, EventType
from vectimus.engine.normaliser import normalise


def _payload(tool_name: str, tool_input: dict | None = None, **extra) -> dict:
    payload = {"tool_name": tool_name, "tool_input": tool_input or {}}
    payload.setdefault("cwd", "/proj")
    payload.update(extra)
    return payload


def _run_hook(payload: dict | str) -> tuple[int, str]:
    runner = CliRunner()
    stdin = payload if isinstance(payload, str) else json.dumps(payload)
    result = runner.invoke(hook_cmd, ["--source", "pi"], input=stdin)
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


# The vendored packs under ./policies are what this change edits.  A default
# PolicyLoader() also layers in a downloaded ~/.vectimus/policy-cache when one
# exists, and the cache takes precedence -- so on a machine with a stale cache it
# would be evaluated instead of the packs under test.  Tests that assert on the
# newly-added companion patterns therefore load the vendored packs explicitly.
# (The same companions must land upstream/API for a synced cache to gain them --
# see the sync note accompanying this change.)
_BUNDLED_POLICIES = Path(__file__).resolve().parents[1] / "policies"


def _bundled_engine(*, extra_disabled_rules: set[str] | None = None) -> PolicyEngine:
    return PolicyEngine(
        loader=PolicyLoader(
            policy_dirs=[str(_BUNDLED_POLICIES)],
            extra_disabled_rules=extra_disabled_rules or set(),
        )
    )


@pytest.fixture()
def sandbox(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect Pi's config dir and cwd into tmp_path.

    Without this a test would read, and worse write, the developer's real
    ``~/.pi``.
    """
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.chdir(project)
    return tmp_path


class TestPiNormaliser:
    """Payloads the adapter accepts, and what it extracts from them."""

    def test_bash_is_a_shell_command(self) -> None:
        event = normalise(
            _payload(
                "bash",
                {"command": "ls -la"},
                cwd="/tmp/project",
                session_id="ses_1",
                call_id="call_1",
                hook_event_name="PreToolUse",
            ),
            "pi",
        )
        assert event.action.action_type == ActionType.SHELL_COMMAND
        assert event.action.command == "ls -la"
        assert event.action.raw_tool_name == "bash"
        assert event.source.tool == "pi"
        assert event.source.session_id == "ses_1"
        assert event.event_id == "call_1"
        assert event.context.cwd == "/tmp/project"
        assert event.event_type == EventType.PRE_ACTION

    def test_bash_refines_to_a_more_specific_action(self) -> None:
        event = normalise(_payload("bash", {"command": "terraform destroy"}), "pi")
        assert event.action.action_type == ActionType.INFRASTRUCTURE

    def test_bash_redirect_becomes_a_file_write(self) -> None:
        event = normalise(_payload("bash", {"command": "echo x > /etc/hosts"}), "pi")
        assert event.action.action_type == ActionType.FILE_WRITE
        assert event.action.file_path == "/etc/hosts"

    def test_read_extracts_the_file_path(self) -> None:
        event = normalise(_payload("read", {"path": "/etc/passwd"}), "pi")
        assert event.action.action_type == ActionType.FILE_READ
        assert event.action.file_path == "/etc/passwd"

    def test_write_carries_content_for_inspection(self) -> None:
        event = normalise(
            _payload("write", {"path": "/srv/app.env", "content": "TOKEN=abc"}),
            "pi",
        )
        assert event.action.action_type == ActionType.FILE_WRITE
        assert event.action.file_path == "/srv/app.env"
        assert event.action.file_content == "TOKEN=abc"

    def test_edit_joins_the_replacement_text(self) -> None:
        """`newText` is what enters the file, so it is what content rules see."""
        event = normalise(
            _payload(
                "edit",
                {
                    "path": "/srv/app.py",
                    "edits": [
                        {"oldText": "a", "newText": "first"},
                        {"oldText": "b", "newText": "second"},
                    ],
                },
            ),
            "pi",
        )
        assert event.action.action_type == ActionType.FILE_WRITE
        assert event.action.file_path == "/srv/app.py"
        assert event.action.file_content == "first\nsecond"

    def test_edit_accepts_the_legacy_single_replacement_form(self) -> None:
        """Pi's own prepareArguments folds this into `edits`, so it is valid."""
        event = normalise(
            _payload("edit", {"path": "/srv/app.py", "oldText": "a", "newText": "b"}),
            "pi",
        )
        assert event.action.file_content == "b"

    def test_edit_keeps_the_match_text_out_of_the_content(self) -> None:
        event = normalise(
            _payload(
                "edit",
                {"path": "/srv/app.py", "edits": [{"oldText": "SECRET_MARKER", "newText": "x"}]},
            ),
            "pi",
        )
        assert event.action.file_content == "x"
        assert event.action.raw_input["edits"][0]["oldText"] == "SECRET_MARKER"

    @pytest.mark.parametrize("tool_name", ["grep", "find", "ls"])
    def test_search_tools_are_reads_and_their_path_is_optional(self, tool_name: str) -> None:
        """Their `path` defaults to the working directory in Pi's own schema."""
        args = {} if tool_name == "ls" else {"pattern": "x"}
        event = normalise(_payload(tool_name, args), "pi")
        assert event.action.action_type == ActionType.FILE_READ
        assert event.action.file_path is None

    @pytest.mark.parametrize("tool_name", ["grep", "find", "ls"])
    def test_search_tools_extract_a_path_when_given_one(self, tool_name: str) -> None:
        args = {"path": "/etc"} if tool_name == "ls" else {"pattern": "x", "path": "/etc"}
        event = normalise(_payload(tool_name, args), "pi")
        assert event.action.file_path == "/etc"

    def test_every_mapped_tool_normalises(self) -> None:
        """No row in the inventory maps to a tool the adapter then refuses."""
        minimal = {
            "bash": {"command": "true"},
            "read": {"path": "/f"},
            "write": {"path": "/f", "content": "c"},
            "edit": {"path": "/f", "edits": [{"oldText": "a", "newText": "b"}]},
            "grep": {"pattern": "p"},
            "find": {"pattern": "p"},
            "ls": {},
        }
        assert set(minimal) == set(PI_TOOL_MAP)
        for tool_name, args in minimal.items():
            event = normalise(_payload(tool_name, args), "pi")
            assert event.action.raw_tool_name == tool_name


class TestPiRelativePaths:
    """Pi sends model-written paths, so relative ones are the normal case."""

    def test_a_relative_path_is_resolved_against_cwd(self) -> None:
        event = normalise(_payload("read", {"path": "notes.txt"}, cwd="/proj/sub"), "pi")
        assert event.action.file_path == "/proj/sub/notes.txt"

    def test_traversal_out_of_the_project_resolves_to_the_real_target(self) -> None:
        """The point of resolving: a rule on `/Users/*/.ssh/*` must still match.

        Left relative, `../.ssh/id_rsa` matches no absolute policy pattern and
        the read would be allowed on a technicality.
        """
        event = normalise(
            _payload("read", {"path": "../.ssh/id_rsa"}, cwd="/Users/dev/proj"),
            "pi",
        )
        assert event.action.file_path == "/Users/dev/.ssh/id_rsa"

    def test_an_absolute_path_is_left_alone(self) -> None:
        event = normalise(_payload("read", {"path": "/etc/passwd"}, cwd="/proj"), "pi")
        assert event.action.file_path == "/etc/passwd"

    def test_a_relative_path_without_cwd_is_refused(self) -> None:
        payload = {"tool_name": "read", "tool_input": {"path": "notes.txt"}}
        with pytest.raises(PiNormalisationError, match="cannot be matched against policy paths"):
            normalise(payload, "pi")

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            (r"C:\Users\dev\.ssh\id_rsa", "c:/users/dev/.ssh/id_rsa"),
            (r"\\server\share\secrets.txt", "//server/share/secrets.txt"),
        ],
    )
    def test_a_windows_path_is_canonicalised_not_merely_recognised(
        self, raw: str, expected: str
    ) -> None:
        """Recognising it as absolute is only half of it.

        `posixpath.isabs(r"C:\\...")` is False, so left to POSIX rules the
        path would be joined onto the cwd.  But passing the backslashes
        straight through fails open just as surely: a rule guarding
        `*/.ssh/*` matches none of them, so a Windows session judged by a
        POSIX evaluator would come back ALLOW.
        """
        event = normalise(_payload("read", {"path": raw}, cwd=r"C:\proj"), "pi")
        assert event.action.file_path == expected

    def test_windows_traversal_is_collapsed_before_the_separators_go(self) -> None:
        """`posixpath` cannot see `..\\` as traversal, so `ntpath` does it here."""
        event = normalise(
            _payload("read", {"path": r"C:\proj\..\Users\dev\.ssh\id_rsa"}, cwd=r"C:\proj"),
            "pi",
        )
        assert event.action.file_path == "c:/users/dev/.ssh/id_rsa"

    def test_a_windows_relative_path_joins_with_the_windows_cwd(self) -> None:
        """Joined the Windows way, then canonicalised like any Windows path."""
        event = normalise(_payload("read", {"path": r"sub\notes.txt"}, cwd=r"C:\proj"), "pi")
        assert event.action.file_path == "c:/proj/sub/notes.txt"

    def test_a_bash_redirect_to_a_relative_path_is_resolved_too(self) -> None:
        event = normalise(_payload("bash", {"command": "echo x > out.txt"}, cwd="/proj"), "pi")
        assert event.action.file_path == "/proj/out.txt"


class TestPiWindowsPathsReachACedarDeny:
    """Windows-shaped credential reads must land on a real Cedar DENY.

    A string-shape assertion alone proves nothing about enforcement: a
    canonicalisation that silently regressed -- backslashes left in, case
    left folded the wrong way -- could still satisfy it while the path sailed
    past every rule.  So these normalise the event and run it through the
    engine, and assert the SSH-key rule is what blocks it.
    """

    RULE = "vectimus-secrets-002"

    @pytest.mark.parametrize(
        ("raw", "cwd"),
        [
            # A plain drive-letter path: the baseline the others are variants of.
            (r"C:\Users\dev\.ssh\id_rsa", r"C:\Users\dev\proj"),
            # `.SSH`: Windows is case-insensitive, and the rule is lowercase, so
            # the fold is the only thing making this match.
            (r"C:\Users\dev\.SSH\id_rsa", r"C:\Users\dev\proj"),
            # A mixed-separator UNC path -- absolute to posixpath, so a
            # POSIX-first return would have handed it on with backslashes still
            # in it, matching nothing.
            ("//server\\share\\.ssh\\id_rsa", r"C:\proj"),
            # A clean UNC path.
            ("\\\\server\\share\\.ssh\\id_rsa", r"C:\proj"),
        ],
    )
    def test_a_windows_ssh_key_read_is_denied(self, raw: str, cwd: str) -> None:
        event = normalise(_payload("read", {"path": raw}, cwd=cwd), "pi")
        decision = PolicyEngine(loader=PolicyLoader()).evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert self.RULE in decision.matched_policy_ids

    def test_the_deny_comes_from_the_ssh_rule_and_not_a_blanket_one(self) -> None:
        """Anti-vacuity: disable the SSH-key rule and the read must be allowed.

        Without this, the denies above would keep passing if `vectimus-secrets-002`
        were deleted and some unrelated catch-all happened to block instead --
        they would say nothing about whether the canonicalisation actually made
        the path reach that rule.
        """
        event = normalise(
            _payload("read", {"path": r"C:\Users\dev\.SSH\id_rsa"}, cwd=r"C:\Users\dev\proj"),
            "pi",
        )
        engine = PolicyEngine(loader=PolicyLoader(extra_disabled_rules={self.RULE}))
        assert engine.evaluate(event).decision == DecisionVerdict.ALLOW, (
            f"with {self.RULE} disabled the Windows SSH-key read must be allowed, "
            "otherwise the denies above prove nothing about that rule"
        )

    @pytest.mark.parametrize(
        ("raw", "why"),
        [
            (r"C:\Users\dev\.ssh.\id_rsa", "trailing dot Windows strips"),
            (r"C:\Users\dev\.ssh \id_rsa", "trailing space Windows strips"),
            (r"\\.\C:\Users\dev\.ssh\id_rsa", "device namespace"),
            (r"\\?\C:\Users\dev\.ssh\id_rsa", "extended-length device namespace"),
            (r"\Users\dev\.ssh\id_rsa", "root-relative, drive dropped"),
            (r"C:\PROGRA~1\.ssh\id_rsa", "8.3 short-name alias"),
        ],
    )
    def test_an_uncanonicalisable_windows_shape_is_refused(self, raw: str, why: str) -> None:
        """Fail closed on a shape that cannot be reduced to one matchable path.

        Each of these would otherwise reach Cedar as a path matching none of
        the SSH rules it should -- a fail-open.  The adapter refuses instead,
        and the hook turns that refusal into a deny.
        """
        with pytest.raises(PiNormalisationError):
            normalise(_payload("read", {"path": raw}, cwd=r"C:\proj"), "pi")


class TestPackPatternsMatchCanonicalisedWindowsPaths:
    """Folding both sides: a canonicalised Windows write still hits its rule.

    Cedar `like` is case-sensitive, and several packs spell their path patterns
    the way a Windows path used to arrive -- uppercase (`*CLAUDE.md`) or
    backslash-separated (`*\\Windows\\System32\\*`).  The Pi adapter lowercases
    and forward-slashes Windows paths for a POSIX evaluator, so those native
    spellings alone would stop matching: lowercasing the path does not merely let
    new rules match, it stops the native ones matching at all, and a write the
    pack denied before canonicalisation would be allowed after it.

    The packs now carry a lowercase, forward-slash companion beside each such
    pattern.  These tests prove the companion closes the gap -- a Windows write
    the pack denies in its native spelling is still denied once canonicalised --
    and, via per-case anti-vacuity, that the *named* rule's companion is what
    denies it rather than some blanket rule.  A separate control proves the
    native spelling still denies, so the companion was added, not swapped in.

    `.ssh` (TestPiWindowsPathsReachACedarDeny) is already lowercase/forward-slash
    and survives the fold untouched; these are the families that did not.
    """

    # (Windows path, cwd, the rule whose companion must catch the canonical form).
    # Every path canonicalises to lowercase/forward-slash and must reach `rule`.
    CASES = [
        (r"C:\proj\CLAUDE.md", r"C:\proj", "vectimus-fileint-011"),
        (r"C:\proj\AGENTS.md", r"C:\proj", "vectimus-fileint-011"),
        (r"C:\proj\Cargo.lock", r"C:\proj", "vectimus-supchain-005"),
        (r"C:\proj\Pipfile.lock", r"C:\proj", "vectimus-supchain-005"),
        (r"C:\proj\Gemfile.lock", r"C:\proj", "vectimus-supchain-005"),
        (r"C:\Windows\System32\drv.sys", r"C:\proj", "vectimus-fileint-009"),
        (r"C:\Windows\SysWOW64\x.dll", r"C:\proj", "vectimus-fileint-009"),
        (r"C:\prod\Dockerfile", r"C:\proj", "vectimus-fileint-002"),
    ]

    # The native (un-canonicalised) spelling each companion sits beside.  POSIX
    # paths are not folded, and native Windows spellings are injected directly
    # (the adapter would fold them), so either way the *original* pattern is what
    # is exercised -- proving the companion was added alongside it, not in place
    # of it.
    NATIVE_CASES = [
        ("/proj/CLAUDE.md", "vectimus-fileint-011"),
        ("/proj/AGENTS.md", "vectimus-fileint-011"),
        ("/proj/Cargo.lock", "vectimus-supchain-005"),
        ("/proj/Pipfile.lock", "vectimus-supchain-005"),
        ("/proj/Gemfile.lock", "vectimus-supchain-005"),
        (r"C:\Windows\System32\drv.sys", "vectimus-fileint-009"),
        (r"C:\Windows\SysWOW64\x.dll", "vectimus-fileint-009"),
        ("/proj/prod/Dockerfile", "vectimus-fileint-002"),
    ]

    @staticmethod
    def _write_event(raw: str, cwd: str):
        return normalise(_payload("write", {"path": raw, "content": "x"}, cwd=cwd), "pi")

    @pytest.mark.parametrize(("raw", "cwd", "rule"), CASES)
    def test_a_canonicalised_windows_write_is_denied_by_the_companion(
        self, raw: str, cwd: str, rule: str
    ) -> None:
        """The write goes through the adapter (which canonicalises the path) and
        the engine, and the rule that owns the companion is what denies it."""
        decision = _bundled_engine().evaluate(self._write_event(raw, cwd))
        assert decision.decision == DecisionVerdict.DENY
        assert rule in decision.matched_policy_ids, (
            f"canonicalised {raw!r} must be denied by {rule}'s companion pattern"
        )

    @pytest.mark.parametrize(("raw", "cwd", "rule"), CASES)
    def test_the_deny_comes_from_that_rule_and_not_a_blanket_one(
        self, raw: str, cwd: str, rule: str
    ) -> None:
        """Anti-vacuity: disable the owning rule and the write must be allowed.

        Without this the denies above would keep passing if the companion were
        deleted and some unrelated catch-all blocked instead -- they would say
        nothing about whether the companion actually catches the canonical path.
        """
        engine = _bundled_engine(extra_disabled_rules={rule})
        assert engine.evaluate(self._write_event(raw, cwd)).decision == DecisionVerdict.ALLOW, (
            f"with {rule} disabled the canonicalised Windows write of {raw!r} must be "
            "allowed, otherwise the deny proves nothing about that rule's companion"
        )

    @pytest.mark.parametrize(("raw", "rule"), NATIVE_CASES)
    def test_the_native_spelling_still_denies(self, raw: str, rule: str) -> None:
        """Control: adding a companion must not disturb the pattern it sits beside.

        The path is injected directly onto the event (POSIX paths are not folded;
        native Windows spellings the adapter would fold are set explicitly), so the
        original uppercase/backslash pattern is what has to match.
        """
        event = self._write_event("/proj/x", "/proj")
        event.action.file_path = raw
        decision = _bundled_engine().evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert rule in decision.matched_policy_ids, (
            f"native spelling {raw!r} must still be denied by {rule}"
        )


class TestPiNormaliserRefusals:
    """Everything the adapter refuses to guess at."""

    def test_an_unknown_tool_is_refused(self) -> None:
        with pytest.raises(PiNormalisationError, match="Unknown Pi tool 'mystery_tool'"):
            normalise(_payload("mystery_tool", {"x": 1}), "pi")

    def test_the_refusal_points_at_the_inventory(self) -> None:
        with pytest.raises(PiNormalisationError, match="docs/pi-tool-inventory.md"):
            normalise(_payload("mystery_tool", {}), "pi")

    def test_a_tool_from_another_extension_is_refused(self) -> None:
        """Custom tools arrive with an arbitrary name and no known schema."""
        with pytest.raises(PiNormalisationError):
            normalise(_payload("my_custom_tool", {"action": "delete"}), "pi")

    @pytest.mark.parametrize("tool_name", ["", "   ", None, 42])
    def test_a_missing_tool_name_is_refused(self, tool_name: object) -> None:
        with pytest.raises(PiNormalisationError, match="no tool name"):
            normalise({"tool_name": tool_name, "tool_input": {}, "cwd": "/p"}, "pi")

    @pytest.mark.parametrize("tool_input", ["a string", 42, ["a", "list"]])
    def test_a_non_object_tool_input_is_refused(self, tool_input: object) -> None:
        with pytest.raises(PiNormalisationError, match="non-object tool_input"):
            normalise({"tool_name": "bash", "tool_input": tool_input, "cwd": "/p"}, "pi")

    def test_an_unmapped_tool_never_falls_back_to_shell_command(self) -> None:
        """A fallback would evaluate the call against the wrong rules."""
        with pytest.raises(PiNormalisationError):
            normalise(_payload("run_command", {"command": "rm -rf /"}), "pi")

    @pytest.mark.parametrize(
        ("tool_name", "tool_input"),
        [
            ("bash", {}),
            ("bash", {"command": ""}),
            ("bash", {"command": "   "}),
            ("bash", {"command": None}),
            ("read", {}),
            ("write", {"path": "/f"}),
            ("write", {"content": "c"}),
            ("edit", {"path": "/f"}),
            ("grep", {}),
            ("find", {}),
        ],
    )
    def test_a_missing_required_argument_is_refused(self, tool_name: str, tool_input: dict) -> None:
        with pytest.raises(PiNormalisationError):
            normalise(_payload(tool_name, tool_input), "pi")

    @pytest.mark.parametrize(
        "edits",
        [
            [],
            "not a list",
            ["not an object"],
            [{"oldText": "a"}],
            [{"oldText": "a", "newText": 42}],
            [{"oldText": "a", "newText": "ok"}, {"oldText": "b"}],
        ],
    )
    def test_a_malformed_edits_list_is_refused(self, edits: object) -> None:
        """An unreadable replacement list means the content cannot be inspected."""
        with pytest.raises(PiNormalisationError):
            normalise(_payload("edit", {"path": "/f", "edits": edits}), "pi")

    def test_edit_with_no_replacements_at_all_is_refused(self) -> None:
        """Neither `edits` nor the legacy pair means nothing to inspect."""
        with pytest.raises(PiNormalisationError, match="non-empty 'edits' list"):
            normalise(_payload("edit", {"path": "/f"}), "pi")

    def test_an_empty_payload_is_refused(self) -> None:
        with pytest.raises(PiNormalisationError):
            normalise({}, "pi")


class TestPiHookCommand:
    """End-to-end through ``vectimus hook --source pi``."""

    @pytest.fixture(autouse=True)
    def _no_daemon(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Evaluate inline.

        A daemon left running by an older install answers these calls
        otherwise, which makes the result depend on the developer's machine.
        """
        monkeypatch.setenv("VECTIMUS_NO_DAEMON", "1")

    def test_pi_is_a_valid_source(self) -> None:
        assert "pi" in VALID_SOURCES

    def test_safe_command_allows_with_no_verdict_on_stdout(self, tmp_path, monkeypatch) -> None:
        """An allow prints nothing; the extension treats any output as a block.

        CliRunner mixes stderr into ``output``, so this asserts no JSON verdict
        rather than a wholly empty stream.
        """
        monkeypatch.chdir(tmp_path)
        exit_code, output = _run_hook(
            _payload("bash", {"command": "echo hello"}, cwd=str(tmp_path))
        )
        assert exit_code == 0
        assert '"decision"' not in output
        assert not any(line.strip().startswith("{") for line in output.splitlines())

    def test_destructive_command_denies(self, tmp_path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        exit_code, output = _run_hook(_payload("bash", {"command": "rm -rf /"}, cwd=str(tmp_path)))
        assert exit_code == 0
        parsed = _extract_json(output)
        assert parsed["decision"] == "deny"
        assert "reason" in parsed

    def test_unknown_tool_denies_through_the_hook(self, tmp_path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        exit_code, output = _run_hook(_payload("mystery_tool", {"x": 1}, cwd=str(tmp_path)))
        assert exit_code == 0
        parsed = _extract_json(output)
        assert parsed["decision"] == "deny"
        # The agent needs to know which tool was refused, not just that
        # something failed to normalise.
        assert "mystery_tool" in parsed["reason"]
        assert "docs/pi-tool-inventory.md" in parsed["reason"]

    def test_missing_argument_names_the_argument(self, tmp_path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        exit_code, output = _run_hook(_payload("bash", {}, cwd=str(tmp_path)))
        assert exit_code == 0
        assert "'command'" in _extract_json(output)["reason"]

    def test_invalid_json_denies(self) -> None:
        exit_code, output = _run_hook("{not json")
        assert exit_code == 0
        assert _extract_json(output)["decision"] == "deny"

    def test_escalate_is_a_hard_deny(self, tmp_path, monkeypatch) -> None:
        """Pi has no ask channel, so escalate blocks (issue #53)."""
        monkeypatch.chdir(tmp_path)
        from unittest.mock import patch

        from vectimus.engine.models import Decision

        with (
            patch("vectimus.cli.daemon_client.daemon_evaluate", return_value=None),
            patch("vectimus.cli.hook_cmd.PolicyEngine") as mock_engine_cls,
        ):
            mock_engine_cls.return_value.evaluate.return_value = Decision(
                decision=DecisionVerdict.ESCALATE, reason="Requires human approval"
            )
            exit_code, output = _run_hook(
                _payload("bash", {"command": "echo test"}, cwd=str(tmp_path))
            )

        assert exit_code == 0
        parsed = _extract_json(output)
        assert parsed["decision"] == "deny"
        assert "[escalate]" in parsed["reason"]


class TestPiIncidentRegression:
    """The 2026-08-17 recursive-delete incident, as Pi would send it."""

    INCIDENT_COMMAND = "rm -rf ~/Development"

    def _event(self):
        return normalise(
            _payload("bash", {"command": self.INCIDENT_COMMAND}, cwd="/Users/dev/Development"),
            "pi",
        )

    def test_incident_command_is_denied(self) -> None:
        decision = PolicyEngine(loader=PolicyLoader()).evaluate(self._event())
        assert decision.decision == DecisionVerdict.DENY
        assert "vectimus-destruct-001" in decision.matched_policy_ids

    def test_the_deny_comes_from_that_rule_and_not_a_blanket_one(self) -> None:
        """Guards against a vacuous pass: disable the rule and it must allow.

        Without this, the test above would keep passing if destruct-001 were
        deleted and some unrelated catch-all happened to deny instead.
        """
        engine = PolicyEngine(loader=PolicyLoader(extra_disabled_rules={"vectimus-destruct-001"}))
        decision = engine.evaluate(self._event())
        assert decision.decision == DecisionVerdict.ALLOW, (
            "with vectimus-destruct-001 disabled the incident command must be allowed, "
            "otherwise the deny above proves nothing about that rule"
        )


class TestExtensionTemplatePackaging:
    """The template ships as package data and its digest is pinned."""

    def test_template_is_readable_from_the_installed_package(self) -> None:
        assert "VECTIMUS-MANAGED" in template_text()

    def test_template_declares_the_current_extension_version(self) -> None:
        assert marker_version(template_text()) == EXTENSION_VERSION

    def test_pinned_digest_matches_the_shipped_template(self) -> None:
        """Editing the template without bumping the version fails here.

        The digest is what tells an untouched managed install from one a user
        edited, so a stale pin would make `vectimus init` refuse to update
        installs it wrote itself.
        """
        digest = hashlib.sha256(template_text().encode("utf-8")).hexdigest()
        assert digest == SHIPPED_EXTENSION_DIGESTS[EXTENSION_VERSION]

    def test_no_digest_entry_was_dropped(self) -> None:
        assert set(SHIPPED_EXTENSION_DIGESTS) == set(range(1, EXTENSION_VERSION + 1))

    def test_the_template_subscribes_to_the_tool_call_event(self) -> None:
        """Pi's blocking hook is `tool_call`; any other event guards nothing."""
        assert 'pi.on("tool_call"' in template_text()


class TestExtensionInstall:
    """`vectimus init` owns exactly one marked file per scope, and nothing else."""

    def test_installs_globally_by_default(self, sandbox: Path) -> None:
        result = install_extension(global_extension_path())
        assert result.status == InstallStatus.INSTALLED
        assert global_extension_path().exists()
        assert is_managed(global_extension_path())

    def test_the_global_path_has_the_agent_segment(self, sandbox: Path) -> None:
        """`~/.pi/extensions/` is not scanned; `~/.pi/agent/extensions/` is."""
        assert global_extension_path() == sandbox / ".pi" / "agent" / "extensions" / "vectimus.ts"

    def test_the_project_path_has_no_agent_segment(self, sandbox: Path) -> None:
        assert project_extension_path() == Path.cwd() / ".pi" / "extensions" / "vectimus.ts"

    def test_installing_twice_is_a_no_op(self, sandbox: Path) -> None:
        install_extension(global_extension_path())
        result = install_extension(global_extension_path())
        assert result.status == InstallStatus.UNCHANGED

    def test_it_refuses_a_file_it_did_not_write(self, sandbox: Path) -> None:
        path = global_extension_path()
        path.parent.mkdir(parents=True)
        path.write_text("// someone else's extension\n")
        result = install_extension(path)
        assert result.status == InstallStatus.REFUSED_UNMANAGED
        assert path.read_text() == "// someone else's extension\n"

    def test_it_refuses_an_edited_managed_file(self, sandbox: Path) -> None:
        """Silently reverting a change to a security control is worse than stale."""
        path = global_extension_path()
        install_extension(path)
        edited = path.read_text() + "\n// a human changed this\n"
        path.write_text(edited)
        result = install_extension(path)
        assert result.status == InstallStatus.REFUSED_MODIFIED
        assert path.read_text() == edited

    def test_it_refuses_a_newer_version_than_it_ships(self, sandbox: Path) -> None:
        path = global_extension_path()
        path.parent.mkdir(parents=True)
        path.write_text(
            template_text().replace(
                f"extension-version: {EXTENSION_VERSION}",
                f"extension-version: {EXTENSION_VERSION + 99}",
            )
        )
        assert install_extension(path).status == InstallStatus.REFUSED_NEWER

    def test_it_leaves_no_temp_file_behind(self, sandbox: Path) -> None:
        path = global_extension_path()
        install_extension(path)
        assert [p.name for p in path.parent.iterdir()] == ["vectimus.ts"]

    def test_global_and_project_installs_coexist(self, sandbox: Path) -> None:
        """Pi's extension directories are a union, not a fallback chain."""
        install_extension(global_extension_path())
        install_extension(project_extension_path())
        assert global_extension_path().exists()
        assert project_extension_path().exists()


class TestExtensionRemove:
    """`vectimus remove` deletes only what it wrote."""

    def test_it_removes_a_managed_file(self, sandbox: Path) -> None:
        path = global_extension_path()
        install_extension(path)
        assert remove_extension(path) is True
        assert not path.exists()

    def test_it_leaves_an_unmanaged_file_alone(self, sandbox: Path) -> None:
        path = global_extension_path()
        path.parent.mkdir(parents=True)
        path.write_text("// not ours\n")
        assert remove_extension(path) is False
        assert path.exists()

    def test_it_tidies_the_empty_extensions_directory(self, sandbox: Path) -> None:
        path = global_extension_path()
        install_extension(path)
        remove_extension(path)
        assert not path.parent.exists()
        # Pi's own config directory is not ours to delete.
        assert path.parent.parent.exists()

    def test_it_keeps_a_directory_that_holds_other_extensions(self, sandbox: Path) -> None:
        path = global_extension_path()
        install_extension(path)
        neighbour = path.parent / "someone-elses.ts"
        neighbour.write_text("// another extension\n")
        remove_extension(path)
        assert neighbour.exists()


class TestInitAndRemoveCommands:
    """The CLI surface, with Pi detected."""

    @pytest.fixture(autouse=True)
    def _detected(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Report Pi as present and every other tool as absent."""
        from vectimus.cli import detect as detect_mod
        from vectimus.cli.detect import (
            DetectionMethod,
            DetectionReport,
            ToolDetectionResult,
            ToolName,
        )

        def fake_detect_all() -> DetectionReport:
            report = DetectionReport()
            for tool in ToolName:
                found = tool == ToolName.PI
                report.results[tool] = ToolDetectionResult(
                    tool=tool,
                    found=found,
                    method=DetectionMethod.PATH if found else None,
                    executable_path="/usr/local/bin/pi" if found else None,
                )
            return report

        monkeypatch.setattr(detect_mod, "detect_all", fake_detect_all)
        monkeypatch.setattr("vectimus.cli.init_cmd.detect_all", fake_detect_all)
        monkeypatch.setattr("vectimus.cli.remove_cmd.detect_all", fake_detect_all)

    def test_init_installs_the_extension_globally(self, sandbox: Path) -> None:
        from vectimus.cli.init_cmd import init_cmd

        result = CliRunner().invoke(init_cmd, ["--ci"])
        assert result.exit_code == 0, result.output
        assert global_extension_path().exists()
        assert not project_extension_path().exists()

    def test_init_project_installs_into_the_project(self, sandbox: Path) -> None:
        from vectimus.cli.init_cmd import init_cmd

        result = CliRunner().invoke(init_cmd, ["--ci", "--project"])
        assert result.exit_code == 0, result.output
        assert project_extension_path().exists()
        assert not global_extension_path().exists()

    def test_init_reports_a_refusal_rather_than_claiming_success(self, sandbox: Path) -> None:
        """A refused install must not be counted as a configured tool."""
        from vectimus.cli.init_cmd import init_cmd

        path = global_extension_path()
        path.parent.mkdir(parents=True)
        path.write_text("// someone else's extension\n")

        result = CliRunner().invoke(init_cmd, ["--ci"])
        assert result.exit_code == 0, result.output
        assert "not configured" in result.output
        assert path.read_text() == "// someone else's extension\n"

    def test_remove_deletes_the_extension(self, sandbox: Path) -> None:
        from vectimus.cli.remove_cmd import remove_cmd

        install_extension(global_extension_path())
        result = CliRunner().invoke(remove_cmd, ["--force"])
        assert result.exit_code == 0, result.output
        assert not global_extension_path().exists()
        assert "extension removed" in result.output

    def test_remove_leaves_an_unmanaged_file(self, sandbox: Path) -> None:
        from vectimus.cli.remove_cmd import remove_cmd

        path = global_extension_path()
        path.parent.mkdir(parents=True)
        path.write_text("// not ours\n")
        CliRunner().invoke(remove_cmd, ["--force"])
        assert path.exists()


class TestStatus:
    """`vectimus status` reports where the extension is installed."""

    def test_it_reports_the_installed_extension(self, sandbox: Path) -> None:
        from vectimus.cli.status_cmd import _check_pi

        assert _check_pi() is None
        install_extension(global_extension_path())
        assert _check_pi() == str(global_extension_path())
