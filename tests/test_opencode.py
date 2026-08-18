"""Tests for the OpenCode adapter, plugin install and hook wiring.

The adapter is deliberately stricter than the older ones, so most of these
tests assert that something is *refused*: OpenCode's plugin blocks by
throwing, and everything Vectimus cannot map with confidence has to end up
there rather than in an allow.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from vectimus.adapters.opencode import OPENCODE_TOOL_MAP, OpenCodeNormalisationError
from vectimus.cli.hook_cmd import VALID_SOURCES, hook_cmd
from vectimus.cli.opencode_plugin import (
    PLUGIN_VERSION,
    SHIPPED_PLUGIN_DIGESTS,
    InstallStatus,
    global_plugin_path,
    install_plugin,
    is_managed,
    marker_version,
    project_plugin_path,
    remove_plugin,
    template_text,
)
from vectimus.engine.evaluator import PolicyEngine
from vectimus.engine.loader import PolicyLoader
from vectimus.engine.models import ActionType, DecisionVerdict, EventType
from vectimus.engine.normaliser import normalise


def _payload(tool_name: str, tool_input: dict | None = None, **extra) -> dict:
    payload = {"tool_name": tool_name, "tool_input": tool_input or {}}
    payload.update(extra)
    return payload


def _run_hook(payload: dict | str) -> tuple[int, str]:
    runner = CliRunner()
    stdin = payload if isinstance(payload, str) else json.dumps(payload)
    result = runner.invoke(hook_cmd, ["--source", "opencode"], input=stdin)
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


@pytest.fixture()
def sandbox(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Redirect OpenCode's config dir and cwd into tmp_path.

    Without this a test would read, and worse write, the developer's real
    ``~/.config/opencode``.
    """
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    project = tmp_path / "project"
    project.mkdir()
    monkeypatch.chdir(project)
    return tmp_path


class TestOpenCodeNormaliser:
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
            "opencode",
        )
        assert event.action.action_type == ActionType.SHELL_COMMAND
        assert event.action.command == "ls -la"
        assert event.action.raw_tool_name == "bash"
        assert event.source.tool == "opencode"
        assert event.source.session_id == "ses_1"
        assert event.event_id == "call_1"
        assert event.context.cwd == "/tmp/project"
        assert event.event_type == EventType.PRE_ACTION

    def test_bash_refines_to_a_more_specific_action(self) -> None:
        event = normalise(_payload("bash", {"command": "terraform destroy"}), "opencode")
        assert event.action.action_type == ActionType.INFRASTRUCTURE

    def test_bash_redirect_becomes_a_file_write(self) -> None:
        event = normalise(_payload("bash", {"command": "echo x > /etc/hosts"}), "opencode")
        assert event.action.action_type == ActionType.FILE_WRITE
        assert event.action.file_path == "/etc/hosts"

    def test_read_extracts_the_file_path(self) -> None:
        event = normalise(_payload("read", {"filePath": "/etc/passwd"}), "opencode")
        assert event.action.action_type == ActionType.FILE_READ
        assert event.action.file_path == "/etc/passwd"

    def test_file_paths_are_normalised_against_traversal(self) -> None:
        event = normalise(_payload("read", {"filePath": "/home/u/proj/../.ssh/id_rsa"}), "opencode")
        assert event.action.file_path == "/home/u/.ssh/id_rsa"

    def test_write_carries_content_for_inspection(self) -> None:
        event = normalise(
            _payload("write", {"filePath": "/tmp/a.txt", "content": "AKIAIOSFODNN7EXAMPLE"}),
            "opencode",
        )
        assert event.action.action_type == ActionType.FILE_WRITE
        assert event.action.file_path == "/tmp/a.txt"
        assert event.action.file_content == "AKIAIOSFODNN7EXAMPLE"

    def test_edit_uses_the_replacement_text_as_content(self) -> None:
        event = normalise(
            _payload(
                "edit",
                {"filePath": "/tmp/a.txt", "oldString": "old", "newString": "new"},
            ),
            "opencode",
        )
        assert event.action.action_type == ActionType.FILE_WRITE
        assert event.action.file_content == "new"

    @pytest.mark.parametrize("tool_name", ["glob", "grep"])
    def test_search_tools_use_their_optional_path(self, tool_name: str) -> None:
        event = normalise(_payload(tool_name, {"pattern": "*.env", "path": "/srv"}), "opencode")
        assert event.action.action_type == ActionType.FILE_READ
        assert event.action.file_path == "/srv"

    @pytest.mark.parametrize("tool_name", ["glob", "grep"])
    def test_search_tools_without_a_path_have_none(self, tool_name: str) -> None:
        event = normalise(_payload(tool_name, {"pattern": "*.env"}), "opencode")
        assert event.action.file_path is None

    def test_webfetch_extracts_the_url(self) -> None:
        event = normalise(_payload("webfetch", {"url": "https://example.com"}), "opencode")
        assert event.action.action_type == ActionType.WEB_REQUEST
        assert event.action.url == "https://example.com"

    def test_task_builds_the_synthetic_spawn_command(self) -> None:
        event = normalise(
            _payload(
                "task",
                {
                    "description": "d",
                    "prompt": "p",
                    "subagent_type": "build",
                    "background": True,
                },
            ),
            "opencode",
        )
        assert event.action.action_type == ActionType.AGENT_SPAWN
        assert event.action.command == "spawn subagent_type=build background=true"

    def test_task_omits_background_when_it_is_not_set(self) -> None:
        event = normalise(
            _payload("task", {"description": "d", "prompt": "p", "subagent_type": "build"}),
            "opencode",
        )
        assert event.action.command == "spawn subagent_type=build"

    def test_code_mode_execute_is_inspected_as_a_shell_command(self) -> None:
        event = normalise(_payload("execute", {"code": "await bash('rm -rf /')"}), "opencode")
        assert event.action.action_type == ActionType.SHELL_COMMAND
        assert event.action.command == "await bash('rm -rf /')"

    def test_session_only_tools_carry_no_command(self) -> None:
        event = normalise(_payload("todowrite", {"todos": [{"id": "1"}]}), "opencode")
        assert event.action.action_type == ActionType.AGENT_MESSAGE
        assert event.action.command is None

    def test_every_mapped_tool_normalises_or_names_its_missing_argument(self) -> None:
        """No mapped tool may raise for a reason other than a missing argument."""
        for tool_name in OPENCODE_TOOL_MAP:
            try:
                normalise(_payload(tool_name), "opencode")
            except OpenCodeNormalisationError as exc:
                assert "required" in str(exc) or "argument" in str(exc), tool_name


class TestOpenCodeMcpTools:
    """MCP resource tools normalise; MCP *tool* calls cannot be split."""

    def test_read_mcp_resource_carries_the_server(self) -> None:
        event = normalise(
            _payload("read_mcp_resource", {"server": "github", "uri": "repo://x"}),
            "opencode",
        )
        assert event.action.action_type == ActionType.MCP_TOOL
        assert event.action.mcp_server == "github"
        assert event.action.mcp_tool == "read_mcp_resource"

    def test_list_mcp_resources_without_a_server_has_none(self) -> None:
        event = normalise(_payload("list_mcp_resources", {}), "opencode")
        assert event.action.action_type == ActionType.MCP_TOOL
        assert event.action.mcp_server is None

    def test_an_mcp_tool_call_is_not_guessed_at(self) -> None:
        """OpenCode names MCP tools ``sanitize(server)_sanitize(tool)``.

        Both halves can contain underscores, so the split is ambiguous.  The
        adapter must refuse rather than pick one.
        """
        with pytest.raises(OpenCodeNormalisationError) as exc:
            normalise(_payload("github_create_issue", {"title": "x"}), "opencode")
        assert "github_create_issue" in str(exc.value)

    def test_an_unresolvable_mcp_server_would_be_denied_anyway(self) -> None:
        """Even a correct split denies while the server is not approved."""
        engine = PolicyEngine(loader=PolicyLoader())
        event = normalise(
            _payload("read_mcp_resource", {"server": "evil", "uri": "x://y"}), "opencode"
        )
        decision = engine.evaluate(event)
        assert decision.decision == DecisionVerdict.DENY
        assert "vectimus-mcp-001" in decision.matched_policy_ids


class TestOpenCodeNormaliserRefusals:
    """Everything the adapter refuses to map, and therefore denies."""

    @pytest.mark.parametrize(
        "payload",
        [
            {},
            {"tool_input": {"command": "ls"}},
            {"tool_name": "", "tool_input": {}},
            {"tool_name": "   ", "tool_input": {}},
            {"tool_name": None, "tool_input": {}},
            {"tool_name": 42, "tool_input": {}},
        ],
        ids=["empty", "no-name", "blank-name", "whitespace-name", "null-name", "int-name"],
    )
    def test_missing_tool_name_raises(self, payload: dict) -> None:
        with pytest.raises(OpenCodeNormalisationError):
            normalise(payload, "opencode")

    @pytest.mark.parametrize("tool_input", ["a string", 42, ["a", "list"], True])
    def test_non_object_tool_input_raises(self, tool_input: object) -> None:
        with pytest.raises(OpenCodeNormalisationError):
            normalise({"tool_name": "bash", "tool_input": tool_input}, "opencode")

    @pytest.mark.parametrize(
        "tool_name",
        ["shell", "Bash", "run_command", "notatool", "bash_extra", "read_file"],
    )
    def test_unknown_tool_raises(self, tool_name: str) -> None:
        with pytest.raises(OpenCodeNormalisationError) as exc:
            normalise(_payload(tool_name, {"command": "rm -rf /"}), "opencode")
        assert tool_name in str(exc.value)
        assert "docs/opencode-tool-inventory.md" in str(exc.value)

    @pytest.mark.parametrize(
        ("tool_name", "tool_input"),
        [
            ("bash", {}),
            ("bash", {"command": ""}),
            ("bash", {"command": "   "}),
            ("bash", {"command": None}),
            ("bash", {"timeout": 1000}),
            ("read", {}),
            ("read", {"filePath": ""}),
            ("write", {"filePath": "/tmp/a"}),
            ("write", {"content": "x"}),
            ("edit", {"filePath": "/tmp/a", "oldString": "a"}),
            ("glob", {}),
            ("grep", {"path": "/srv"}),
            ("webfetch", {}),
            ("websearch", {}),
            ("task", {"description": "d", "prompt": "p"}),
            ("apply_patch", {}),
            ("skill", {}),
            ("todowrite", {"todos": []}),
            ("execute", {}),
            ("read_mcp_resource", {"server": "github"}),
            ("lsp", {"operation": "hover", "filePath": "/a"}),
        ],
    )
    def test_missing_required_argument_raises(self, tool_name: str, tool_input: dict) -> None:
        with pytest.raises(OpenCodeNormalisationError):
            normalise(_payload(tool_name, tool_input), "opencode")

    def test_a_non_string_command_is_not_coerced(self) -> None:
        with pytest.raises(OpenCodeNormalisationError):
            normalise(_payload("bash", {"command": ["rm", "-rf", "/"]}), "opencode")


class TestOpenCodeApplyPatch:
    """One event carries one file_path, so multi-file patches cannot pass."""

    def test_single_file_patch_is_a_file_write(self) -> None:
        patch = "*** Begin Patch\n*** Update File: src/app.ts\n+const x = 1\n*** End Patch"
        event = normalise(_payload("apply_patch", {"patchText": patch}), "opencode")
        assert event.action.action_type == ActionType.FILE_WRITE
        assert event.action.file_path == "src/app.ts"
        assert event.action.file_content == patch

    @pytest.mark.parametrize("verb", ["Add", "Update", "Delete"])
    def test_every_patch_verb_yields_a_target(self, verb: str) -> None:
        patch = f"*** Begin Patch\n*** {verb} File: a.ts\n*** End Patch"
        event = normalise(_payload("apply_patch", {"patchText": patch}), "opencode")
        assert event.action.file_path == "a.ts"

    def test_multi_file_patch_raises(self) -> None:
        patch = (
            "*** Begin Patch\n"
            "*** Update File: src/app.ts\n"
            "+const x = 1\n"
            "*** Add File: .env\n"
            "+AWS_SECRET_ACCESS_KEY=hunter2\n"
            "*** End Patch"
        )
        with pytest.raises(OpenCodeNormalisationError) as exc:
            normalise(_payload("apply_patch", {"patchText": patch}), "opencode")
        assert "2 files" in str(exc.value)

    def test_patch_without_a_file_header_raises(self) -> None:
        with pytest.raises(OpenCodeNormalisationError):
            normalise(
                _payload("apply_patch", {"patchText": "*** Begin Patch\n*** End Patch"}),
                "opencode",
            )


class TestOpenCodeHookCommand:
    """End-to-end through ``vectimus hook --source opencode``."""

    @pytest.fixture(autouse=True)
    def _no_daemon(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Evaluate inline.

        A daemon left running by an older install answers these calls
        otherwise, which makes the result depend on the developer's machine.
        """
        monkeypatch.setenv("VECTIMUS_NO_DAEMON", "1")

    def test_opencode_is_a_valid_source(self) -> None:
        assert "opencode" in VALID_SOURCES

    def test_safe_command_allows_with_no_verdict_on_stdout(self, tmp_path, monkeypatch) -> None:
        """An allow prints nothing; the plugin treats any output as a block.

        CliRunner mixes stderr into ``output``, so this asserts no JSON
        verdict rather than a wholly empty stream.
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
        assert "docs/opencode-tool-inventory.md" in parsed["reason"]

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
        """OpenCode has no ask channel, so escalate blocks (issue #53)."""
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


class TestOpenCodeIncidentRegression:
    """The 2026-08-17 recursive-delete incident, as OpenCode would send it."""

    INCIDENT_COMMAND = "rm -rf ~/Development"

    def _event(self):
        return normalise(
            _payload("bash", {"command": self.INCIDENT_COMMAND}, cwd="/Users/dev/Development"),
            "opencode",
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


class TestPluginTemplatePackaging:
    """The template ships as package data and its digest is pinned."""

    def test_template_is_readable_from_the_installed_package(self) -> None:
        assert "VECTIMUS-MANAGED" in template_text()

    def test_template_declares_the_current_plugin_version(self) -> None:
        assert marker_version(template_text()) == PLUGIN_VERSION

    def test_pinned_digest_matches_the_shipped_template(self) -> None:
        """Editing the template without bumping the version fails here.

        The digest is what tells an untouched managed install from one a user
        edited, so a stale pin would make `vectimus init` refuse to update
        installs it wrote itself.
        """
        digest = hashlib.sha256(template_text().encode("utf-8")).hexdigest()
        assert digest == SHIPPED_PLUGIN_DIGESTS[PLUGIN_VERSION]

    def test_no_digest_entry_was_dropped(self) -> None:
        assert set(SHIPPED_PLUGIN_DIGESTS) == set(range(1, PLUGIN_VERSION + 1))


class TestPluginInstall:
    """`vectimus init` owns exactly one marked file, and nothing else."""

    def test_installs_globally_by_default(self, sandbox: Path) -> None:
        path = global_plugin_path()
        result = install_plugin(path)
        assert result.status == InstallStatus.INSTALLED
        assert path.read_text() == template_text()
        assert path.parent.name == "plugin"
        assert path.parent.parent == sandbox / "config" / "opencode"

    def test_installs_into_the_project_when_asked(self, sandbox: Path) -> None:
        path = project_plugin_path()
        assert install_plugin(path).status == InstallStatus.INSTALLED
        assert path == Path.cwd() / ".opencode" / "plugin" / "vectimus.ts"

    def test_reinstalling_is_a_no_op(self, sandbox: Path) -> None:
        path = global_plugin_path()
        install_plugin(path)
        assert install_plugin(path).status == InstallStatus.UNCHANGED

    def test_refuses_a_file_it_did_not_write(self, sandbox: Path) -> None:
        path = global_plugin_path()
        path.parent.mkdir(parents=True)
        path.write_text("export const Mine = async () => ({})\n")
        result = install_plugin(path)
        assert result.status == InstallStatus.REFUSED_UNMANAGED
        assert not result.ok
        assert path.read_text() == "export const Mine = async () => ({})\n"

    def test_refuses_an_edited_managed_file(self, sandbox: Path) -> None:
        path = global_plugin_path()
        install_plugin(path)
        edited = template_text() + "\n// my tweak\n"
        path.write_text(edited)
        result = install_plugin(path)
        assert result.status == InstallStatus.REFUSED_MODIFIED
        assert path.read_text() == edited

    def test_refuses_a_newer_plugin_version(self, sandbox: Path) -> None:
        path = global_plugin_path()
        path.parent.mkdir(parents=True)
        newer = template_text().replace(
            f"plugin-version: {PLUGIN_VERSION}", f"plugin-version: {PLUGIN_VERSION + 99}"
        )
        path.write_text(newer)
        result = install_plugin(path)
        assert result.status == InstallStatus.REFUSED_NEWER
        assert path.read_text() == newer

    def test_write_leaves_no_temp_file_behind(self, sandbox: Path) -> None:
        path = global_plugin_path()
        install_plugin(path)
        assert [p.name for p in path.parent.iterdir()] == ["vectimus.ts"]


class TestPluginRemove:
    def test_removes_a_managed_plugin(self, sandbox: Path) -> None:
        path = global_plugin_path()
        install_plugin(path)
        assert remove_plugin(path) is True
        assert not path.exists()

    def test_leaves_an_unmanaged_file_alone(self, sandbox: Path) -> None:
        path = global_plugin_path()
        path.parent.mkdir(parents=True)
        path.write_text("export const Mine = async () => ({})\n")
        assert remove_plugin(path) is False
        assert path.exists()

    def test_leaves_opencodes_own_config_directory_in_place(self, sandbox: Path) -> None:
        path = global_plugin_path()
        install_plugin(path)
        remove_plugin(path)
        assert path.parent.parent.is_dir(), "OpenCode owns its config dir; do not delete it"

    def test_is_managed_is_false_for_a_missing_file(self, sandbox: Path) -> None:
        assert is_managed(global_plugin_path()) is False


class TestInitAndRemoveCommands:
    """The CLI surface, with OpenCode detected."""

    @pytest.fixture(autouse=True)
    def _detect_only_opencode(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import shutil

        monkeypatch.setattr(
            shutil, "which", lambda name: "/usr/local/bin/opencode" if name == "opencode" else None
        )
        monkeypatch.setattr("vectimus.cli.detect._cursor_known_locations", lambda: [])
        monkeypatch.setattr("vectimus.cli.detect._vscode_known_locations", lambda: [])
        monkeypatch.setattr("vectimus.cli.detect._check_linux_appimage", lambda app: None)

    def test_configure_installs_globally(self, sandbox: Path) -> None:
        from vectimus.cli.init_cmd import _configure_opencode

        detail = _configure_opencode()
        assert str(global_plugin_path()) in detail
        assert global_plugin_path().exists()
        assert not project_plugin_path().exists()

    def test_configure_project_scope_installs_locally(self, sandbox: Path) -> None:
        from vectimus.cli.init_cmd import _configure_opencode

        detail = _configure_opencode(project=True)
        assert str(project_plugin_path()) in detail
        assert project_plugin_path().exists()
        assert not global_plugin_path().exists()

    def test_configure_raises_rather_than_failing_quietly(self, sandbox: Path) -> None:
        """A refused install must not be counted as a configured tool."""
        from vectimus.cli.init_cmd import ConfigureRefusedError, _configure_opencode

        path = global_plugin_path()
        path.parent.mkdir(parents=True)
        path.write_text("export const Mine = async () => ({})\n")
        with pytest.raises(ConfigureRefusedError):
            _configure_opencode()

    def test_remove_deletes_both_installs(self, sandbox: Path) -> None:
        from vectimus.cli.remove_cmd import remove_cmd

        install_plugin(global_plugin_path())
        install_plugin(project_plugin_path())

        result = CliRunner().invoke(remove_cmd, ["--force"])
        assert result.exit_code == 0, result.output
        assert not global_plugin_path().exists()
        assert not project_plugin_path().exists()

    def test_remove_reports_nothing_when_not_installed(self, sandbox: Path) -> None:
        from vectimus.cli.remove_cmd import remove_cmd

        result = CliRunner().invoke(remove_cmd, ["--force"])
        assert result.exit_code == 0
        assert "No Vectimus hooks found" in result.output


class TestStatus:
    def test_status_reports_the_installed_plugin(self, sandbox: Path) -> None:
        from vectimus.cli.status_cmd import _check_opencode

        assert _check_opencode() is None
        install_plugin(global_plugin_path())
        assert _check_opencode() == str(global_plugin_path())
