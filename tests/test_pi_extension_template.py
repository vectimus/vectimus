"""Run the packaged Pi extension against a fake ``vectimus`` binary.

The extension is the whole enforcement point on the Pi side, so reading the
template is not enough to know it blocks in every failure mode.  These tests
execute the real shipped file under a JS runtime, drive a stub ``vectimus``
through each outcome -- allow, deny, garbage, whitespace where a verdict
should be, non-zero exit, signal death, spawn failure, missing binary, a hang,
a child that exits without reading the call, and a reply that arrives in
pieces -- and also check the payload the extension sends.

``test_the_harness_catches_a_neutered_block`` is the guard on the guard: it
mutates the extension so a deny stops blocking, and fails if the harness
still reports a block.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from vectimus.cli.pi_extension import template_text
from vectimus.templates import PI_EXTENSION

# node handles .mts natively (type stripping is on by default from 23.6); bun
# reads TypeScript directly.  Either will do.
_RUNTIME = shutil.which("node") or shutil.which("bun")

pytestmark = pytest.mark.skipif(
    _RUNTIME is None,
    reason="needs node or bun on PATH to execute the Pi extension template",
)

# The line that turns a deny verdict into a block.  Pinned so the revert check
# fails loudly if the template is restructured, instead of quietly mutating
# nothing.
_BLOCK_ON_DENY = "return { block: true, reason: `Blocked by Vectimus: ${reason}` }"

# Stands in for Pi: collects the `tool_call` handler the extension registers,
# calls it with one event, and prints the outcome.  The event is overridable so
# a test can check what the extension makes of a relative path.
_DRIVER = """
import { readFileSync } from "node:fs"

const mod = await import("./extension.mts")
const register = mod.default

let handler
register({
  on: (name, fn) => {
    if (name === "tool_call") handler = fn
  },
})

if (typeof handler !== "function") {
  console.log("NO_HANDLER")
  process.exit(0)
}

// From a file rather than the environment: one case needs an input larger
// than an environment variable may be.
const event = JSON.parse(readFileSync("./event.json", "utf8"))
const ctx = {
  cwd: process.env.VECTIMUS_TEST_CWD,
  sessionManager: { getSessionId: () => "ses_test" },
}

try {
  const result = await handler(event, ctx)
  if (result && result.block) {
    console.log("BLOCKED: " + result.reason)
  } else {
    console.log("ALLOWED")
  }
} catch (error) {
  console.log("THREW: " + error.message)
}
"""

# Stub `vectimus` implementations, one per outcome the extension must handle.
# Each drains stdin first, the way the real hook does.
_STUBS = {
    "allow": "cat >/dev/null\nprintf 'VECTIMUS-ALLOW\\n' >&3\nexit 0\n",
    "deny": (
        "cat >/dev/null\n"
        'echo \'{"decision":"deny","reason":"Blocked by policy vectimus-destruct-001"}\'\n'
        "exit 0\n"
    ),
    "garbage": "cat >/dev/null\necho 'not json at all'\nexit 0\n",
    "allow_json": 'cat >/dev/null\necho \'{"decision":"allow"}\'\nexit 0\n',
    "exit_1_empty": "cat >/dev/null\nexit 1\n",
    "exit_2_empty": "cat >/dev/null\nexit 2\n",
    "signal": "cat >/dev/null\nkill -9 $$\n",
    # exec so the shell is replaced: the extension's SIGKILL then reaches the
    # process actually holding the stdout pipe, as it would with the real
    # single-process `vectimus`.
    "hang": "cat >/dev/null\nexec sleep 30\n",
    "chunked": (
        "cat >/dev/null\n"
        'printf \'{"decision":"deny",\'\n'
        "sleep 0.2\n"
        'printf \'"reason":"arrived in two writes"}\'\n'
        "exit 0\n"
    ),
    "whitespace": "cat >/dev/null\nprintf ' \\n\\t\\n'\nexit 0\n",
    # Never reads stdin.  Paired with an oversized input, the extension is
    # still writing when this exits, so the write ends in EPIPE.
    "exit_0_without_reading": "sleep 0.2\nexit 0\n",
}

_DEFAULT_EVENT = {
    "type": "tool_call",
    "toolName": "bash",
    "toolCallId": "call_1",
    "input": {"command": "rm -rf /"},
}


class _Harness:
    """A temp directory holding the extension, a driver and a stub binary."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.bin = root / "bin"
        self.bin.mkdir()
        (root / "driver.mjs").write_text(_DRIVER)
        self.extension_path = root / "extension.mts"
        self.extension_path.write_text(template_text())
        # Where a payload-capturing stub writes what it was sent.
        self.captured = root / "captured.json"

    def write_stub(self, body: str | None, *, executable: bool = True) -> None:
        stub = self.bin / "vectimus"
        stub.write_text("#!/bin/sh\n" + (body or "exit 0\n"))
        stub.chmod(0o755 if executable else 0o644)

    def write_capturing_stub(self) -> None:
        """A stub that saves stdin, acknowledges its allow, and then exits."""
        self.write_stub(f"cat > {self.captured}\nprintf 'VECTIMUS-ALLOW\\n' >&3\nexit 0\n")

    def remove_stub(self) -> None:
        (self.bin / "vectimus").unlink(missing_ok=True)

    def run(
        self,
        *,
        timeout_ms: int = 3000,
        event: dict | None = None,
        cwd: str | None = None,
    ) -> str:
        assert _RUNTIME is not None
        env = dict(os.environ)
        # The stub dir first, then the runtime's own dir and the standard
        # locations the stub shell script needs (sh, cat, sleep, kill).
        env["PATH"] = os.pathsep.join(
            [str(self.bin), str(Path(_RUNTIME).parent), "/usr/bin", "/bin"]
        )
        env["VECTIMUS_PLUGIN_TIMEOUT_MS"] = str(timeout_ms)
        env["VECTIMUS_TEST_CWD"] = cwd if cwd is not None else str(self.root)
        (self.root / "event.json").write_text(json.dumps(event or _DEFAULT_EVENT))
        result = subprocess.run(
            [_RUNTIME, "driver.mjs"],
            cwd=self.root,
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0, (
            f"driver failed ({result.returncode})\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )
        return result.stdout.strip()

    def captured_payload(self) -> dict:
        return json.loads(self.captured.read_text())


@pytest.fixture()
def harness(tmp_path: Path) -> _Harness:
    return _Harness(tmp_path)


def test_the_copy_under_test_is_the_packaged_file(harness: _Harness) -> None:
    """Guards against the harness drifting from what ships."""
    shipped = hashlib.sha256(PI_EXTENSION.read_bytes()).hexdigest()
    under_test = hashlib.sha256(harness.extension_path.read_bytes()).hexdigest()
    assert under_test == shipped


def test_the_extension_registers_a_tool_call_handler(harness: _Harness) -> None:
    """A template that subscribes to the wrong event would guard nothing."""
    harness.write_stub(_STUBS["allow"])
    assert harness.run() != "NO_HANDLER"


def test_exit_zero_with_empty_stdout_allows(harness: _Harness) -> None:
    harness.write_stub(_STUBS["allow"])
    assert harness.run() == "ALLOWED"


@pytest.mark.parametrize(
    ("stub", "expected"),
    [
        ("deny", "vectimus-destruct-001"),
        ("garbage", "not JSON"),
        ("allow_json", "unrecognised response"),
        ("exit_1_empty", "exited 1"),
        ("exit_2_empty", "exited 2"),
        ("signal", "killed by SIGKILL"),
        ("chunked", "arrived in two writes"),
    ],
)
def test_every_other_outcome_blocks(harness: _Harness, stub: str, expected: str) -> None:
    harness.write_stub(_STUBS[stub])
    output = harness.run()
    assert output.startswith("BLOCKED:"), output
    assert expected in output


def test_exit_one_with_empty_stdout_is_not_an_allow(harness: _Harness) -> None:
    """Empty stdout alone is not an allow -- exit 0 is also required.

    A crashed hook prints nothing, which is byte-for-byte what an allow looks
    like on stdout.  Only the pair of them permits the tool call.
    """
    harness.write_stub(_STUBS["exit_1_empty"])
    output = harness.run()
    assert output.startswith("BLOCKED:"), output
    assert "fail closed" in output


def test_whitespace_on_stdout_is_not_an_allow(harness: _Harness) -> None:
    """An allow is silence, and a stray newline is not silence.

    Trimming stdout before testing it for emptiness would read a check that
    printed a blank line -- a broken build, a debug echo, a shell wrapper --
    as consent it never gave.
    """
    harness.write_stub(_STUBS["whitespace"])
    output = harness.run()
    assert output.startswith("BLOCKED:"), output
    assert "only whitespace" in output


def test_a_check_that_exits_without_reading_the_call_blocks(harness: _Harness) -> None:
    """It cannot have judged a call it never received.

    The write is left in flight and ends in EPIPE, while the rest of the
    outcome -- exit 0, empty stdout -- is byte-for-byte an allow.  Swallowing
    that error would turn any check that dies early into a pass.  The input is
    oversized so the write is still going when the child exits; a small one
    would fit the pipe buffer and complete regardless.
    """
    harness.write_stub(_STUBS["exit_0_without_reading"])
    event = {
        "type": "tool_call",
        "toolName": "bash",
        "toolCallId": "call_6",
        "input": {"command": "echo " + "x" * 512_000},
    }
    output = harness.run(event=event)
    assert output.startswith("BLOCKED:"), output
    assert "did not read the tool call" in output


def test_a_hang_past_the_deadline_blocks(harness: _Harness) -> None:
    harness.write_stub(_STUBS["hang"])
    output = harness.run(timeout_ms=500)
    assert output.startswith("BLOCKED:"), output
    assert "did not answer within 500ms" in output


def test_a_missing_binary_blocks(harness: _Harness) -> None:
    harness.remove_stub()
    output = harness.run()
    assert output.startswith("BLOCKED:"), output
    assert "not on PATH" in output


def test_a_binary_that_cannot_be_executed_blocks(harness: _Harness) -> None:
    harness.write_stub(_STUBS["allow"], executable=False)
    output = harness.run()
    assert output.startswith("BLOCKED:"), output
    assert "Blocked by Vectimus" in output


class TestThePayloadItSends:
    """What the extension puts on the hook's stdin."""

    def test_a_bash_call_arrives_in_the_shape_the_adapter_reads(self, harness: _Harness) -> None:
        harness.write_capturing_stub()
        assert harness.run(cwd="/proj") == "ALLOWED"
        payload = harness.captured_payload()
        assert payload["tool_name"] == "bash"
        assert payload["tool_input"] == {"command": "rm -rf /"}
        assert payload["hook_event_name"] == "PreToolUse"
        assert payload["call_id"] == "call_1"
        assert payload["session_id"] == "ses_test"
        assert payload["cwd"] == "/proj"

    def test_a_relative_path_is_resolved_against_the_session_cwd(self, harness: _Harness) -> None:
        """Otherwise an absolute-path policy never matches it.

        Pi passes model-written paths straight through, so this is the
        ordinary case rather than an edge one.
        """
        harness.write_capturing_stub()
        event = {
            "type": "tool_call",
            "toolName": "read",
            "toolCallId": "call_2",
            "input": {"path": "../.ssh/id_rsa"},
        }
        assert harness.run(event=event, cwd="/Users/dev/proj") == "ALLOWED"
        assert harness.captured_payload()["tool_input"]["path"] == "/Users/dev/.ssh/id_rsa"

    def test_an_absolute_path_is_passed_through_unchanged(self, harness: _Harness) -> None:
        harness.write_capturing_stub()
        event = {
            "type": "tool_call",
            "toolName": "write",
            "toolCallId": "call_3",
            "input": {"path": "/etc/hosts", "content": "x"},
        }
        assert harness.run(event=event, cwd="/proj") == "ALLOWED"
        assert harness.captured_payload()["tool_input"]["path"] == "/etc/hosts"

    def test_other_arguments_survive_the_path_rewrite(self, harness: _Harness) -> None:
        """The rewrite copies the input; it must not drop the rest of it."""
        harness.write_capturing_stub()
        event = {
            "type": "tool_call",
            "toolName": "edit",
            "toolCallId": "call_4",
            "input": {"path": "notes.txt", "edits": [{"oldText": "a", "newText": "b"}]},
        }
        assert harness.run(event=event, cwd="/proj") == "ALLOWED"
        payload = harness.captured_payload()
        assert payload["tool_input"]["path"] == "/proj/notes.txt"
        assert payload["tool_input"]["edits"] == [{"oldText": "a", "newText": "b"}]

    def test_an_unknown_tool_is_forwarded_rather_than_judged_locally(
        self, harness: _Harness
    ) -> None:
        """Deciding which tools exist is the adapter's job, not the template's.

        A template that filtered unknown tools itself would let a tool another
        extension registers run unchecked.
        """
        harness.write_capturing_stub()
        event = {
            "type": "tool_call",
            "toolName": "some_other_extensions_tool",
            "toolCallId": "call_5",
            "input": {"anything": 1},
        }
        harness.run(event=event, cwd="/proj")
        assert harness.captured_payload()["tool_name"] == "some_other_extensions_tool"


def test_the_harness_catches_a_neutered_block(harness: _Harness) -> None:
    """Mutation check: remove the block and the deny case must stop blocking.

    Without this, every assertion above would keep passing if the extension
    were rewritten to allow on a deny -- they would just be asserting that
    some unrelated failure happened to block.
    """
    source = harness.extension_path.read_text()
    assert _BLOCK_ON_DENY in source, (
        "the pinned block-on-deny line is gone from the template; update "
        "_BLOCK_ON_DENY so this check keeps mutating something real"
    )
    harness.extension_path.write_text(source.replace(_BLOCK_ON_DENY, "return undefined"))

    harness.write_stub(_STUBS["deny"])
    assert harness.run() == "ALLOWED", (
        "with the block removed the extension must allow a deny payload; if it "
        "still blocks, this harness is not testing what it claims to"
    )
