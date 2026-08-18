"""Run the packaged OpenCode plugin against a fake ``vectimus`` binary.

The plugin is the whole enforcement point on the OpenCode side: OpenCode
blocks a tool call only when ``tool.execute.before`` throws.  Reading the
template is not enough to know it throws in every failure mode, so these
tests execute the real shipped file under a JS runtime and drive a stub
``vectimus`` through each outcome -- allow, deny, garbage, whitespace where a
verdict should be, non-zero exit, signal death, spawn failure, missing binary,
a hang, a child that exits without reading the call, and a reply that arrives
in pieces.

``test_the_harness_catches_a_neutered_throw`` is the guard on the guard: it
mutates the plugin so a deny stops throwing, and fails if the harness still
reports a block.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from vectimus.cli.opencode_plugin import template_text
from vectimus.templates import OPENCODE_PLUGIN

# node handles .mts natively (type stripping is on by default from 23.6); bun
# reads TypeScript directly.  Either will do.
_RUNTIME = shutil.which("node") or shutil.which("bun")

pytestmark = pytest.mark.skipif(
    _RUNTIME is None,
    reason="needs node or bun on PATH to execute the OpenCode plugin template",
)

# The line that turns a deny verdict into a thrown error.  Pinned so the
# revert check fails loudly if the template is restructured, instead of
# quietly mutating nothing.
_THROW_ON_DENY = "finish(blocked(reasonFrom(trimmed)))"

_DRIVER = """
import { readFileSync } from "node:fs"

const mod = await import("./plugin.mts")
const plugin = Object.values(mod)[0]
const hooks = await plugin({ directory: process.cwd(), worktree: process.cwd() })
// From a file rather than the environment: one case needs arguments larger
// than an environment variable may be.
const args = JSON.parse(readFileSync("./args.json", "utf8"))
try {
  await hooks["tool.execute.before"](
    { tool: "bash", sessionID: "ses_1", callID: "call_1" },
    { args },
  )
  console.log("ALLOWED")
} catch (error) {
  console.log("THREW: " + error.message)
}
"""

# Stub `vectimus` implementations, one per outcome the plugin must handle.
# Each drains stdin first, the way the real hook does.
_STUBS = {
    "allow": "cat >/dev/null\nexit 0\n",
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
    # exec so the shell is replaced: the plugin's SIGKILL then reaches the
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
    # Never reads stdin.  Paired with oversized arguments, the plugin is still
    # writing when this exits, so the write ends in EPIPE.
    "exit_0_without_reading": "sleep 0.2\nexit 0\n",
    "not_executable": None,  # written without the executable bit
}

_DEFAULT_ARGS = {"command": "rm -rf /"}


class _Harness:
    """A temp directory holding the plugin, a driver and a stub binary."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.bin = root / "bin"
        self.bin.mkdir()
        (root / "driver.mjs").write_text(_DRIVER)
        self.plugin_path = root / "plugin.mts"
        self.plugin_path.write_text(template_text())

    def write_stub(self, body: str | None, *, executable: bool = True) -> None:
        stub = self.bin / "vectimus"
        stub.write_text("#!/bin/sh\n" + (body or "exit 0\n"))
        stub.chmod(0o755 if executable else 0o644)

    def remove_stub(self) -> None:
        (self.bin / "vectimus").unlink(missing_ok=True)

    def run(self, *, timeout_ms: int = 3000, args: dict | None = None) -> str:
        assert _RUNTIME is not None
        (self.root / "args.json").write_text(json.dumps(args or _DEFAULT_ARGS))
        env = dict(os.environ)
        # The stub dir first, then the runtime's own dir and the standard
        # locations the stub shell script needs (sh, cat, sleep, kill).
        env["PATH"] = os.pathsep.join(
            [str(self.bin), str(Path(_RUNTIME).parent), "/usr/bin", "/bin"]
        )
        env["VECTIMUS_PLUGIN_TIMEOUT_MS"] = str(timeout_ms)
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


@pytest.fixture()
def harness(tmp_path: Path) -> _Harness:
    return _Harness(tmp_path)


def test_the_copy_under_test_is_the_packaged_file(harness: _Harness) -> None:
    """Guards against the harness drifting from what ships."""
    shipped = hashlib.sha256(OPENCODE_PLUGIN.read_bytes()).hexdigest()
    under_test = hashlib.sha256(harness.plugin_path.read_bytes()).hexdigest()
    assert under_test == shipped


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
def test_every_other_outcome_throws(harness: _Harness, stub: str, expected: str) -> None:
    harness.write_stub(_STUBS[stub])
    output = harness.run()
    assert output.startswith("THREW:"), output
    assert expected in output


def test_exit_one_with_empty_stdout_is_not_an_allow(harness: _Harness) -> None:
    """Empty stdout alone is not an allow -- exit 0 is also required.

    A crashed hook prints nothing, which is byte-for-byte what an allow
    looks like on stdout.  Only the pair of them permits the tool call.
    """
    harness.write_stub(_STUBS["exit_1_empty"])
    output = harness.run()
    assert output.startswith("THREW:"), output
    assert "fail closed" in output


def test_whitespace_on_stdout_is_not_an_allow(harness: _Harness) -> None:
    """An allow is silence, and a stray newline is not silence.

    Trimming stdout before testing it for emptiness would read a check that
    printed a blank line -- a broken build, a debug echo, a shell wrapper --
    as consent it never gave.
    """
    harness.write_stub(_STUBS["whitespace"])
    output = harness.run()
    assert output.startswith("THREW:"), output
    assert "only whitespace" in output


def test_a_check_that_exits_without_reading_the_call_throws(harness: _Harness) -> None:
    """It cannot have judged a call it never received.

    The write is left in flight and ends in EPIPE, while the rest of the
    outcome -- exit 0, empty stdout -- is byte-for-byte an allow.  Swallowing
    that error would turn any check that dies early into a pass.  The
    arguments are oversized so the write is still going when the child exits;
    small ones would fit the pipe buffer and complete regardless.
    """
    harness.write_stub(_STUBS["exit_0_without_reading"])
    output = harness.run(args={"command": "echo " + "x" * 512_000})
    assert output.startswith("THREW:"), output
    assert "did not read the tool call" in output


def test_a_hang_past_the_deadline_throws(harness: _Harness) -> None:
    harness.write_stub(_STUBS["hang"])
    output = harness.run(timeout_ms=500)
    assert output.startswith("THREW:"), output
    assert "did not answer within 500ms" in output


def test_a_missing_binary_throws(harness: _Harness) -> None:
    harness.remove_stub()
    output = harness.run()
    assert output.startswith("THREW:"), output
    assert "not on PATH" in output


def test_a_binary_that_cannot_be_executed_throws(harness: _Harness) -> None:
    harness.write_stub(_STUBS["allow"], executable=False)
    output = harness.run()
    assert output.startswith("THREW:"), output
    assert "Blocked by Vectimus" in output


def test_the_harness_catches_a_neutered_throw(harness: _Harness) -> None:
    """Mutation check: remove the throw and the deny case must stop blocking.

    Without this, every assertion above would keep passing if the plugin
    were rewritten to resolve on a deny -- they would just be asserting that
    some unrelated error happened to be raised.
    """
    source = harness.plugin_path.read_text()
    assert _THROW_ON_DENY in source, (
        "the pinned throw-on-deny line is gone from the template; update "
        "_THROW_ON_DENY so this check keeps mutating something real"
    )
    harness.plugin_path.write_text(source.replace(_THROW_ON_DENY, "finish()"))

    harness.write_stub(_STUBS["deny"])
    assert harness.run() == "ALLOWED", (
        "with the throw removed the plugin must allow a deny payload; if it "
        "still blocks, this harness is not testing what it claims to"
    )
