# Pi

[Pi](https://pi.dev/) is guarded by an extension rather than a hooks config.
`vectimus init` installs it; every tool call then goes through
`vectimus hook --source pi` before Pi runs it.

```bash
vectimus init             # installs to Pi's user-level agent directory
vectimus init --project   # installs to ./.pi/extensions/ instead
vectimus status           # shows which extension file is in place
vectimus remove           # deletes it
```

Support is experimental.  Verified against `@mariozechner/pi-coding-agent`
0.73.1.

## How blocking works

Pi extensions subscribe to the `tool_call` event, which fires before a tool
runs and can stop it.  Unlike OpenCode, Pi offers a structured block:
returning `{ block: true, reason }` cancels the call and hands the reason to
the model as the tool's error result.  Throwing blocks too -- Pi does not
catch `tool_call` handler errors, and documents that as fail-safe.

The extension allows a call only when `vectimus hook` exits 0 with nothing on
stdout, and blocks in every other case:

| What happened | Result |
|---------------|--------|
| Exit 0, empty stdout | **Allowed** |
| Deny payload on stdout | Blocked, with the policy's reason |
| Output that is not JSON | Blocked |
| Output that parses but is not a deny | Blocked |
| Non-zero exit, even with empty stdout | Blocked |
| Killed by a signal | Blocked |
| `vectimus` not on PATH | Blocked |
| No answer within 30 seconds | Child killed, blocked |

Empty stdout on its own is not an allow.  A hook that crashed prints exactly
what an allow prints, so the exit code has to agree.

Override the deadline with `VECTIMUS_PLUGIN_TIMEOUT_MS` if 30 seconds is
wrong for your setup.  Lowering it makes Vectimus block sooner under load,
not allow sooner.

## Escalate is a hard block

A policy with `escalate` enforcement blocks under Pi, the same as `deny`, and
the reason is prefixed `[escalate]`.  Pi can prompt the user -- extensions
have `ctx.ui.confirm` -- but only in interactive mode, and a guard that
silently stops asking in `-p` or RPC mode is worse than one that consistently
blocks.  Wiring up real escalation is tracked in
[#53](https://github.com/vectimus/vectimus/issues/53).  Until then, treat
escalate as deny, which is what it already does for Claude Code.

## What is covered

All seven built-in Pi tools: `bash`, `read`, `write`, `edit`, `grep`, `find`
and `ls`.  The full table, with the argument each policy matches on, is in
[pi-tool-inventory.md](pi-tool-inventory.md).

Pi has no MCP subsystem, no web-fetch or web-search tool and no sub-agent
spawn tool, so those rule packs simply never fire under Pi.  This is not a
coverage gap -- there is nothing for them to match.

One thing is deliberately blocked rather than evaluated:

- **Tools Vectimus does not recognise.**  A tool added by a newer Pi, or one
  registered by another extension via `pi.registerTool()`, has no known
  argument schema, so there is nothing to evaluate.  Guessing an action type
  would report a pass the call did not earn.  If a new Pi release blocks
  something you need, upgrade Vectimus or open an issue -- the inventory is
  versioned against Pi releases.

## Relative paths

Pi passes tool paths to the extension exactly as the model wrote them, and
models routinely write relative ones (`notes.txt`, `../config`).  Left
alone, a relative path matches none of the absolute patterns policies are
written against, so a read of `../.ssh/id_rsa` would slip past a rule
guarding `/Users/*/.ssh/*`.

The extension resolves paths against the session's working directory before
sending them, and the adapter resolves anything still relative against the
payload's `cwd`.  A relative path arriving with no `cwd` at all is blocked
rather than evaluated.

This affects how you write policies, in a good way: rules can assume
absolute paths under Pi, as they do for the other sources.

## Where the extension goes

Pi auto-discovers extensions from its global and project directories, and
those directories are a union rather than a fallback chain.  A user-level
extension and a project-level extension therefore both load and both receive
`tool_call`.  That is redundant but harmless -- the second check reaches the
same verdict as the first, at the cost of one extra evaluation.

Vectimus writes `vectimus.ts` into:

- **Global (default):** `~/.pi/agent/extensions/`.  Note the `agent`
  segment; `~/.pi/extensions/` is not scanned.
- **Project (`--project`):** `./.pi/extensions/`, with no `agent` segment.

Pi also loads extensions listed in `settings.json` and ones passed with
`pi -e <path>`.  Vectimus does not touch either, so if you manage extensions
that way, point the entry at the installed file.

The file carries a `VECTIMUS-MANAGED extension-version: N` marker on its
first line.  `vectimus init` replaces it only when the marker is present
*and* the contents match a version Vectimus shipped; an edited file is left
alone with a message, and so is a file from a newer Vectimus.
`vectimus remove` deletes it only while the marker is intact.  Writes go
through a temp file and a rename, so an interrupted install cannot leave a
half-written extension behind.

## Upgrading and downgrading

Upgrade Vectimus, then re-run `vectimus init` so the extension file matches,
and stop the evaluation daemon (`vectimus daemon stop`; the next hook call
starts a fresh one).  A daemon left running from an older install still has
the old adapters loaded, and will deny `--source pi` as an unknown source
until it is replaced.

Before downgrading to a Vectimus older than 0.23.0, run `vectimus remove`.
A 0.23 extension talking to a CLI that has never heard of `--source pi`
fails closed on every tool call -- correct behaviour, but it looks like the
agent has locked up.

## Not covered

Extensions run in Pi's own process, so an extension loaded before Vectimus
that mutates `event.input` in place changes the arguments Vectimus then
inspects, and one loaded after it can mutate them again afterwards.  A
single-extension install is the supported deployment; if you run others
alongside Vectimus, their ordering is worth checking.

### Known event-model limitations (tracked)

Path-based controls (which file may be read or written) apply normally. The
gaps below are in the *content* and *scope* dimensions and are tracked for a
dedicated fix; several also affect the older adapters.

- **Unscoped recursive reads.** `grep`, `find` and `ls` invoked without a
  `path` operate on the working directory, but the event carries no path, so
  path policies do not match the effective scope
  ([#71](https://github.com/vectimus/vectimus/issues/71)).
- **Multi-edit content inspection.** `edit` joins its replacement chunks with
  a newline, so a string that a content rule would catch can be split across
  two adjacent replacements to evade inspection. Path rules on the edited
  file still apply ([#72](https://github.com/vectimus/vectimus/issues/72)).
- **Symlinked paths** are matched lexically, so a link into a protected
  directory is judged on the link's own path
  ([#74](https://github.com/vectimus/vectimus/issues/74); product-wide).
