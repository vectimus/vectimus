# OpenCode

[OpenCode](https://opencode.ai/) is guarded by a plugin rather than a hooks
config.  `vectimus init` installs it; every tool call then goes through
`vectimus hook --source opencode` before OpenCode runs it.

```bash
vectimus init             # installs to the user-level OpenCode config dir
vectimus init --project   # installs to ./.opencode/plugin/ instead
vectimus status           # shows which plugin file is in place
vectimus remove           # deletes it
```

Support is experimental.  Verified against OpenCode 1.18.18.

## How blocking works

OpenCode plugins have one way to stop a tool call: throw from
`tool.execute.before`.  There is no deny verdict to return and no way to ask
the user.  So the plugin allows a call only when `vectimus hook` exits 0 with
nothing on stdout **and** writes its allow acknowledgement (on fd 3), and
throws in every other case:

| What happened | Result |
|---------------|--------|
| Exit 0, empty stdout, allow acknowledged | **Allowed** |
| Exit 0, empty stdout, no acknowledgement | Blocked |
| Deny payload on stdout | Blocked, with the policy's reason |
| Output that is not JSON | Blocked |
| Output that parses but is not a deny | Blocked |
| Non-zero exit, even with empty stdout | Blocked |
| Killed by a signal | Blocked |
| `vectimus` not on PATH | Blocked |
| No answer within 30 seconds | Child killed, blocked |

Empty stdout on its own is not an allow.  A hook that crashed prints exactly
what an allow prints, so the exit code has to agree -- and so must the
acknowledgement.  A replaced or broken `vectimus` -- `/usr/bin/true`, a shim
that never reads the call -- exits 0 silently too; only the real allow path
emits the acknowledgement, so without it the call is blocked.

Override the deadline with `VECTIMUS_PLUGIN_TIMEOUT_MS` if 30 seconds is
wrong for your setup.  Lowering it makes Vectimus block sooner under load,
not allow sooner.

## Escalate is a hard block

A policy with `escalate` enforcement blocks under OpenCode, the same as
`deny`, and the reason is prefixed `[escalate]`.  OpenCode's
`permission.ask` hook could in principle prompt the user instead; wiring
that up is tracked in
[#53](https://github.com/vectimus/vectimus/issues/53).  Until then, treat
escalate as deny -- which is what it already does for Claude Code.

## What is covered

Every built-in OpenCode tool: `bash`, `read`, `write`, `edit`,
`apply_patch`, `glob`, `grep`, `webfetch`, `websearch`, `task`, `skill`,
`lsp`, `todowrite`, `question`, `plan_exit`, `execute` and the three MCP
resource tools.  The full table, with the argument each policy matches on,
is in [opencode-tool-inventory.md](opencode-tool-inventory.md).

Three things are deliberately blocked rather than evaluated:

- **Tools Vectimus does not recognise.**  A tool added by a newer OpenCode,
  by a project's own `tool/*.ts`, or by another plugin has no known argument
  schema, so there is nothing to evaluate.  Guessing an action type would
  report a pass the call did not earn.  If a new OpenCode release blocks
  something you need, upgrade Vectimus or open an issue -- the inventory is
  versioned against OpenCode releases.
- **MCP tool calls.**  OpenCode names them `server_tool` after replacing
  every character outside `[A-Za-z0-9_-]` with `_`, so `github_create_issue`
  could be `github` + `create_issue` or `github_create` + `issue`.  Nothing
  in the payload breaks the tie.  Note the shipped `vectimus-mcp-001` rule
  denies unapproved MCP servers anyway, so this only costs coverage for
  servers you had approved.
- **Multi-file `apply_patch` calls.**  One evaluation carries one file path.
  A patch that edits an innocuous file first would carry that path past a
  path rule while still writing the others.  Send one patch per file.
  `apply_patch` only appears for GPT models, so most sessions never hit it.

## Where the plugin goes

OpenCode scans `{plugin,plugins}/*.{ts,js}` in each of its config
directories, and those directories are a union rather than a fallback chain.
A user-level plugin and a project-level plugin therefore both load and both
run.  That is redundant but harmless -- the second check reaches the same
verdict as the first, at the cost of one extra evaluation.

Vectimus writes `vectimus.ts` into the singular `plugin/` directory of:

- **Global (default):** `$XDG_CONFIG_HOME/opencode/plugin/`, or
  `~/.config/opencode/plugin/` when `XDG_CONFIG_HOME` is unset.
- **Project (`--project`):** `./.opencode/plugin/`.

The file carries a `VECTIMUS-MANAGED plugin-version: N` marker on its first
line.  `vectimus init` replaces it only when the marker is present *and* the
contents match a version Vectimus shipped; an edited file is left alone with
a message, and so is a file from a newer Vectimus.  `vectimus remove`
deletes it only while the marker is intact.  Writes go through a temp file
and a rename, so an interrupted install cannot leave a half-written plugin
behind -- which, under the contract above, would block every tool call.

## Recommended: a native permission backstop

The plugin is the only full-coverage guard, but it is a file, and files get
deleted, renamed or fail to load.  OpenCode's own declarative permissions
cost nothing while the plugin is working -- OpenCode prompts only when its
own pattern matches, and by then Vectimus has already allowed the call -- so
they are worth setting as a backstop.  In your OpenCode config:

```json
{
  "$schema": "https://opencode.ai/config.json",
  "permission": {
    "bash": {
      "rm *": "ask",
      "sudo *": "ask",
      "git push --force*": "ask"
    }
  }
}
```

OpenCode matches these patterns last-match-wins against the command string.
This is coarse: it matches command prefixes, not policy, and it asks rather
than blocks.  It catches the plugin-is-gone case and nothing more.  Verify
it by renaming the plugin file and checking that the prompt still appears.

## Upgrading and downgrading

Upgrade Vectimus, then re-run `vectimus init` so the plugin file matches,
and stop the evaluation daemon (`vectimus daemon stop`; the next hook call
starts a fresh one).  A daemon left running from an older install still has
the old adapters loaded, and will deny `--source opencode` as an unknown
source until it is replaced.

Before downgrading to a Vectimus older than 0.23.0, run `vectimus remove`.
A 0.23 plugin talking to a CLI that has never heard of `--source opencode`
fails closed on every tool call -- correct behaviour, but it looks like the
agent has locked up.

## Not covered

If OpenCode runs behind a gateway that answers with its own built-in agent
instead of spawning OpenCode, no OpenCode plugin sees those tool calls.
That path is governed by whatever the gateway itself enforces.

### Known event-model limitations (tracked)

Path-based controls (which file may be read or written) apply normally. The
gaps below are in the *content* and *scope* dimensions and are tracked for a
dedicated fix; several also affect the older adapters.

- **Unscoped recursive reads.** `grep` and `glob` invoked without a `path`
  read the working directory recursively, but the event carries no path, so
  path policies do not match the effective scope
  ([#75](https://github.com/vectimus/vectimus/issues/75)).
- **Unscoped MCP resource listing.** `list_mcp_resources` /
  `list_mcp_resource_templates` carry no server, so the MCP server allowlist
  does not constrain them ([#77](https://github.com/vectimus/vectimus/issues/77)).
- **Symlinked paths** are matched lexically, so a link into a protected
  directory is judged on the link's own path
  ([#78](https://github.com/vectimus/vectimus/issues/78); product-wide).
