# Pi tool inventory

Source of truth for `src/vectimus/adapters/pi.py`.  Built from the
installed `@mariozechner/pi-coding-agent` **0.73.1** package and from
payloads captured out of a real Pi session, not from documentation or
guesswork:

| Fact | Where it comes from |
|------|---------------------|
| Built-in tool IDs | `dist/core/tools/index.d.ts` -- the `ToolName` union and `allToolNames` |
| Argument schemas | the `*Schema = Type.Object({...})` literal in each `dist/core/tools/*.js` |
| Event shape | `dist/core/extensions/types.d.ts` -- `ToolCallEvent` and its per-tool members |
| Block contract | `dist/core/extensions/types.d.ts` -- `ToolCallEventResult`; `dist/core/extensions/runner.js` -- `emitToolCall`; `node_modules/@mariozechner/pi-agent-core/dist/agent-loop.js` -- `prepareToolCall` |
| Argument preparation order | `agent-loop.js` -- `prepareToolCallArguments` -> `validateToolArguments` -> `beforeToolCall` |
| Extension discovery | `docs/extensions.md` -- "Extension Locations", confirmed by running Pi with a global and a project extension at once |

Re-verify this table when bumping the supported Pi version.  A tool Pi
adds and this table does not list is **denied**, not guessed at -- see
[Unlisted tools](#unlisted-tools).

## What the extension sends

Pi's hook is the `tool_call` event, not a `PreToolUse` process hook.  The
extension receives `(event, ctx)` where `event` is
`{ type, toolName, toolCallId, input }` and `ctx` carries the working
directory and the session manager.  Issue #51 described Pi's payload as
Claude-compatible; it is not.  The field names differ (`toolName` /
`input`, not `tool_name` / `tool_input`), the file argument is `path`
rather than `file_path`, and `edit` takes an array of replacements.  The
extension therefore translates into the shape the Vectimus CLI already
reads:

```json
{
  "tool_name": "bash",
  "tool_input": { "command": "rm -rf ~/Development" },
  "hook_event_name": "PreToolUse",
  "session_id": "01J...",
  "call_id": "call_zycm2by3",
  "cwd": "/abs/path/to/project"
}
```

Captured verbatim from a live session (`tool_call` for `write`):

```json
{
  "type": "tool_call",
  "toolName": "write",
  "toolCallId": "call_uu1vqjce",
  "input": { "path": "notes.txt", "content": "alpha beta\n" }
}
```

`session_id` comes from `ctx.sessionManager.getSessionId()` and is absent
under `--no-session`.  `cwd` comes from `ctx.cwd`; it is required, for the
reason in [Relative paths](#relative-paths).

## What Pi guarantees before the hook runs

`prepareToolCall` in `agent-loop.js` runs, in this order:

1. `prepareToolCallArguments` -- each tool's own `prepareArguments` shim
2. `validateToolArguments` -- typebox validation against the tool schema
3. `beforeToolCall` -- the `tool_call` event, i.e. this extension
4. `executePreparedToolCall` -- with the *same* args object the hook saw

Three consequences the adapter relies on:

- Arguments reaching the adapter have already passed schema validation, so
  a missing required argument normally fails before Vectimus is consulted.
  The adapter still checks, because the extension is also driven directly
  by tests and because a future Pi could reorder these steps.
- `edit`'s legacy top-level `{ oldText, newText }` form is folded into
  `edits[]` by `prepareEditArguments` before the hook sees it, so the
  adapter only has to understand the array form.  It accepts the legacy
  form anyway rather than deny a shape Pi itself accepts.
- There is no re-read between the check and the execution, so no
  time-of-check/time-of-use gap on the arguments.

An unregistered tool name is rejected by Pi (`Tool X not found`) before
the hook, so the adapter's unknown-tool deny is a backstop, not the
primary path.

## Built-in tools

Pi ships exactly seven tools, all lowercase (`ToolName` in
`dist/core/tools/index.d.ts`).  `Required args` are enforced by the
adapter: a recognised tool whose required argument is missing, empty or
the wrong type raises, and the normalisation-error path denies.  Optional
arguments are recorded in `raw_input` and are not required to be present.

| Tool ID | Required args | Optional args | Action type | Fields extracted |
|---------|---------------|---------------|-------------|------------------|
| `bash` | `command` | `timeout` | `shell_command`, then refined by `_refine_shell_action` (may become `file_read`, `file_write`, `git_operation`, `package_operation`, `infrastructure`) | `command`, `file_path` when the command reads or writes a file, `script_content` when it runs a script |
| `read` | `path` | `offset`, `limit` | `file_read` | `file_path` |
| `write` | `path`, `content` | -- | `file_write` | `file_path`, `file_content` |
| `edit` | `path`, plus replacements (`edits`, or the legacy top-level pair) | -- | `file_write` | `file_path`, `file_content` from the joined `newText` values -- see [edit](#edit) |
| `grep` | `pattern` | `path`, `glob`, `ignoreCase`, `literal`, `context`, `limit` | `file_read` | `file_path` from `path` when given |
| `find` | `pattern` | `path`, `limit` | `file_read` | `file_path` from `path` when given |
| `ls` | -- | `path`, `limit` | `file_read` | `file_path` from `path` when given |

Notes on the less obvious rows:

- `ls` has no required argument at all: its `path` is optional and
  defaults to the working directory.  `grep` and `find` require only
  `pattern`; their `path` is likewise optional.  Treating a missing
  optional `path` as malformed would deny ordinary sessions, so it is not
  in the required set.
- Pi has **no MCP subsystem** -- there are no MCP files anywhere in the
  package, and no MCP tool names reach the hook.  The OpenCode adapter's
  irreversible-MCP-name problem therefore has no counterpart here.
- Pi has no web-fetch, web-search or sub-agent-spawn tool, so no
  `web_request` or `agent_spawn` row exists for it.

### edit

`edit` takes one `path` and an array of replacements:

```json
{
  "path": "notes.txt",
  "edits": [{ "oldText": "alpha", "newText": "gamma" }]
}
```

Unlike OpenCode's `apply_patch`, every replacement in one call targets the
same single file, so there is no multi-target problem and nothing has to
be denied on those grounds.  A `VectimusEvent` carries one `file_path`,
which is exactly what this call has.

`file_content` is the `newText` values joined with newlines.  That is what
the content-inspection rules (secrets, credentials) need to see: the text
about to enter the file.  `oldText` is the match target, not new content,
so it is not part of `file_content`; both remain in `raw_input`.

The adapter requires a non-empty list of objects each carrying a string
`newText`, and accepts the legacy top-level `{ oldText, newText }` pair as
a single replacement.  Requiring the `edits` name specifically would refuse
a shape Pi itself accepts, so the required-argument table lists only `path`
for this tool and the replacement check lives in one place.

Pi's own `validateEditInput` rejects an empty `edits`, so an empty array
reaching the adapter means something upstream changed; it is denied rather
than treated as a no-op write.

### Relative paths

Pi passes tool paths through **exactly as the model wrote them**, and
models routinely write relative ones -- the captured `write` above is
`"path": "notes.txt"`, not an absolute path.  Pi resolves them against
the session's working directory at execution time.

This matters for policy matching.  `_extract_file_path` in the shared
normaliser only calls `os.path.normpath`; it does not make a path
absolute.  A rule written against `/Users/*/.ssh/*` would therefore never
match a Pi `read` of `../.ssh/id_rsa`, and the call would be allowed on a
technicality.

The adapter closes that by resolving every relative path against the
payload's `cwd` before normalisation.  Both POSIX and Windows path
flavours count as absolute regardless of the host platform: judging
`C:\Users\dev\.ssh\id_rsa` by POSIX rules alone would call it relative
and join it onto the cwd, yielding a path that matches no rule at all.

Recognising a Windows path is only half of it, so the adapter also
rewrites one into a single canonical spelling: traversal collapsed with
`ntpath`, then backslashes folded to forward slashes.
`C:\Users\dev\.ssh\id_rsa` becomes `C:/Users/dev/.ssh/id_rsa`, and
`\\server\share\secrets.txt` becomes `//server/share/secrets.txt`.
Without that, a Windows session judged by a POSIX evaluation server would
pass every path rule it should have failed -- `like "*.ssh/*"` matches
nothing written with backslashes -- and `posixpath` cannot see `..\` as
traversal either.

A relative path with **no** `cwd`
in the payload is denied: without the working directory the path cannot
be made comparable to the paths policies are written against, and
evaluating it anyway would report a pass it did not earn.  The extension
always sends `ctx.cwd`, so this only fires on a hand-built payload.

Pi is the first source Vectimus supports that sends relative paths by
design; the older adapters are not changed here.

## Unlisted tools

Anything not in the table above -- a tool Pi adds in a later version, a
custom tool registered by another extension (these arrive as
`CustomToolCallEvent` with an arbitrary `toolName`), or a tool from an
installed Pi package -- raises in the adapter, and the
normalisation-error path denies with a reason naming the tool.  There is
no `shell_command` fallback: guessing an action type for an unknown tool
would evaluate it against the wrong rules and report a pass it did not
earn.

## How the extension blocks

`ToolCallEventResult` is `{ block?: boolean; reason?: string }`.
Returning `{ block: true, reason }` stops the tool and hands `reason` to
the model as the tool's error result (`prepareToolCall` turns it into
`createErrorToolResult(beforeResult.reason)`).

Throwing also blocks.  `emitToolCall` in `runner.js` deliberately does
**not** wrap `tool_call` handlers in try/catch -- compare `emitUserBash`
just below it, which does swallow errors -- so a throw propagates to
`beforeToolCall`, and `prepareToolCall`'s own try/catch converts it into
an immediate error result without executing the tool.  `docs/extensions.md`
states the intent: "`tool_call` errors block the tool (fail-safe)".

Both paths were verified live against Pi 0.73.1: an extension that
returned `{ block: true }` for a command containing a marker string left
`SPIKE.txt` uncreated, and the throwing variant left `THROWN.txt`
uncreated.

The extension uses the structured return for every decided block, because
it carries a readable reason to the model, and lets genuinely unexpected
exceptions propagate, because those block too.  There is no path on which
a failure results in an allow.

## Extension install locations

`docs/extensions.md` and the loader auto-discover:

| Location | Scope |
|----------|-------|
| `~/.pi/agent/extensions/*.ts` | Global (all projects) |
| `~/.pi/agent/extensions/*/index.ts` | Global (subdirectory) |
| `.pi/extensions/*.ts` | Project-local |
| `.pi/extensions/*/index.ts` | Project-local |

Note the `agent` segment in the global path: it is `~/.pi/agent/extensions/`,
not `~/.pi/extensions/`.  Vectimus writes the flat `*.ts` form in both
scopes.

Extensions may additionally be listed in `settings.json` under
`extensions` or loaded ad hoc with `pi -e <path>`; Vectimus does not
touch either.

Like OpenCode's plugin directories, these are a union rather than a
fallback chain: with a global and a project extension both present, both
load and both receive `tool_call`.  Confirmed by running a session with
one of each and observing both fire on the same call.  Two Vectimus
extensions running at once is redundant but harmless -- the second check
sees the same verdict.
