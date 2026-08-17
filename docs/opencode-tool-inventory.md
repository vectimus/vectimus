# OpenCode tool inventory

Source of truth for `src/vectimus/adapters/opencode.py`.  Built from the
OpenCode source at tag `v1.18.18`, not from documentation or guesswork:

| Fact | Where it comes from |
|------|---------------------|
| Built-in tool IDs | `packages/opencode/src/tool/registry.ts` (the `Tool.init` block) plus each tool's own `Tool.define(<id>, ...)` |
| Argument schemas | The `Parameters` (`Schema.Struct`) export in each `packages/opencode/src/tool/*.ts` |
| `bash` tool ID | `packages/opencode/src/tool/shell/id.ts` -- `export const ToolID = "bash"` ("Keep the exposed tool ID and permission key as `bash` for compatibility ... Rename with opencode 2.0") |
| MCP resource tool IDs | `packages/opencode/src/session/tools.ts` -- `MCP_RESOURCE_TOOLS` |
| MCP tool naming | `packages/opencode/src/mcp/catalog.ts` -- `toolName()` and `sanitize()` |
| Hook payload shape | `packages/plugin/src/index.ts` -- the `tool.execute.before` entry in `Hooks` |
| Plugin directory glob | `packages/opencode/src/config/plugin.ts` -- `Glob.scan("{plugin,plugins}/*.{ts,js}")` |

Re-verify this table when bumping the supported OpenCode version.  A tool
that OpenCode adds and this table does not list is **denied**, not guessed
at -- see [Unlisted tools](#unlisted-tools).

## What the plugin sends

`tool.execute.before` receives `(input, output)` where `input` is
`{ tool, sessionID, callID }` and `output` is `{ args }`.  There is no
working directory in the hook payload, so the plugin takes it from
`PluginInput.directory`, captured when OpenCode loads the plugin.

```json
{
  "tool_name": "bash",
  "tool_input": { "command": "rm -rf /" },
  "hook_event_name": "PreToolUse",
  "session_id": "ses_...",
  "call_id": "call_...",
  "cwd": "/abs/path/to/project"
}
```

## Built-in tools

`Required args` are enforced by the adapter: a recognised tool whose
required argument is missing, empty or the wrong type raises, and the
normalisation-error path denies.  Optional arguments are recorded in
`raw_input` and are not required to be present.

| Tool ID | Required args | Optional args | Action type | Fields extracted |
|---------|---------------|---------------|-------------|------------------|
| `bash` | `command` | `timeout`, `workdir` | `shell_command`, then refined by `_refine_shell_action` (may become `file_read`, `file_write`, `git_operation`, `package_operation`, `infrastructure`) | `command`, `file_path` when the command reads or writes a file, `script_content` when it runs a script |
| `read` | `filePath` | `offset`, `limit` | `file_read` | `file_path` |
| `glob` | `pattern` | `path` | `file_read` | `file_path` from `path` when given |
| `grep` | `pattern` | `path`, `include` | `file_read` | `file_path` from `path` when given |
| `edit` | `filePath`, `oldString`, `newString` | `replaceAll` | `file_write` | `file_path`, `file_content` from `newString` |
| `write` | `filePath`, `content` | -- | `file_write` | `file_path`, `file_content` |
| `apply_patch` | `patchText` | -- | `file_write` | `file_path` from the patch header, `file_content` from `patchText`.  Multi-file patches deny -- see [apply_patch](#apply_patch) |
| `task` | `description`, `prompt`, `subagent_type` | `task_id`, `command`, `background` | `agent_spawn` | synthetic `command` (`spawn subagent_type=... background=true`) so the agent-governance pack matches |
| `webfetch` | `url` | `format`, `timeout` | `web_request` | `url` |
| `websearch` | `query` | `numResults`, `livecrawl`, `type`, `contextMaxCharacters` | `web_request` | none (a search has no URL); the query stays in `raw_input` |
| `lsp` | `operation`, `filePath`, `line`, `character` | `query` | `file_read` | `file_path` |
| `skill` | `name` | -- | `file_read` | none; the skill name stays in `raw_input` |
| `todowrite` | `todos` | -- | `agent_message` | none |
| `question` | `questions` | -- | `agent_message` | none |
| `plan_exit` | -- | -- | `agent_message` | none |
| `invalid` | `tool`, `error` | -- | `agent_message` | none |
| `execute` | `code` | -- | `shell_command` | `command` from `code` |
| `list_mcp_resources` | -- | `server` | `mcp_tool` | `mcp_server` from `server`, `mcp_tool` = the tool ID |
| `list_mcp_resource_templates` | -- | `server` | `mcp_tool` | `mcp_server` from `server`, `mcp_tool` = the tool ID |
| `read_mcp_resource` | `server`, `uri` | -- | `mcp_tool` | `mcp_server`, `mcp_tool` = the tool ID |

Notes on the less obvious rows:

- `lsp`, `plan_exit` and `execute` are behind runtime flags
  (`experimentalLspTool`, `experimentalPlanMode`, `experimentalCodeMode`).
  They are mapped anyway so enabling a flag does not turn into a lockout.
- `execute` (code mode) runs a script in a confined interpreter that calls
  other tools.  It maps to `shell_command` so the code-execution pack
  inspects the script body.
- `todowrite`, `question`, `plan_exit` and `invalid` have no filesystem,
  network or process effect -- they update session state or render a
  prompt.  They map to `agent_message` with no `command`, which no rule in
  the shipped packs matches.  They are listed rather than left unmapped so
  that a normal OpenCode session is not blocked by the unlisted-tool deny.
- `skill` loads a skill's instructions into context.  It maps to
  `file_read` with no path, so no secrets rule fires on it today.  Skill
  content is a prompt-injection surface that Vectimus does not yet inspect.
- `apply_patch` is only offered to GPT models (`registry.ts` swaps
  `edit`/`write` for `apply_patch` when the model ID contains `gpt-`), so
  most sessions never see it.

### apply_patch

`apply_patch` takes one `patchText` that can touch several files:

```
*** Begin Patch
*** Update File: src/app.ts
...
*** Add File: .env
...
*** End Patch
```

A `VectimusEvent` carries a single `file_path`, so a multi-file patch
cannot be evaluated per target in one call -- a patch that edits an
innocuous file first would carry that path past a `file_path` rule while
still writing `.env`.  Rather than evaluate only the first target, the
adapter **denies multi-file patches** and asks for one patch per file.
Single-file patches normalise as an ordinary `file_write`.

Evaluating each target and combining the verdicts needs a change in
`hook_cmd` (one payload, several events), which is a follow-up.

## MCP tools

OpenCode exposes an MCP tool to the model under
`sanitize(serverName) + "_" + sanitize(toolName)`, where
`sanitize = (v) => v.replace(/[^a-zA-Z0-9_-]/g, "_")`
(`packages/opencode/src/mcp/catalog.ts`).  That name is what arrives in
`tool.execute.before`.

The format is not reversible.  Both halves may contain `_`, and the
separator is a single `_`, so `github_create_issue` splits as
`github` + `create_issue`, `github_create` + `issue` or
`github_create_issue` + `` with equal justification, and the sanitiser
maps distinct server names onto the same string.  There is no delimiter,
length prefix or server list in the hook payload to break the tie.

The adapter therefore does not guess.  An MCP tool call reaches the
adapter as an unlisted tool name and is **denied**, with a reason naming
the tool.  Note the shipped `vectimus-mcp-001` rule already denies any
`mcp_tool` whose server is not on the approved list, so a correct split
would not change the outcome for an unapproved server -- only for an
approved one.

Restoring MCP coverage under OpenCode means giving the adapter the
connected server names so the split can be resolved uniquely (and denied
when it cannot).  OpenCode can supply them: the plugin receives an SDK
`client` in `PluginInput`, and configured servers are readable from
OpenCode config.  That is a follow-up, not part of this change.

The three MCP *resource* tools are different: `list_mcp_resources`,
`list_mcp_resource_templates` and `read_mcp_resource` are fixed built-in
IDs that carry the server name in an argument, so they normalise cleanly
to `mcp_tool` with a real `mcp_server`.

## Unlisted tools

Anything not in the tables above -- a tool OpenCode adds in a later
version, an MCP tool, a user-defined tool from `tool/*.ts`, or a tool
contributed by another plugin -- raises in the adapter, and the
normalisation-error path denies with a reason naming the tool.  There is
no `shell_command` fallback: guessing an action type for an unknown tool
would evaluate it against the wrong rules and report a pass it did not
earn.

## Plugin install locations

`packages/opencode/src/config/plugin.ts` scans `{plugin,plugins}/*.{ts,js}`
in every config directory, so both the singular and plural spellings load.
Vectimus writes the singular `plugin/`.

Config directories come from `ConfigPaths.directories`
(`packages/opencode/src/config/paths.ts`), in this order:

1. `Global.Path.config` -- `$XDG_CONFIG_HOME/opencode`, or
   `~/.config/opencode` when `XDG_CONFIG_HOME` is unset
2. every `.opencode` directory from the current directory up to the
   worktree root, unless `OPENCODE_DISABLE_PROJECT_CONFIG` is set
3. `~/.opencode`
4. `$OPENCODE_CONFIG_DIR`, when set

The list is a union, not a fallback chain: a global plugin and a project
plugin both load and both run.
