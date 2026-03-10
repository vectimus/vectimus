# Architecture

Technical reference for the Vectimus evaluation pipeline.  This document covers component responsibilities, data flow and integration schemas.

## Evaluation flow

```
AI Agent (tool call) -> Shim (stdin JSON) -> Normaliser -> Cedar PolicyEngine -> Decision
                                                                                    |
                                                                              Audit Log (JSONL)
```

The MVP path is entirely local.  Command hooks read JSON from stdin, evaluate via cedarpy and return a decision via exit code.  No server, no network, no daemon.

The optional HTTP server (`vectimus server start`) exists for enterprise centralised policy management.

## Data models

All models use Pydantic v2 BaseModel.  See `src/vectimus/core/models.py` for the full definitions.

**VectimusEvent** is the normalised event that Cedar policies evaluate.  Key fields:
- `source` (SourceInfo) -- where the event came from (tool name, version, session)
- `identity` (IdentityInfo) -- who triggered it (principal, persona, groups)
- `action` (ActionInfo) -- what is being attempted (action_type, command, file_path, etc.)
- `context` (ContextInfo) -- environmental context (repo, branch, cwd)

**Decision** is the governance result:
- `decision` -- "allow", "deny" or "escalate"
- `reason` -- human-readable explanation (mandatory for deny)
- `suggested_alternative` -- what the agent should try instead (mandatory for deny)
- `matched_policy_ids` -- which policies triggered

**AuditRecord** pairs a VectimusEvent with its Decision for the audit log.

## Action types

Normalised across all tools:

| Action type | Examples |
|---|---|
| `shell_command` | Bash, terminal, shell execution |
| `file_write` | Write, Edit, MultiEdit, file creation |
| `file_read` | Read, Grep, Glob, file access |
| `web_request` | WebFetch, curl, HTTP calls |
| `mcp_tool` | Any MCP server tool invocation |
| `package_operation` | npm, pip, cargo, yarn |
| `git_operation` | git push, commit, branch operations |
| `infrastructure` | terraform, kubectl, docker, cloud CLI |
| `agent_spawn` | Task, subagent creation |

Shell commands are further classified: commands starting with `terraform`/`kubectl`/`docker` map to `infrastructure`, `npm`/`pip`/`cargo`/`yarn` to `package_operation`, `git` to `git_operation`.

## Normaliser input schemas

The normaliser accepts tool-specific JSON and produces VectimusEvent objects.  New tools are added by registering a normaliser function.

### Claude Code

```json
{
  "tool_name": "Bash",
  "tool_input": { "command": "rm -rf /tmp/build" },
  "tool_use_id": "uuid",
  "session_id": "uuid",
  "cwd": "/home/user/project",
  "hook_event_name": "PreToolUse"
}
```

Tool name mapping:

| Tool name | Action type |
|---|---|
| `Bash` | `shell_command` |
| `Write`, `Edit`, `MultiEdit` | `file_write` |
| `Read`, `Grep`, `Glob` | `file_read` |
| `WebFetch`, `WebSearch` | `web_request` |
| `Task` | `agent_spawn` |
| `mcp__*` | `mcp_tool` |

### Cursor

```json
{
  "conversation_id": "uuid",
  "generation_id": "uuid",
  "command": "rm -rf /tmp/build",
  "cwd": "/home/user/project",
  "hook_event_name": "beforeShellExecution",
  "workspace_roots": ["/home/user/project"]
}
```

Event mapping: `beforeShellExecution` -> `shell_command`, `beforeMCPExecution` -> `mcp_tool`, `beforeReadFile` -> `file_read`, `afterFileEdit` -> `file_write`.

### GitHub Copilot / VS Code

```json
{
  "timestamp": "2026-03-08T14:30:00.000Z",
  "cwd": "/home/user/project",
  "sessionId": "uuid",
  "hookEventName": "PreToolUse",
  "tool_name": "Bash",
  "tool_input": { "command": "rm -rf /tmp/build" }
}
```

## Cedar schema

The Cedar schema defines entity types, actions and context shapes.  See `src/vectimus/core/schemas.py` for the full definition.

Entity types: `User`, `Agent`, `Tool`.

Each action type (`shell_command`, `file_write`, etc.) applies to `[User, Agent]` principals and `Tool` resources with a context containing a `parameters` record.

## Cedar policy conventions

Every policy rule must have:
- `@id("vectimus-base-NNN")` or `@id("owasp-NNN")` -- unique identifier
- `@description("...")` -- human-readable explanation
- `@incident("...")` -- real-world incident reference (where applicable)
- `@controls("...")` -- compliance controls it satisfies (where applicable)

See [Writing policies](writing-policies.md) for the full guide.

## Server endpoints (enterprise, opt-in)

Activated via `vectimus server start`.  Not part of the default MVP flow.

| Method | Path | Purpose |
|---|---|---|
| POST | `/evaluate` | Evaluate a tool event against policies |
| GET | `/policies` | List loaded policies with metadata |
| GET | `/health` | Server status, policy count, uptime |
| GET | `/events` | SSE stream of real-time evaluation events |

The `/evaluate` endpoint accepts an `X-Vectimus-Source` header to identify the source tool.  For Claude Code HTTP hooks, the response includes `hookSpecificOutput` with `permissionDecision` and `permissionDecisionReason`.

## Configuration

Locations (in order of precedence):
1. Environment variables (`VECTIMUS_PERSONA`, `VECTIMUS_CONTENT_MAX_LINES`, etc.)
2. `.vectimus/config.toml` (project-local, version-controllable)
3. `~/.vectimus/config.toml` (user-level global)
4. Hardcoded defaults

```toml
[identity]
persona = "default"
groups = ["engineering", "platform"]
identity_type = "human"

[limits]
content_inspection_max_lines = 5000
excessive_turns_threshold = 50
session_spawn_limit = 10
session_message_limit = 50
session_ttl_seconds = 3600
git_timeout_seconds = 5

[audit]
max_file_size_mb = 100
log_dir = "~/.vectimus"

[rules]
disabled = []
```

The `.vectimus/` directory in the project root is protected by Cedar policy `vectimus-base-020e`, preventing agents from modifying governance config.
