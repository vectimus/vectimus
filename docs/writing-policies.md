# Writing policies

Vectimus uses the [Cedar policy language](https://www.cedarpolicy.com/) for governance rules.  Each rule evaluates a normalised event and returns allow, deny or escalate.

## Policy file format

Place `.cedar` files in your policy directory (default: `./policies` or the built-in `policies/base/`).  Each file can contain multiple rules grouped by theme.

## Annotations

Every rule should include:

- `@id("unique-id")` -- a unique identifier (must be unique across all packs)
- `@description("human readable text")` -- what the rule does
- `@incident("reference")` -- the real-world incident that motivated it (where applicable)
- `@controls("SOC2-CC6.1")` -- compliance controls it satisfies (where applicable)
- `@suggested_alternative("try this instead")` -- what the agent should do instead

Duplicate `@id` values across packs will cause a load-time error.  This is intentional: shadowed rules are a bug.

## Example rule

```cedar
@id("custom-001")
@description("Block writes to production database config")
@suggested_alternative("Propose config changes via a pull request for human review.")
forbid (
    principal,
    action == Vectimus::Action::"file_write",
    resource
) when {
    context.file_path like "*production*database*"
};
```

## Action types

The normaliser maps tool-specific actions to these types:

| Action type | Description |
|------------|-------------|
| `shell_command` | Bash, terminal, shell execution |
| `file_write` | Write, Edit, file creation |
| `file_read` | Read, Grep, Glob, file access |
| `web_request` | WebFetch, curl, HTTP calls |
| `mcp_tool` | Any MCP server tool invocation |
| `package_operation` | npm, pip, cargo operations |
| `git_operation` | git push, commit, branch operations |
| `infrastructure` | terraform, kubectl, docker, cloud CLI |
| `agent_spawn` | Task, subagent creation |

## Context fields

Policies can match on these context attributes:

| Field | Available on | Description |
|-------|-------------|-------------|
| `context.command` | shell_command, package_operation, infrastructure, mcp_tool | Shell command text |
| `context.file_path` | file_write, file_read, mcp_tool | Target file path |
| `context.url` | web_request, mcp_tool | Target URL |
| `context.cwd` | all | Working directory |
| `context.mcp_server` | mcp_tool | MCP server name (from tool name) |
| `context.mcp_tool` | mcp_tool | MCP tool name (from tool name) |
| `context.package_name` | package_operation | Package being installed/published |

## MCP tool policies

Vectimus intercepts the agent's *request* to call an MCP tool before it is sent to the server.  It does not observe what happens on the MCP server.  Policies can inspect:

1. **Server name** (`context.mcp_server`) -- extracted from the tool name (e.g. `mcp__github__create_issue` yields `github`)
2. **Tool name** (`context.mcp_tool`) -- extracted from the tool name (e.g. `create_issue`)
3. **Input parameters** (`context.command`, `context.file_path`, `context.url`) -- whatever the agent passes as tool inputs

A tool that internally accesses credentials or writes to CI/CD pipelines without exposing that in its input parameters will not be caught.  The most effective MCP control is server allowlisting.

### Server allowlisting

By default, rule `vectimus-base-030` blocks all MCP tool calls.  Approve servers via the CLI:

```bash
vectimus mcp allow github
vectimus mcp allow slack
```

Or via environment variable:

```bash
export VECTIMUS_MCP_ALLOWED="github,slack,jira"
```

The loader rewrites rule 030 at load time with a Cedar `unless` clause listing approved servers.  Unapproved servers are blocked regardless of tool name or input.

### Input inspection (defence in depth)

Rules 032-036 check tool inputs for sensitive patterns on approved servers:

- **032**: Credential and secret paths in `file_path`
- **033**: Private key files in `file_path`
- **034**: CI/CD pipeline files in `file_path`
- **035**: Dangerous shell commands in `command`
- **036**: Governance config files in `file_path`

These rules catch recognisable patterns in tool parameters but cannot catch tools that do sensitive things without exposing it in their input schema.

## Rule management

Users can disable individual rules globally or per-project via the CLI:

```bash
# Disable for current project only
vectimus rule disable custom-001

# Disable everywhere
vectimus rule disable custom-001 --global
```

Per-project overrides are stored in `.vectimus/config.toml` in the project root.  See [Getting started](getting-started.md) for the full precedence model.

### Deny messages and override hints

When a rule blocks an action, the deny reason shown to the agent must never include instructions on how to disable the rule.  If the agent sees override instructions it will attempt to run `vectimus rule disable` itself.  The built-in base pack includes a rule (`vectimus-base-021`) that blocks agents from running vectimus CLI commands for exactly this reason.

Override hints should only appear on stderr, which is visible to the human operator but not parsed by the agent:

```python
# stdout (agent-visible): clean deny reason only
print(json.dumps({"permissionDecision": "deny", "permissionDecisionReason": reason}))

# stderr (human-visible): override hints
print(f"vectimus: To disable for this project: vectimus rule disable {pid}", file=sys.stderr)
print(f"vectimus: To disable everywhere: vectimus rule disable {pid} --global", file=sys.stderr)
```

## Custom policy packs

To create a custom pack, add a directory under `~/.vectimus/packs/` with a `pack.toml` manifest:

```
~/.vectimus/packs/my-team/
  pack.toml
  my-rules.cedar
```

```toml
[pack]
name = "my-team"
version = "1.0.0"
description = "Team-specific governance rules"
author = "My Team"
```

The pack is automatically discovered and loaded on the next evaluation.

## Testing policies

Use `vectimus test` to validate your policies against sample events.  You can also provide a custom JSON file:

```bash
vectimus test --file my-test-events.json --policy-dir ./my-policies
```
