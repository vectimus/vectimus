# Getting started

## Installation

```bash
pipx install vectimus
```

Or with uv:

```bash
uv tool install vectimus
```

## Initialise

Run `vectimus init` in your project directory.  It detects which AI coding tools you have installed and generates the appropriate hook configurations.

```bash
vectimus init
```

If you already have hooks configured for Claude Code, Cursor or Copilot, `vectimus init` merges its hooks with your existing ones.  Your custom hooks are preserved.

## Observe mode

Before enforcing policies, run Vectimus in observe mode to see what would be blocked.  All decisions are logged to the audit trail but no actions are denied.

```bash
vectimus observe on
```

Review the audit log at `~/.vectimus/logs/` to understand which actions your policies would block.  When you're satisfied, switch to enforcement:

```bash
vectimus observe off
```

You can check the current mode at any time:

```bash
vectimus observe status
```

For CI/CD pipelines, set the environment variable instead:

```bash
export VECTIMUS_OBSERVE=true
```

## Test your policies

```bash
vectimus test
```

This evaluates a set of built-in test events against your loaded policies and prints a summary table.

## MCP server allowlist

Vectimus blocks all MCP tool calls by default (rule `vectimus-base-030`).  This prevents agents from communicating with unapproved MCP servers.

### Auto-discovery during init

`vectimus init` reads MCP server names from your existing tool configs and prompts you to approve them:

```
MCP servers detected:
  Claude Code:  posthog, slack
  Cursor:       github

Allow all 3 servers? [y/N]: n
  Allow github? [Y/n]: y
  Allow posthog? [Y/n]: y
  Allow slack? [Y/n]: n

Approved 2 MCP server(s): github, posthog
```

If you decline the bulk prompt, each server is offered individually (default yes).  To skip prompts entirely and approve all discovered servers:

```bash
vectimus init --allow-mcp
```

It reads from these config files:

| Tool | Config path | Key |
|------|-------------|-----|
| Claude Code | `~/.claude/settings.json` | `mcpServers` |
| Cursor | `~/.cursor/mcp.json` | `mcpServers` |
| VS Code | `~/.vscode/mcp.json` | `servers` |

### Manual management

You can manage the allowlist at any time:

```bash
# Approve servers one at a time
vectimus mcp allow github
vectimus mcp allow slack

# View the current allowlist
vectimus mcp list

# Remove a server from the list
vectimus mcp deny evil-server
```

For CI/CD or container deployments, use the environment variable:

```bash
export VECTIMUS_MCP_ALLOWED="github,slack,jira"
```

The environment variable merges with the config file list.

**How it works:** Vectimus intercepts the agent's request to call an MCP tool before it is sent.  It sees the server name, tool name and input parameters.  It does not observe what happens on the MCP server.  Server allowlisting blocks the request entirely if the server is not approved.  Input inspection rules add defence in depth by checking tool parameters for credential paths, CI/CD files and dangerous commands.

## Project-local configuration

Vectimus supports a `.vectimus/config.toml` file in your project root, following the `.claude/` and `.cursor/` convention.  This file is version-controllable and discoverable by your team.

```toml
[identity]
persona = "default"
groups = ["engineering", "platform"]
identity_type = "human"

[limits]
content_inspection_max_lines = 5000
excessive_turns_threshold = 50

[audit]
max_file_size_mb = 100
log_dir = "~/.vectimus"

[rules]
disabled = []
```

**Resolution order:** Environment variables take highest precedence, then project `.vectimus/config.toml`, then global `~/.vectimus/config.toml`, then hardcoded defaults.

The `.vectimus/` directory is protected by policy `vectimus-base-020e` — agents cannot modify it.  Changes must be made by a human via the CLI or editor.

## Rule management

Vectimus ships with built-in policy packs.  You can manage individual rules via the CLI:

```bash
# List all rules and their status
vectimus rule list

# Show full details for a rule
vectimus rule show vectimus-base-007
```

### Per-project rule overrides

You can disable specific rules for a specific project without affecting your global policy.  This is useful when a project legitimately needs operations that a rule would otherwise block.

```bash
# Disable a rule for the current project only
vectimus rule disable vectimus-base-010

# Disable a rule everywhere
vectimus rule disable vectimus-base-010 --global

# View project-specific overrides
vectimus rule overrides

# Re-enable a rule for the current project
vectimus rule enable vectimus-base-010

# Re-enable a rule everywhere
vectimus rule enable vectimus-base-010 --global
```

Per-project overrides are stored in `.vectimus/config.toml` in the project root.

**Precedence model:**  A rule is disabled if it appears in either the global disabled list or the project disabled list.  Project overrides can only relax (disable) rules.  They cannot re-enable a globally disabled rule.

### Pack management

Packs are groups of related rules that can be enabled or disabled together:

```bash
# List all policy packs
vectimus pack list

# Disable a pack
vectimus pack disable owasp-agentic

# Enable a pack
vectimus pack enable owasp-agentic
```

Pack enable/disable is always global.  Per-project overrides apply to individual rules only.

## System status

Check the current state of your Vectimus installation:

```bash
vectimus status
```

This shows configured tools, loaded policies, audit statistics and current mode.

## Write custom policies

See [Writing policies](writing-policies.md) for the full guide.  Place `.cedar` files in your policy directory and Vectimus will load them automatically.

## Environment variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `VECTIMUS_OBSERVE` | Enable observe mode (`true`/`1`) | Off |
| `VECTIMUS_MCP_ALLOWED` | Comma-separated approved MCP servers | None (all blocked) |
| `VECTIMUS_POLICY_DIR` | Custom policy directory | Built-in policies |
| `VECTIMUS_SERVER_URL` | Forward hooks to a shared server | Local evaluation |
| `VECTIMUS_LOG_DIR` | Audit log directory | `~/.vectimus` |
| `VECTIMUS_API_KEY` | API key for server auth (client and server) | None |
| `VECTIMUS_TIMEOUT` | Server request timeout in seconds | 5 |
| `VECTIMUS_PERSONA` | Override identity persona | `default` |
| `VECTIMUS_GROUPS` | Comma-separated group memberships | Empty |
| `VECTIMUS_IDENTITY_TYPE` | Identity type (`human` or `agent`) | `human` |
| `VECTIMUS_CONTENT_MAX_LINES` | Max lines for content inspection | 5000 |
| `VECTIMUS_EXCESSIVE_TURNS` | Excessive agent turns threshold | 50 |
| `VECTIMUS_GIT_TIMEOUT` | Git command timeout in seconds | 5 |
| `VECTIMUS_AUDIT_MAX_MB` | Max audit log file size in MB | 100 |
| `VECTIMUS_SESSION_SPAWN_LIMIT` | Max agent spawns per session | 10 |
| `VECTIMUS_SESSION_MESSAGE_LIMIT` | Max messages per session | 50 |
| `VECTIMUS_SESSION_TTL` | Session TTL in seconds | 3600 |
