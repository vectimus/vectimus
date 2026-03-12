# Vectimus

Deterministic governance for AI coding agents. Cedar policies. Under 5ms. Apache 2.0.

## The problem

AI coding agents execute shell commands, write files, install packages and call APIs with no guardrails.  The Clinejection attack in February 2026 compromised over 4,000 developers when a malicious MCP server instructed agents to publish backdoored npm packages.  A month earlier, an autonomous agent ran `terraform destroy` against a production environment because nothing stopped it.  Without governance, every agent is one prompt injection away from catastrophe.

## What Vectimus does

Vectimus intercepts every action an AI agent takes and evaluates it against [Cedar](https://www.cedarpolicy.com/) policies before execution.  It returns allow, deny or escalate decisions in single-digit milliseconds.  It works across Claude Code, Claude Agent SDK, Cursor, GitHub Copilot and Gemini CLI through their native hook mechanisms.

```
┌─────────────┐     ┌───────────────┐     ┌──────────────┐     ┌──────────┐
│  AI Agent   │────▶│   Vectimus    │────▶│ Cedar Policy │────▶│ Decision │
│ (tool call) │     │  Normaliser   │     │   Engine     │     │ allow /  │
│             │◀────│               │◀────│              │◀────│ deny     │
└─────────────┘     └───────────────┘     └──────────────┘     └──────────┘
                           │
                           ▼
                    ┌──────────────┐
                    │  Audit Log   │
                    │  (JSONL)     │
                    └──────────────┘
```

## Quick start

Two commands. 78 policies with 368 rules active out of the box.

```bash
pipx install vectimus
vectimus init
```

Or with uv:

```bash
uv tool install vectimus
vectimus init
```

That's it. Your agents are now governed. Dangerous commands, secret access, infrastructure changes and supply chain attacks are blocked before execution.

Verify your setup:

```bash
vectimus test
```

## Observe mode

If you want to trial Vectimus without blocking anything, observe mode logs all decisions to the audit trail but always allows actions.

```bash
vectimus observe on       # Enable observe mode
vectimus observe off      # Switch to enforcement
vectimus observe status   # Show current mode
```

Review the audit log at `~/.vectimus/logs/` to understand which actions your policies would block. For CI pipelines, set `VECTIMUS_OBSERVE=true` as an environment variable.

## Uninstall

To remove Vectimus hooks from all detected tools in the current project:

```bash
vectimus remove
```

This strips Vectimus entries from your tool configs while preserving any non-Vectimus hooks. Your `~/.vectimus/` config and audit logs are not touched.

## Supported tools

| Tool | Hook mechanism | Status |
|------|---------------|--------|
| Claude Code | HTTP hook or command hook | Supported |
| Claude Agent SDK | Same as Claude Code (shared hook system) | Supported |
| Cursor | Command hook | Supported |
| GitHub Copilot (VS Code) | Command hook | Supported |
| Gemini CLI | Command hook | Supported |
| LangChain / LangGraph | Middleware + MCP interceptor | Supported |

## LangGraph / LangChain integration

Vectimus can govern tool calls made by LangChain agents and LangGraph workflows.  The same Cedar policies that block `rm -rf` in a coding agent will block dangerous tool calls in a LangGraph customer support bot, a RAG pipeline or a multi-agent system.

Install with the langgraph extras:

```bash
pip install vectimus[langgraph]
```

### Agent middleware

Use `VectimusMiddleware` with `create_agent()` to evaluate every tool call against Cedar policies:

```python
from vectimus.integrations.langgraph import VectimusMiddleware

middleware = VectimusMiddleware(
    policy_dir="./policies",   # Optional, defaults to bundled policies
    observe_mode=False,        # Optional, defaults to False
)

agent = create_agent(
    model="openai:gpt-4.1",
    tools=my_tools,
    middleware=[middleware],
)
```

When a tool call is denied, the agent receives a clear message like `"Blocked by Vectimus policy vectimus-base-015: npm publish is not permitted."` and can try a different approach.

### MCP interceptor

For MCP tool calls via `MultiServerMCPClient`, use `create_interceptor`:

```python
from vectimus.integrations.langgraph import create_interceptor

interceptor = create_interceptor(
    policy_dir="./policies",
    observe_mode=False,
)

client = MultiServerMCPClient(
    {...},
    tool_interceptors=[interceptor],
)
```

Both mechanisms support observe mode — log what would be blocked without actually blocking, so you can trial Vectimus in your pipelines before switching to enforcement.

## Example policy

```cedar
@id("vectimus-base-015")
@description("Block npm publish to prevent supply-chain attacks")
@incident("Clinejection: malicious npm packages published by compromised AI agent, February 2026")
@controls("SLSA-L2, ASI02-01, CC8.1-01")
forbid (
    principal,
    action == Vectimus::Action::"package_operation",
    resource
) when {
    context.command like "*npm publish*"
};
```

Every rule references the real-world incident that motivated it.  Governance rules that exist "because best practice" are weak.  Rules that exist because a specific attack compromised thousands of developers are compelling.

## Policy files

All Cedar policies live in the top-level `policies/` directory, organised into packs:

**Base pack** (`policies/base/`):

| File | Coverage |
|------|----------|
| `agent_safety.cedar` | Agent spawning limits, excessive turns, session flooding |
| `database_safety.cedar` | Database credentials and CLI access |
| `destructive_commands.cedar` | rm -rf, rmdir, terraform destroy and similar |
| `file_protection.cedar` | .vectimus/ directory protection, sensitive file access |
| `git_safety.cedar` | Force push, history rewriting, credential exposure |
| `infrastructure_safety.cedar` | Infrastructure tool access (terraform, kubectl, docker, cloud CLIs) |
| `mcp_tools.cedar` | MCP server allowlisting and input parameter inspection |
| `package_operations.cedar` | npm publish, pip index, URL installs |
| `secret_access.cedar` | Credential file paths, environment variables, secret managers |

**OWASP Agentic pack** (`policies/owasp-agentic/`):

| File | Coverage |
|------|----------|
| `asi01_goal_hijack.cedar` | Goal and objective hijacking |
| `asi02_tool_misuse.cedar` | Tool parameter injection, command injection |
| `asi03_identity_privilege.cedar` | Identity spoofing, privilege escalation |
| `asi04_supply_chain.cedar` | Package tampering, repository poisoning |
| `asi05_code_execution.cedar` | Code injection, eval execution |
| `asi06_memory_poisoning.cedar` | Prompt injection, context hijacking |
| `asi07_inter_agent.cedar` | Agent-to-agent communication attacks |
| `asi08_cascading_failures.cedar` | Cascading system failures |
| `asi10_rogue_agents.cedar` | Rogue agent detection |

## MCP server governance

Vectimus blocks all MCP tool calls by default.  During `vectimus init`, it reads your existing tool configs (Claude Code, Cursor, VS Code) and offers to approve the MCP servers you already use:

```
MCP servers detected:
  Claude Code:  posthog, slack
  Cursor:       github

Allow all 3 servers? [y/N]:
```

To skip the prompts and approve everything automatically:

```bash
vectimus init --allow-mcp
```

You can also manage the allowlist manually at any time:

```bash
vectimus mcp allow github
vectimus mcp allow slack
vectimus mcp list
```

Or via environment variable for CI/CD:

```bash
export VECTIMUS_MCP_ALLOWED="github,slack,jira"
```

Approved servers still go through input inspection rules that check for credential paths, CI/CD file tampering and dangerous commands in tool parameters.  See [Writing policies](https://vectimus.com/docs/writing-policies) for details.

## Per-project rule overrides

Disable specific rules for specific repositories without affecting global policy:

```bash
# Disable a rule for the current project only
vectimus rule disable vectimus-base-010

# Disable a rule everywhere
vectimus rule disable vectimus-base-010 --global

# View project-specific overrides
vectimus rule overrides
```

Overrides are stored in `.vectimus/config.toml` in the project root.  The `.vectimus/` directory is protected by policy — agents cannot modify it.

## Documentation

Full documentation is available at [vectimus.com/docs](https://vectimus.com/docs).

- [Getting started](https://vectimus.com/docs/getting-started)
- [Writing policies](https://vectimus.com/docs/writing-policies)
- [Running a shared server](https://vectimus.com/docs/server)
- [Architecture](https://vectimus.com/docs/architecture)

## Configuration

Create `.vectimus/config.toml` in your project root:

```toml
[policies]
dir = "./policies"

[server]
host = "0.0.0.0"
port = 8420

[logging]
dir = "~/.vectimus/logs"

[mcp]
allowed_servers = ["github", "slack"]

[identity]
resolver = "git"
```

Or use environment variables:

| Variable | Purpose |
|----------|---------|
| `VECTIMUS_POLICY_DIR` | Policy directory path |
| `VECTIMUS_SERVER_URL` | Server URL for hook forwarding |
| `VECTIMUS_LOG_DIR` | Audit log directory |
| `VECTIMUS_OBSERVE` | Set to `true` for observe mode |
| `VECTIMUS_MCP_ALLOWED` | Comma-separated approved MCP servers |
| `VECTIMUS_API_KEY` | Single API key for server authentication |
| `VECTIMUS_API_KEYS` | Named team keys (`name:key,name:key`) |
| `VECTIMUS_WORKERS` | Server worker processes |
| `VECTIMUS_SSL_CERTFILE` | TLS certificate file |
| `VECTIMUS_SSL_KEYFILE` | TLS private key file |
| `VECTIMUS_CORS_ORIGINS` | Allowed CORS origins (comma-separated) |

## Contributing

Contributions are welcome.  Please open an issue before submitting large changes.

1. Fork and clone the repository
2. Install dev dependencies: `uv pip install -e ".[dev]"`
3. Run tests: `pytest`
4. Run linting: `ruff check src/ tests/`

## License

Apache 2.0.  See [LICENSE](LICENSE).
