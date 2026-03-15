# AGENTS.md

## What is Vectimus?

Deterministic governance for AI coding tools and autonomous agents.  Intercepts every agent action, evaluates it against Cedar policies and returns allow/deny/escalate decisions before execution.  Open-source core with a commercial enterprise tier planned.

## Tech stack

- **Language:** Python 3.12+
- **Package manager:** uv (pyproject.toml, no setup.py)
- **Policy engine:** cedarpy >=4.8.0 (Cedar policy language bindings)
- **HTTP server:** FastAPI + uvicorn (optional, behind `pip install vectimus[server]`)
- **CLI:** click
- **Testing:** pytest + pytest-asyncio
- **Linting:** ruff
- **Logging:** structlog

## Development commands

```bash
uv sync --group dev          # Install all dependencies
pytest                       # Run tests
pytest tests/test_benchmark.py  # Run performance benchmarks
ruff check src/ tests/       # Lint
ruff format src/ tests/      # Format
vectimus test                # Test policies against sample events
vectimus init                # Generate hook configs for detected AI tools
```

## Project layout

```
policies/           # Cedar policy packs (11 domain-based dirs) — top-level for visibility
src/vectimus/
  engine/           # Core evaluation: evaluator, normaliser, models, Cedar schema, config, loader
  adapters/         # Thin hook translators for coding tools (Claude Code, Cursor, Copilot)
  integrations/     # Framework middleware/plugins (LangGraph, ADK, etc. — placeholder)
  server/           # Optional FastAPI server (behind vectimus[server])
  exporters/        # Audit log exporters (JSONL with file locking)
  cli/              # Click CLI commands (init, hook, test, status, pack, rule, observe, mcp, server)
tests/              # pytest tests
docs/               # Documentation
```

## CLI commands

| Command | Purpose |
|---------|---------|
| `vectimus hook --source <tool>` | Unified hook entry point for Claude Code, Cursor, Copilot |
| `vectimus init` | Detect tools, generate hook configs (merges with existing hooks) |
| `vectimus remove` | Remove Vectimus hooks from detected tools in this project |
| `vectimus test` | Test policies against sample events |
| `vectimus status` | Show configured tools, loaded policies, audit stats |
| `vectimus observe on/off/status` | Toggle observe mode (log only, no blocking) |
| `vectimus mcp allow/deny/list` | Manage MCP server allowlist |
| `vectimus rule list/show/disable/enable/overrides` | Manage individual rules |
| `vectimus pack list/enable/disable` | Manage policy packs |
| `vectimus server start` | Start the HTTP evaluation server |

## Writing standards

- No Oxford commas.
- No em dashes.
- No AI buzzwords (crucial, delve, landscape, leverage, pivotal, cutting-edge, game-changing, revolutionise).
- Vary sentence rhythm.  Mix short and long.
- Be specific.  No puffery.

## Code standards

- All Python code must have type hints.
- Docstrings on all public functions and classes.
- Keep functions small and focused.
- Use `pathlib.Path` for file paths, not string concatenation.  Windows compatibility matters.
- Line length limit: 100 characters (enforced by ruff).

## Key design decisions

**Fail closed.**  This is the single most important invariant in the codebase.  Only an explicit ALLOW from the policy engine should result in exit code 0.  Everything else (DENY, ESCALATE, errors, unknown values) must result in exit code 2 (deny).  When adding new code paths that handle decisions, always check for the allow case explicitly and deny everything else.  Never check only for DENY and let other values fall through to allow.

**Steer, don't just block.**  Every DENY must include a human-readable `reason` and a `suggested_alternative`.  A governance layer that only says "no" is a productivity killer.  One that says "not that way, try this instead" is a force multiplier.

**MVP is local-only.**  Command hooks evaluate locally via cedarpy.  No server, no daemon, no network, no attack surface by default.  The server module exists for team use cases and is activated explicitly behind `pip install vectimus[server]`.

**Observe before enforce.**  Observe mode logs decisions but always returns allow.  Teams run observe mode to see what would be blocked, review the audit log, then switch to enforcement.  This is how adoption works.

**MCP: allowlist, don't inspect.**  Vectimus intercepts MCP tool call requests, not server-side behaviour.  The highest-value control is server allowlisting (block calls to unapproved servers).  Input parameter inspection is defence in depth.  Docs are honest about what can and cannot be caught.

**Incident and standards-driven policies.**  Every policy rule must reference a real-world incident where possible or reference a control in a set of standards or recommendations like OWASP, etc.  Rules that exist "because best practice" are weak.  Rules that exist because a specific attack compromised thousands of developers are compelling.

**Performance target.**  Local evaluation <50ms p99 (CI guard).  Actual measured performance is ~3ms p99 across all 78 rules (11 packs) with 10,000 events.  The benchmark suite (`tests/test_benchmark.py`) covers mixed workloads, deny-heavy worst case, content inspection double evaluation, concurrent threading and throughput.

**No telemetry.**  The open-source version sends no usage data.  The only network call is a background policy update check every 24 hours that contacts `api.vectimus.com` to fetch new policies.  This sends the installed version via the User-Agent header.  No other data leaves the machine.

**Escalation is simple (MVP).**  ESCALATE is always denied at the hook level.  The hook returns exit code 2 with a reason stating the action requires human approval.  No Slack, no approval workflows yet.  In future the enterprise tier will support out-of-band approval (Slack, ServiceNow, PagerDuty) where the hook denies, the approval happens asynchronously and the developer retries after approval.  The invariant that must never change: ESCALATE produces a deny at the hook.  Approval never happens inline.

## Cedar policy conventions

- Policy IDs: `vectimus-<pack>-NNN` (e.g. `vectimus-destruct-001`, `vectimus-supchain-001`, `vectimus-exfil-001`)
- Pack short names: `destruct`, `fileint`, `git`, `infra`, `secrets`, `supchain`, `db`, `mcp`, `agentgov`, `codexec`, `exfil`
- Required annotations: `@id`, `@description`
- Recommended annotations: `@incident`, `@controls`, `@suggested_alternative`
- Duplicate `@id` values across packs cause a load-time error
- See [docs/writing-policies.md](docs/writing-policies.md) for the full guide

## Compliance positioning

Vectimus maps to SOC 2 Type II, NIST AI RMF and EU AI Act.  It is the enforcement and audit layer for AI agent tool access within a broader compliance programme.  It is not a complete compliance solution for any of these frameworks.

### What Vectimus can honestly claim

- **SOC 2:** Evidence of logical access controls (CC6.1), system boundary protection (CC6.6), malicious software controls (CC6.8), anomalous behaviour monitoring (CC7.2) and change management (CC8.1) for AI agent tool access.
- **NIST AI RMF:** Behaviour monitoring (MEASURE 2.5), evaluation documentation (MEASURE 2.6), risk mitigation mechanisms (MANAGE 2.2) and third-party risk controls (MANAGE 3.2) at the tool level.
- **EU AI Act:** Record-keeping (Art. 12), transparency (Art. 13), human oversight enforcement (Art. 14) and cybersecurity controls (Art. 15) for agent tool operations.

### What Vectimus cannot claim

- Full framework compliance for any of these standards.
- Model-level governance (cannot see prompts, model outputs or semantic meaning of agent decisions).
- Risk classification (EU AI Act Article 6 is a product-level decision).
- Organisational controls (SOC 2 user provisioning, access reviews, incident response).
- Data governance (NIST AI RMF MAP function, EU AI Act Article 10).

### @controls annotation format

Every policy rule should include a `@controls` annotation mapping to the frameworks it addresses.  Use comma-separated control IDs:

```cedar
@controls("SOC2-CC6.1, NIST-AI-MG-3.2, EU-AI-15")
```

Control ID prefixes:
- `SOC2-CC6.1` through `SOC2-CC8.1` — SOC 2 Trust Service Criteria
- `NIST-AI-GV-x.x`, `NIST-AI-MS-x.x`, `NIST-AI-MG-x.x` — NIST AI RMF subcategories
- `EU-AI-9` through `EU-AI-15` — EU AI Act articles
- `OWASP-ASI01` through `OWASP-ASI10` — OWASP Agentic Top 10
- `SLSA-L2` — SLSA supply chain levels
- `CIS-16` — CIS Controls

### Marketing tone for compliance content

Frame as "evidence for your audit" not "we make you compliant."  The copy should speak to solo devs who care about doing things right, not enterprise buyers reading through a procurement checklist.  Be transparent about limitations.  The OWASP mapping doc is the model: honest about what is and is not enforceable at the hook level.  Do the same for every framework.

Positioning should appeal to solo devs (early adopters) while credibly signalling enterprise readiness.  Not too enterprise-y.  No compliance jargon walls.
