# Changelog

All notable changes to Vectimus will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.19.0] - 2026-03-22

### Added

- Cryptographic governance receipts with Ed25519 signing: every Cedar policy evaluation produces a signed JSON proof with RFC 8785 canonical JSON for deterministic hashing
- `vectimus verify` CLI command for offline receipt verification
- `vectimus receipts prune` CLI command for receipt retention management (`--days`, `--all`)
- Persistent evaluation daemon: keeps Cedar engine warm in memory, auto-starts on first hook call, eliminates ~200ms Python startup cost
- `vectimus daemon reload` CLI command to flush cached policy engines
- Shell command normalizer detects inline file I/O in Python, Node, Ruby and Perl scripts and reclassifies to `file_read`/`file_write`
- `src/vectimus/__main__.py` for `python -m vectimus` support

### Fixed

- Daemon on Windows: added `__main__.py`, fixed `os.kill(pid, 0)` unreliability with `OpenProcess`/`GetExitCodeProcess`, fixed `DETACHED_PROCESS` + `CREATE_NO_WINDOW` console flash, fixed `msvcrt.locking` at wrong file offset
- Restored Unix domain sockets on Unix/macOS (removed during TCP refactor) for stronger auth via filesystem permissions. TCP localhost + auth token kept for Windows only
- Claude Code hook deny enforcement: exit code and JSON format corrected so denials are no longer ignored
- Shell command normalizer bypass: agents can no longer wrap file operations in inline scripts to bypass policies
- Normalizer false positives: file descriptor redirects (`2>&1`) and read-only `open()` calls no longer misclassified
- ADK and LangGraph integrations now thread shell file paths to Cedar policies for path-based matching
- Windows JSONL audit log file locking: seek to byte 0 so all writers contend on the same range

### Changed

- Daemon uses Unix sockets on Unix/macOS, TCP localhost with auth token on Windows only
- Daemon auto-reloads when CLI commands change config (rule disable/enable, pack toggle, mcp allow/deny, policy update)
- Daemon runs receipt retention cleanup automatically to prevent unbounded disk growth
- Receipt ID included in DENY messages and audit log entries for traceability

## [0.18.1] - 2026-03-17

### Changed

- Automatic policy sync is now opt-in (disabled by default). Enable via `[updates] auto_sync = true` in `~/.vectimus/config.toml` or `VECTIMUS_AUTO_SYNC=true` environment variable. A security governance tool should not phone home without explicit consent.
- Sync URL and interval are now configurable via `[updates]` config section or environment variables (`VECTIMUS_SYNC_URL`, `VECTIMUS_SYNC_INTERVAL`)

## [0.18.0] - 2026-03-17

### Added

- Policy update system: policies sync from `api.vectimus.com` via `vectimus policy update` CLI or opt-in background sync
- `vectimus policy update` CLI command for manual policy sync
- `vectimus policy status` CLI command to show policy version and sync info
- Policy cache at `~/.vectimus/policy-cache/` supplements bundled policies (cached packs override bundled packs with matching names)
- Google ADK integration: `VectimusADKPlugin` for `Runner(plugins=[...])` and `create_before_tool_callback` for per-agent callbacks
- `pip install vectimus[adk]` extras group (requires `google-adk>=1.0.0`)
- `pip install vectimus[all]` extras group installs all integration dependencies

### Breaking

- Rule IDs changed from `vectimus-base-NNN`/`owasp-NNN` to `vectimus-<domain>-NNN` format. Existing rule disables and enforcement overrides in `config.toml` must be updated to use the new IDs.

### Changed

- Policy packs reorganized from 2 packs (base, owasp-agentic) to 11 domain-based packs: destructive-ops, secrets, supply-chain, infrastructure, code-execution, data-exfiltration, file-integrity, database, git-safety, mcp-safety, agent-governance
- `evaluator.py` fallback path now uses `PolicyLoader` for dynamic pack discovery instead of hardcoded `policies/base`
- `pack disable` confirmation prompt applies to all packs (previously only triggered for the "base" pack)
- MCP allowlist rewriting uses new `vectimus-mcp-001` rule ID

### Fixed

- MCP server detection now checks all Claude Code config locations: project `.mcp.json`, project `.claude/mcp.json`, user `~/.claude.json` and user `~/.claude/mcp.json`

## [0.17.0] - 2026-03-11

### Added

- Per-rule enforcement levels via `@enforcement("deny"|"escalate"|"observe")` Cedar annotation
- `vectimus rule enforce` CLI command to override enforcement per-project or globally
- Project-local custom packs: place Cedar policies in `<project>/.vectimus/packs/<pack>/` with a `pack.toml` manifest
- `rule list` and `rule show` display effective enforcement level and override source
- Protection for GitHub Copilot hook config files (`.github/hooks/*`) in `vectimus-base-020b`

### Changed

- ESCALATE verdicts in local mode now fall back to deny with a descriptive `[escalate]` message. Claude Code and Cursor do not reliably support interactive approval prompts from hooks. Server mode can implement real approval workflows (PagerDuty, Slack).
- All CLI subcommands (`rule show`, `rule disable`, `rule enable`, `rule enforce`) now pass `project_path` to the loader for project-local pack discovery

## [0.16.0] - 2026-03-11

### Added

- Unified `vectimus hook` subcommand replacing separate shim modules for Claude Code, Cursor and GitHub Copilot
- Fail-closed invariant: ESCALATE verdicts produce exit code 2 (deny), not exit 0
- Hook command tests covering all sources, server mode and edge cases
- `AGENTS.md` documentation for AI agent contributors

### Fixed

- ESCALATE verdict was treated as allow in hook command
- Server-mode deny format for Cursor (was returning Claude Code format)
- Shell-quoting of vectimus binary path in hook configurations
- Empty API key bypass in server authentication
- CORS header ordering on auth rejection responses
- Three bugs found during PR review (security audit)

### Changed

- Moved `write_audit` to `core.audit` module
- Relaxed concurrent benchmark p99 threshold for CI runners

## [0.15.0] - 2026-03-10

### Added

- Production-ready server mode (`pip install vectimus[server]`)
- Multi-key API authentication with named keys
- CORS support with configurable origins
- Kubernetes health probes (`/healthz`, `/ready`)
- SSE event stream endpoint (`/events`)
- Docker and docker-compose deployment configs
- 614 server tests

### Changed

- Moved documentation to the website (removed `docs/` directory from repo)
- Server CLI supports `--observe` flag and `VECTIMUS_OBSERVE` environment variable

### Fixed

- Install docs updated to match website (pipx/uv tool install)

## [0.14.1] - 2026-03-10

Initial public release.

### Added

- Cedar-based policy engine with deterministic evaluation (<50ms p99)
- 52 rules in base pack covering destructive operations, CI/CD protection, credential safety, recursive deletion and more
- 29 rules in OWASP Agentic pack (ASI01-ASI10, all 10 enforced)
- Native hook integration for Claude Code, Cursor and GitHub Copilot
- `vectimus rule list`, `rule show`, `rule disable`, `rule enable` CLI
- `vectimus status` with tool detection and audit statistics
- Per-project and global rule overrides via config.toml
- Audit logging with structured JSONL output
- Observe mode (global) for testing without blocking
- MCP server allowlist
- Compliance annotations mapping to SOC 2, NIST AI RMF, EU AI Act, SLSA and CIS
