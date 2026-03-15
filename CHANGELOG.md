# Changelog

All notable changes to Vectimus will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Google ADK integration: `VectimusADKPlugin` for `Runner(plugins=[...])` and `create_before_tool_callback` for per-agent callbacks
- `pip install vectimus[adk]` extras group (requires `google-adk>=1.0.0`)
- `pip install vectimus[all]` extras group installs all integration dependencies


## [0.18.0] - 2026-03-15

### Added

- SUPPLY-001: Block vulnerable langchain-core version pins (CVE-2025-68664, CVSS 9.3) and base64-encoded exfiltration web requests (VTMS-2026-0032)

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
- 29 rules in OWASP Agentic pack (ASI01-ASI10, 9 of 10 enforced)
- Native hook integration for Claude Code, Cursor and GitHub Copilot
- `vectimus rule list`, `rule show`, `rule disable`, `rule enable` CLI
- `vectimus status` with tool detection and audit statistics
- Per-project and global rule overrides via config.toml
- Audit logging with structured JSONL output
- Observe mode (global) for testing without blocking
- MCP server allowlist
- Compliance annotations mapping to SOC 2, NIST AI RMF, EU AI Act, SLSA and CIS
