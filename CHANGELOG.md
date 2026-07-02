# Changelog

All notable changes to Vectimus will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.22.2] - 2026-07-02

### Fixed

- `vectimus rule disable --for` (and any control command) no longer crashes with `KeyError: 'pid'` when the daemon is not running. The liveness check was handed an empty dict and indexed `info["pid"]` unconditionally, aborting before auto-start could run. `is_daemon_alive` now treats a pid-less info dict as "not alive", so the cold-start path spawns the daemon as intended.

## [0.22.1] - 2026-06-12

### Fixed

- Relative `audit.log_dir` / `logging.dir` config values (and a relative `VECTIMUS_LOG_DIR`) now anchor at the project root (or home when no project is known) instead of the process cwd. Under the daemon the cwd is always `/` since the cwd-resilience fix, and inline hooks run from arbitrary subdirectories, so a cwd-relative path landed somewhere different on every call and audit entries could be silently lost. `~` is now expanded too.

- `vectimus rule disable --for` is now honoured when the agent fires from a subdirectory of the project (#42). Previously the disable was keyed by the cwd at disable time and the hook keyed by the cwd at fire time, so a disable set from the project root never matched a hook fired from `<project>/src/...`. Both sites (and `status`, `rule list`) now walk up to the project root -- the directory containing `.vectimus/config.toml` or `.vectimus/keys/` -- before sending the daemon RPC.
- Receipts no longer sprout `.vectimus/receipts/` directories in every subfolder the agent works from. The same project-root walk fixes receipt placement, and when no `.vectimus` marker exists (hook installed globally, `vectimus init` never run) the walker falls back to the nearest `.git` ancestor so receipts anchor at the repository root. Stray `<subfolder>/.vectimus/` directories created before this fix can be deleted safely.
- The hook now drops a self-ignoring `.vectimus/.gitignore` (containing `receipts/`) when it auto-creates the receipts directory, so receipts can't be committed in projects that never ran `vectimus init`. Keys and config stay committable. Existing `.vectimus/.gitignore` files without a `receipts/` line get it appended atomically.
- The home directory never counts as a project marker. `~/.vectimus/` holds the global config and keypair, so the project-root walk previously resolved every markerless repository under home to the home directory itself -- a temp disable in one repo would have suppressed the rule in every other markerless repo under home. Found by adversarial review.
- `vectimus rule enable` now clears temp disables under the same project key the disable stored them under. Previously an enable from a subdirectory missed the daemon entry and the rule stayed suppressed until the TTL expired. On-disk project-scope disable/enable are also anchored at the project root, so they no longer write a `.vectimus/config.toml` marker into whatever subdirectory they ran from. Found by adversarial review.
- The project-root walk checks the lexical (unresolved) path before the resolved one, so a symlink inside the project pointing elsewhere can't pull the walk out of the project tree and skip project-local config (same evasion class as #38). The returned key is always resolved, preserving the #42 fix.
- Daemon no longer breaks every project when the directory it was started from is deleted. The auto-started daemon inherited the hook's cwd (e.g. an ephemeral Claude Code worktree); once that directory was removed, the eager `os.getcwd()` fallback raised `FileNotFoundError` on every request and all tool calls in all projects were denied with `Daemon error (fail closed)` until a manual restart. The daemon now does `os.chdir("/")` at startup, auto-start spawns it with `cwd="/"`, and the per-request cwd fallback is lazy.
- Hook client self-heals a broken daemon instead of silently falling back to inline evaluation forever: a daemon that is alive but not answering on its socket is stopped and replaced, a stale socket nobody answers on triggers an auto-start plus a single retry, and internal daemon failures (marked with a new `daemon_error` response field) fall back to inline evaluation while the daemon is replaced in the background. Restarts are serialized through a start lock so concurrent hooks cannot fight over the daemon, PIDs are verified to belong to a vectimus process before any signal is sent (PID-reuse guard), daemon readiness is probed with a real socket connect rather than a file-existence check, and a replaced daemon exiting late no longer deletes its successor's socket and PID files.

### Added

- `vectimus status` now shows active temp disables and the project key the daemon resolved them under, so any future project-key mismatch is visible without code changes.
- `vectimus rule disable --for` echoes the resolved project key it sent to the daemon.
- Daemon logs `temp_disable_lookup` with the lookup key and stored keys on every active-temp-disable query, and the hook in `--debug` mode echoes `daemon_call project_key=...` -- pair them to diagnose any future cross-process key drift.

## [0.22.0] - 2026-05-03

### Added

- `vectimus-secrets-005` (via canonical policies 2.3.0): blocks `ln -s` symlink creation pointing at `.env`, `.aws/`, `.ssh/`, `.pem`, `.key`, `/secrets/`, `credentials.*`, `.npmrc`. Closes the symlink-evasion bypass reported in #38.
- Normaliser detects `ln -s|--symbolic <target> <link>` (including combined flags `-sf`, `-fs`) and reclassifies the action as `file_read` against the target so existing `secrets-001/002/003` read policies fire on the bypass attempt — defense in depth even if `secrets-005` is disabled.

### Changed

- Release workflow (`.github/workflows/release.yml`) now pulls policies from canonical `vectimus/policies@main` via `actions/checkout` + `rsync --delete` before `python -m build`. Stops the vendored/canonical drift that was hiding policy updates from PyPI consumers (e.g. `vectimus-fileint-013`, codex-CLI policies, `destops` → `destruct` rename). Tracks `main` rather than a pinned tag, so the next vectimus release always ships the latest reviewed policies.

### Fixed

- Vendored policies that had drifted from canonical now ship correctly: `vectimus-fileint-013` (SANDWORM_MODE XDG config protection), codex CLI hook + config protections, `destops` → `destruct` rule prefix alignment.

## [0.21.0] - 2026-04-13

### Added

- Experimental Codex CLI hook support: Bash shell commands governed via `PreToolUse` hooks. File and MCP coverage limited by Codex upstream. Windows unsupported.
- `vectimus init`, `remove`, `status` and MCP discovery now include Codex CLI
- Cedar policies protect `.codex/hooks.json` and `.codex/config.toml` from agent tampering

### Changed

- `vectimus status` reports a tool as configured only when a Vectimus hook is present. Projects with third-party hooks but no Vectimus hook correctly show as not configured.

## [0.20.0] - 2026-03-28

### Added

- Temporary rule disabling with `vectimus rule disable <rule_id> --for <duration>`: disables a rule for a specified duration (e.g. `30m`, `2h`, `1h30m`) without writing to disk. Lives in daemon memory only and reverts automatically on expiry or daemon restart. Auto-starts daemon if not running.
- `vectimus rule enable` now also clears any active temp disable for the rule
- `vectimus rule list` shows temp-disabled rules with remaining time (e.g. `temp (24m)`)

## [0.19.1] - 2026-03-23

### Added

- `--ci` flag for `vectimus init`: suppresses all interactive prompts for CI/CD pipelines. MCP servers are discovered but not allowed unless `--allow-mcp` is also passed.

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
