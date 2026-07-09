# Contributing to Vectimus

Contributions are welcome. This guide covers the basics.

## Getting started

```bash
git clone https://github.com/vectimus/vectimus.git
cd vectimus
uv pip install -e ".[dev]"
./scripts/install-hooks.sh   # one-time: keeps policies/ in sync with canonical
```

The `install-hooks.sh` step points `core.hooksPath` at the repo-tracked `hooks/` directory.  Once installed, every `git pull` triggers `scripts/sync-policies.sh` which refreshes the vendored `policies/` tree from canonical [vectimus/policies@main](https://github.com/vectimus/policies).  Skip on a per-pull basis with `VECTIMUS_SKIP_POLICY_SYNC=1 git pull`, or run the sync manually any time with `./scripts/sync-policies.sh`.

If you keep a sibling clone of `vectimus/policies` at `../policies`, the script uses that and runs `git pull` on it; otherwise it shallow-clones canonical to a temp directory.

## Development workflow

1. **Fork and clone** the repository
2. **Create a branch** from `main` for your change
3. **Write tests** for new functionality
4. **Run the test suite** before submitting:

```bash
pytest
ruff check src/ tests/
```

## What to contribute

- **Bug fixes** with a test case that reproduces the issue
- **New integrations** for coding agents or agentic frameworks
- **Policy improvements** (submit these to [vectimus/policies](https://github.com/vectimus/policies) instead)
- **Documentation** fixes and improvements

## Before submitting a PR

- Open an issue first for large changes so we can discuss the approach
- Keep PRs focused. One change per PR.
- Add or update tests for any behavioral change
- Run `ruff check` and `pytest` locally

## Code style

- Python 3.12+
- Formatting and linting via [Ruff](https://github.com/astral-sh/ruff)
- Type hints where they add clarity
- No docstring requirements for internal code. Comments where the logic isn't obvious.

## Security vulnerabilities

Do not open a public issue. See [SECURITY.md](SECURITY.md) for responsible disclosure.

## License

By contributing you agree that your contributions will be licensed under Apache 2.0.
