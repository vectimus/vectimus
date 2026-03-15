# Contributing to Vectimus

Contributions are welcome. This guide covers the basics.

## Getting started

```bash
git clone https://github.com/vectimus/vectimus.git
cd vectimus
uv pip install -e ".[dev]"
```

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
