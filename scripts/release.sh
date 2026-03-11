#!/usr/bin/env bash
set -euo pipefail

# Release script for vectimus
# Reads version from pyproject.toml, tags, builds, and publishes to PyPI.
# Requires UV_PUBLISH_TOKEN (set via environment or .env file).

# Load .env if present
if [[ -f .env ]]; then
  set -a
  source .env
  set +a
fi

VERSION=$(grep '^version' pyproject.toml | sed 's/version = "\(.*\)"/\1/')
TAG="v${VERSION}"

echo "Releasing vectimus ${VERSION}"

# Preflight checks
if [[ -z "${UV_PUBLISH_TOKEN:-}" ]]; then
  echo "Error: UV_PUBLISH_TOKEN is not set" >&2
  exit 1
fi

if [[ -n "$(git status --porcelain)" ]]; then
  echo "Error: working tree is dirty. Commit or stash changes first." >&2
  exit 1
fi

BRANCH=$(git rev-parse --abbrev-ref HEAD)
if [[ "${BRANCH}" != "main" ]]; then
  echo "Error: not on main branch (currently on ${BRANCH})" >&2
  exit 1
fi

if git rev-parse "${TAG}" >/dev/null 2>&1; then
  echo "Error: tag ${TAG} already exists" >&2
  exit 1
fi

# Tag
git tag "${TAG}"
echo "Created tag ${TAG}"

# Build
rm -rf dist/
uv build
echo "Built dist/"

# Publish
uv publish
echo "Published vectimus ${VERSION} to PyPI"

# Push tag
git push origin "${TAG}"
echo "Pushed tag ${TAG}"

echo "Done."
