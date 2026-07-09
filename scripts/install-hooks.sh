#!/usr/bin/env bash
# Point this clone's git config at the repo-tracked hooks/ directory.
#
# Run once after cloning the repo.  Re-running is safe and idempotent.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$REPO_ROOT"
git config core.hooksPath hooks
chmod +x hooks/* scripts/*.sh

echo "install-hooks: core.hooksPath = hooks"
echo "install-hooks: post-merge will refresh policies/ on every git pull"
echo "install-hooks: skip with VECTIMUS_SKIP_POLICY_SYNC=1 git pull"
