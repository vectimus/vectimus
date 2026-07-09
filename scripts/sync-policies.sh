#!/usr/bin/env bash
# Sync the vendored policies/ directory from canonical vectimus/policies@main.
#
# Strategy
# --------
# 1. If a sibling clone exists at ../policies (relative to repo root) and it is
#    a git repo, fetch + checkout main + pull, then rsync from it.
# 2. Otherwise, shallow-clone vectimus/policies@main to a temp directory and
#    rsync from that, then clean up.
#
# In both cases we rsync only the policy data — schema, manifest and all .cedar
# pack directories — and skip the canonical repo's own README, CHANGELOG,
# tests, scripts and .git metadata.
#
# Refuses to run if the working tree under policies/ has uncommitted local
# edits, to avoid clobbering in-progress work.  Use ``--force`` to override.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENDORED_DIR="$REPO_ROOT/policies"
SIBLING_DIR="$(cd "$REPO_ROOT/.." && pwd)/policies"
TMP_DIR=""

force=0
quiet=0
for arg in "$@"; do
    case "$arg" in
        --force|-f) force=1 ;;
        --quiet|-q) quiet=1 ;;
        --help|-h)
            sed -n '2,18p' "${BASH_SOURCE[0]}" | sed 's/^# //; s/^#//'
            exit 0 ;;
    esac
done

log() { [[ $quiet -eq 1 ]] || echo "$@"; }
warn() { echo "$@" >&2; }

cleanup() {
    if [[ -n "$TMP_DIR" && -d "$TMP_DIR" ]]; then
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT

check_clean() {
    if [[ $force -eq 1 ]]; then return 0; fi
    if ! command -v git >/dev/null 2>&1; then return 0; fi
    cd "$REPO_ROOT"
    if ! git diff --quiet -- policies/ 2>/dev/null; then
        warn "sync-policies: uncommitted edits in policies/ — refusing to overwrite"
        warn "  (commit, stash, or rerun with --force)"
        exit 1
    fi
}

resolve_source() {
    if [[ -d "$SIBLING_DIR/.git" ]]; then
        log "sync-policies: found sibling clone at $SIBLING_DIR"
        if ! git -C "$SIBLING_DIR" diff --quiet 2>/dev/null; then
            warn "sync-policies: sibling clone has uncommitted edits — pulling anyway"
        fi
        git -C "$SIBLING_DIR" fetch --quiet origin main
        git -C "$SIBLING_DIR" checkout --quiet main
        git -C "$SIBLING_DIR" pull --ff-only --quiet
        SOURCE_DIR="$SIBLING_DIR"
    else
        TMP_DIR="$(mktemp -d -t vectimus-policies-sync-XXXXXX)"
        log "sync-policies: shallow-cloning vectimus/policies@main into $TMP_DIR"
        git clone --quiet --depth 1 --branch main \
            https://github.com/vectimus/policies.git "$TMP_DIR/policies"
        SOURCE_DIR="$TMP_DIR/policies"
    fi
}

run_rsync() {
    log "sync-policies: rsyncing $SOURCE_DIR -> $VENDORED_DIR"
    rsync -a --delete \
        --exclude='.git/' --exclude='.git*' \
        --exclude='.claude/' --exclude='.cursor/' --exclude='.gemini/' \
        --exclude='.vscode/' --exclude='.vectimus/' \
        --exclude='scripts/' --exclude='tests/' \
        --exclude='CHANGELOG.md' --exclude='CONTRIBUTING.md' \
        --exclude='LICENSE' --exclude='README.md' \
        --exclude='SECURITY.md' --exclude='VERSION' \
        "$SOURCE_DIR/" "$VENDORED_DIR/"
}

show_diff_summary() {
    cd "$REPO_ROOT"
    if git diff --quiet -- policies/ 2>/dev/null; then
        log "sync-policies: vendored policies already up-to-date"
    else
        log "sync-policies: vendored policies updated:"
        git diff --stat -- policies/ | sed 's/^/  /' | tail -n +1
        log "  (review with: git diff policies/  ;  commit when ready)"
    fi
}

main() {
    check_clean
    resolve_source
    run_rsync
    show_diff_summary
}

main "$@"
