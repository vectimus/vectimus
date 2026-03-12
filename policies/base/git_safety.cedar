// Git safety -- block dangerous git operations that can destroy history
// or push unreviewed code to protected branches.

@id("vectimus-base-017")
@description("Block force push to main, master or production branches")
@incident("Force push to main overwrote 3 days of team commits, 2025")
@controls("SOC2-CC8.1")
@suggested_alternative("Use git push --force-with-lease for safer force pushes, or push to a feature branch and create a pull request.")
forbid (
    principal,
    action == Vectimus::Action::"git_operation",
    resource
) when {
    context.command like "*git push*--force*main*" ||
    context.command like "*git push*--force*master*" ||
    context.command like "*git push*--force*production*" ||
    context.command like "*git push*-f*main*" ||
    context.command like "*git push*-f*master*" ||
    context.command like "*git push*-f*production*"
};

@id("vectimus-base-018")
@description("Block git reset --hard which discards uncommitted work")
@incident("Agent ran git reset --hard and destroyed hours of uncommitted developer work, 2025")
@controls("SOC2-CC8.1")
@suggested_alternative("Use git stash to save changes, or git reset --soft to keep changes staged, or git revert for a safe undo.")
forbid (
    principal,
    action == Vectimus::Action::"git_operation",
    resource
) when {
    context.command like "*git reset --hard*"
};

@id("vectimus-base-018b")
@description("Block git clean -f which permanently deletes untracked files")
@incident("git clean -f deleted uncommitted test fixtures and local config, developer incident reports")
@controls("SOC2-CC8.1")
@suggested_alternative("Use git clean -n (dry run) to preview what would be deleted, then request human approval.")
forbid (
    principal,
    action == Vectimus::Action::"git_operation",
    resource
) when {
    context.command like "*git clean*-f*"
};
