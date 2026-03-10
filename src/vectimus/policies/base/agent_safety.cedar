// Agent safety -- block an AI agent from launching other AI coding tools with
// permission-bypass flags.  These rules only fire when an agent attempts to
// spawn a second AI tool as a shell subprocess.  They do not affect humans
// running these tools directly from a terminal.

@id("vectimus-base-047")
@description("Block agents from spawning Claude Code with --dangerously-skip-permissions flag")
@incident("Nx S1NGULARITY: malware weaponised Claude Code with permission bypass flags, August 2025")
@controls("SOC2-CC6.1, EU-AI-14")
@suggested_alternative("Spawn Claude Code without --dangerously-skip-permissions.  Sub-agents should go through the normal approval flow.")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    context.command like "*claude*--dangerously-skip-permissions*"
};

@id("vectimus-base-048")
@description("Block agents from spawning Gemini CLI with --yolo flag that disables safety")
@incident("Nx S1NGULARITY: malware weaponised Gemini CLI with --yolo flag, August 2025")
@controls("SOC2-CC6.1, EU-AI-14")
@suggested_alternative("Spawn Gemini CLI without --yolo.  Safety prompts exist to protect against destructive actions.")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    context.command like "*gemini*--yolo*"
};

@id("vectimus-base-049")
@description("Block agents from spawning AI tools with --trust-all-tools flag")
@incident("Nx S1NGULARITY: malware weaponised Amazon Q with --trust-all-tools, August 2025")
@controls("SOC2-CC6.1, EU-AI-14")
@suggested_alternative("Spawn AI tools without --trust-all-tools.  Tool trust should be granted selectively, not globally.")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    context.command like "*--trust-all-tools*"
};

@id("vectimus-base-050")
@description("Block agents from using generic permission bypass flags when spawning AI tools")
@incident("Systematic pattern of agents using force/skip/yolo flags to bypass safety, 2024-2026")
@controls("SOC2-CC6.1, EU-AI-14")
@suggested_alternative("Do not spawn sub-agents with flags that bypass permission checks.  Sub-agent invocations should respect the configured safety policies.")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    context.command like "*--skip-permissions*" ||
    context.command like "*--no-safety*"
};
