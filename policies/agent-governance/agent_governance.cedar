// Agent governance -- enforce agent autonomy limits, spawn controls,
// inter-agent communication rules, persistence prevention and audit
// trail integrity.


// ---------------------------------------------------------------------------
// Agent autonomy bypass (permission-bypass flags)
// ---------------------------------------------------------------------------

@id("vectimus-agentgov-001")
@description("Block agents from spawning Claude Code with --dangerously-skip-permissions flag")
@incident("Nx S1NGULARITY: malware weaponised Claude Code with permission bypass flags, August 2025")
@controls("SOC2-CC6.1, EU-AI-14, OWASP-ASI09, ISO27001-A.8.2")
@suggested_alternative("Spawn Claude Code without --dangerously-skip-permissions.  Sub-agents should go through the normal approval flow.")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    context.command like "*claude*--dangerously-skip-permissions*"
};

@id("vectimus-agentgov-002")
@description("Block agents from spawning Gemini CLI with --yolo flag that disables safety")
@incident("Nx S1NGULARITY: malware weaponised Gemini CLI with --yolo flag, August 2025")
@controls("SOC2-CC6.1, EU-AI-14, OWASP-ASI09, ISO27001-A.8.2")
@suggested_alternative("Spawn Gemini CLI without --yolo.  Safety prompts exist to protect against destructive actions.")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    context.command like "*gemini*--yolo*"
};

@id("vectimus-agentgov-003")
@description("Block agents from spawning AI tools with --trust-all-tools flag")
@incident("Nx S1NGULARITY: malware weaponised Amazon Q with --trust-all-tools, August 2025")
@controls("SOC2-CC6.1, EU-AI-14, OWASP-ASI09, ISO27001-A.8.2")
@suggested_alternative("Spawn AI tools without --trust-all-tools.  Tool trust should be granted selectively, not globally.")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    context.command like "*--trust-all-tools*"
};

@id("vectimus-agentgov-004")
@description("Block agents from using generic permission bypass flags when spawning AI tools")
@incident("Systematic pattern of agents using force/skip/yolo flags to bypass safety, 2024-2026")
@controls("SOC2-CC6.1, EU-AI-14, OWASP-ASI09, ISO27001-A.8.2")
@suggested_alternative("Do not spawn sub-agents with flags that bypass permission checks.  Sub-agent invocations should respect the configured safety policies.")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    context.command like "*--skip-permissions*" ||
    context.command like "*--no-safety*"
};


// ---------------------------------------------------------------------------
// Inter-agent communication
// ---------------------------------------------------------------------------

@id("vectimus-agentgov-005")
@description("Block broadcast messages to all agents to prevent amplification and noise injection")
@incident("Multi-agent broadcast amplification causing token exhaustion, OWASP ASI07 Scenario 2")
@controls("OWASP-ASI07, SOC2-CC7.2, EU-AI-14, ISO27001-A.8.6")
@suggested_alternative("Send targeted messages to specific agents using type 'message' with a named recipient instead of broadcasting.")
forbid (
    principal,
    action == Vectimus::Action::"agent_message",
    resource
) when {
    context.command like "*type=broadcast*"
};

@id("vectimus-agentgov-006")
@description("Block spawning sub-agents with elevated permissions that bypass safety controls")
@incident("Agent privilege cascade via bypassPermissions delegation, OWASP ASI07 Scenario 1")
@controls("OWASP-ASI07, SOC2-CC7.2, EU-AI-14, OWASP-ASI09, ISO27001-A.8.2")
@suggested_alternative("Spawn agents with default permission mode.  If elevated permissions are needed, request human approval first.")
forbid (
    principal,
    action == Vectimus::Action::"agent_spawn",
    resource
) when {
    context.command like "*mode=bypassPermissions*" ||
    context.command like "*mode=dontAsk*"
};

@id("vectimus-agentgov-007")
@description("Block agents from sending shutdown requests to terminate peer agents")
@incident("Compromised agent terminating monitoring agents via shutdown requests, OWASP ASI07 Scenario 3")
@controls("OWASP-ASI07, SOC2-CC7.2, EU-AI-14, ISO27001-A.8.15")
@suggested_alternative("Only team leads should send shutdown requests.  If an agent needs to stop, it should complete its task and go idle.")
forbid (
    principal,
    action == Vectimus::Action::"agent_message",
    resource
) when {
    context.command like "*type=shutdown_request*"
};


// ---------------------------------------------------------------------------
// Cascading failure prevention
// ---------------------------------------------------------------------------

@id("vectimus-agentgov-008")
@description("Block agent spawning with excessive turn counts that risk runaway execution")
@incident("Runaway agent consuming unbounded API tokens over 200+ turns, OWASP ASI08 Scenario 1")
@controls("OWASP-ASI08, SOC2-CC7.2, EU-AI-14, NIST-CSF-DE.AE-02, ISO27001-A.8.6")
@suggested_alternative("Reduce max_turns to 50 or fewer.  Break large tasks into smaller subtasks with human checkpoints between them.")
forbid (
    principal,
    action == Vectimus::Action::"agent_spawn",
    resource
) when {
    context.command like "*EXCESSIVE_TURNS*"
};

@id("vectimus-agentgov-009")
@description("Block creation of multi-agent teams to prevent uncontrolled swarm amplification")
@incident("Multi-agent swarm causing cascading API rate-limit exhaustion, OWASP ASI08 Scenario 2")
@controls("OWASP-ASI08, SOC2-CC7.2, EU-AI-14, NIST-CSF-DE.AE-02, ISO27001-A.8.6")
@suggested_alternative("Spawn individual agents for specific tasks rather than creating teams.  If a team workflow is needed, request human approval.")
forbid (
    principal,
    action == Vectimus::Action::"agent_spawn",
    resource == Vectimus::Tool::"TeamCreate"
) when {
    true
};

@id("vectimus-agentgov-010")
@description("Block spawning background agents with unrestricted permissions to prevent unmonitored cascades")
@incident("Background agent cascade with no human oversight consuming all available compute, OWASP ASI08 Scenario 3")
@controls("OWASP-ASI08, SOC2-CC7.2, EU-AI-14, OWASP-ASI09, NIST-CSF-DE.AE-02, ISO27001-A.8.6")
@suggested_alternative("Run agents in the foreground for human oversight, or use default permission mode for background agents.")
forbid (
    principal,
    action == Vectimus::Action::"agent_spawn",
    resource
) when {
    context.command like "*background=true*" &&
    context.command like "*mode=bypassPermissions*"
};

@id("vectimus-agentgov-011")
@description("Block agent spawning when session-level spawn flood is detected")
@incident("Agent spawning flood detected via session tracking, OWASP ASI08 Scenario 4")
@controls("OWASP-ASI08, SOC2-CC7.2, EU-AI-14, NIST-CSF-DE.AE-02, ISO27001-A.8.6")
@suggested_alternative("Reduce the number of sub-agents.  Break work into sequential steps with human checkpoints rather than parallel fan-out.")
forbid (
    principal,
    action == Vectimus::Action::"agent_spawn",
    resource
) when {
    context.command like "*SESSION_SPAWN_FLOOD*"
};

@id("vectimus-agentgov-012")
@description("Block agent messaging when session-level message flood is detected")
@incident("Agent message flood detected via session tracking, OWASP ASI08 Scenario 5")
@controls("OWASP-ASI08, SOC2-CC7.2, EU-AI-14, NIST-CSF-DE.AE-02, ISO27001-A.8.6")
@suggested_alternative("Reduce inter-agent message volume.  Consolidate updates into fewer, larger messages instead of many small ones.")
forbid (
    principal,
    action == Vectimus::Action::"agent_message",
    resource
) when {
    context.command like "*SESSION_MESSAGE_FLOOD*"
};


// ---------------------------------------------------------------------------
// Persistence and audit trail integrity
// ---------------------------------------------------------------------------

@id("vectimus-agentgov-013")
@description("Block agents from disabling or clearing log and audit files")
@incident("Multi-agent systems executing arbitrary malicious code, arXiv 2503.12188, 2025")
@controls("OWASP-ASI10, SOC2-CC7.2, EU-AI-15, OWASP-ASI09, ISO27001-A.8.15")
@suggested_alternative("Do not modify log files or audit trails.  If log management is needed, use the designated log rotation tools.")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    // Unix/macOS
    context.command like "*truncate*/var/log*" ||
    context.command like "*truncate*audit*" ||
    context.command like "*> /var/log/*" ||
    context.command like "*rm*/var/log/*" ||
    context.command like "*shred*/var/log*" ||
    context.command like "*shred*audit*" ||
    context.command like "rm *audit*" ||
    context.command like "*| rm *audit*" ||
    context.command like "*; rm *audit*" ||
    context.command like "rm *.log*" ||
    context.command like "*| rm *.log*" ||
    context.command like "*; rm *.log*" ||
    // Windows cmd
    context.command like "*wevtutil cl*" ||
    context.command like "*wevtutil clear-log*" ||
    context.command like "*del*\\Logs\\*" ||
    context.command like "*del*.evtx*" ||
    // Windows PowerShell
    context.command like "*Clear-EventLog*" ||
    context.command like "*Remove-EventLog*" ||
    context.command like "*Remove-Item*\\Logs\\*" ||
    context.command like "*Remove-Item*.evtx*"
};

@id("vectimus-agentgov-014")
@description("Block creation of cron jobs and scheduled tasks by agents")
@incident("Rogue agent self-replication via provisioning APIs, OWASP ASI10 Scenario 3")
@controls("OWASP-ASI10, SOC2-CC7.2, EU-AI-15, ISO27001-A.8.2")
@suggested_alternative("Scheduled tasks should be created by a human administrator.  If automation is needed, propose a cron entry for human review.")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    // Unix/macOS
    context.command like "*crontab*" ||
    context.command like "*/etc/cron*" ||
    context.command like "*systemctl enable*" ||
    context.command like "*systemctl start*" ||
    context.command like "at *" ||
    context.command like "*| at *" ||
    context.command like "*; at *" ||
    // Windows cmd
    context.command like "*schtasks*" ||
    // Windows PowerShell
    context.command like "*Register-ScheduledTask*" ||
    context.command like "*New-ScheduledTask*" ||
    context.command like "*Set-ScheduledTask*" ||
    // macOS
    context.command like "*launchctl load*" ||
    context.command like "*launchctl submit*"
};
