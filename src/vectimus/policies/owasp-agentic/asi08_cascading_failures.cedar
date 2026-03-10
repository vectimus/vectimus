// ASI08: Cascading Failures -- detect agent spawning patterns that risk
// resource exhaustion, runaway execution and uncontrolled proliferation.
// Without session-level state tracking Vectimus cannot detect temporal
// patterns (feedback loops, fan-out rates) but it can enforce guardrails
// on the parameters that enable cascading behaviour.

@id("owasp-025")
@category("ASI08")
@incident("Runaway agent consuming unbounded API tokens over 200+ turns, OWASP ASI08 Scenario 1")
@description("Block agent spawning with excessive turn counts that risk runaway execution")
@suggested_alternative("Reduce max_turns to 50 or fewer.  Break large tasks into smaller subtasks with human checkpoints between them.")
@controls("OWASP-ASI08, SOC2-CC7.2, EU-AI-14")
forbid (
    principal,
    action == Vectimus::Action::"agent_spawn",
    resource
) when {
    context.command like "*EXCESSIVE_TURNS*"
};

@id("owasp-026")
@category("ASI08")
@incident("Multi-agent swarm causing cascading API rate-limit exhaustion, OWASP ASI08 Scenario 2")
@description("Block creation of multi-agent teams to prevent uncontrolled swarm amplification")
@suggested_alternative("Spawn individual agents for specific tasks rather than creating teams.  If a team workflow is needed, request human approval.")
@controls("OWASP-ASI08, SOC2-CC7.2, EU-AI-14")
forbid (
    principal,
    action == Vectimus::Action::"agent_spawn",
    resource == Vectimus::Tool::"TeamCreate"
) when {
    true
};

@id("owasp-027")
@category("ASI08")
@incident("Background agent cascade with no human oversight consuming all available compute, OWASP ASI08 Scenario 3")
@description("Block spawning background agents with unrestricted permissions to prevent unmonitored cascades")
@suggested_alternative("Run agents in the foreground for human oversight, or use default permission mode for background agents.")
@controls("OWASP-ASI08, SOC2-CC7.2, EU-AI-14")
forbid (
    principal,
    action == Vectimus::Action::"agent_spawn",
    resource
) when {
    context.command like "*background=true*" &&
    context.command like "*mode=bypassPermissions*"
};

@id("owasp-028")
@category("ASI08")
@incident("Agent spawning flood detected via session tracking, OWASP ASI08 Scenario 4")
@description("Block agent spawning when session-level spawn flood is detected")
@suggested_alternative("Reduce the number of sub-agents.  Break work into sequential steps with human checkpoints rather than parallel fan-out.")
@controls("OWASP-ASI08, SOC2-CC7.2, EU-AI-14")
forbid (
    principal,
    action == Vectimus::Action::"agent_spawn",
    resource
) when {
    context.command like "*SESSION_SPAWN_FLOOD*"
};

@id("owasp-029")
@category("ASI08")
@incident("Agent message flood detected via session tracking, OWASP ASI08 Scenario 5")
@description("Block agent messaging when session-level message flood is detected")
@suggested_alternative("Reduce inter-agent message volume.  Consolidate updates into fewer, larger messages instead of many small ones.")
@controls("OWASP-ASI08, SOC2-CC7.2, EU-AI-14")
forbid (
    principal,
    action == Vectimus::Action::"agent_message",
    resource
) when {
    context.command like "*SESSION_MESSAGE_FLOOD*"
};
