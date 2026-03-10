// ASI07: Insecure Inter-Agent Communication -- detect unsafe message
// patterns and privilege delegation across agent boundaries.  Vectimus
// cannot inspect inter-agent wire protocols (TLS, mutual auth) but it
// can govern the tool calls that agents use to communicate and spawn
// sub-agents with elevated permissions.

@id("owasp-022")
@category("ASI07")
@incident("Multi-agent broadcast amplification causing token exhaustion, OWASP ASI07 Scenario 2")
@description("Block broadcast messages to all agents to prevent amplification and noise injection")
@suggested_alternative("Send targeted messages to specific agents using type 'message' with a named recipient instead of broadcasting.")
@controls("OWASP-ASI07, SOC2-CC7.2, EU-AI-14")
forbid (
    principal,
    action == Vectimus::Action::"agent_message",
    resource
) when {
    context.command like "*type=broadcast*"
};

@id("owasp-023")
@category("ASI07")
@incident("Agent privilege cascade via bypassPermissions delegation, OWASP ASI07 Scenario 1")
@description("Block spawning sub-agents with elevated permissions that bypass safety controls")
@suggested_alternative("Spawn agents with default permission mode.  If elevated permissions are needed, request human approval first.")
@controls("OWASP-ASI07, SOC2-CC7.2, EU-AI-14")
forbid (
    principal,
    action == Vectimus::Action::"agent_spawn",
    resource
) when {
    context.command like "*mode=bypassPermissions*" ||
    context.command like "*mode=dontAsk*"
};

@id("owasp-024")
@category("ASI07")
@incident("Compromised agent terminating monitoring agents via shutdown requests, OWASP ASI07 Scenario 3")
@description("Block agents from sending shutdown requests to terminate peer agents")
@suggested_alternative("Only team leads should send shutdown requests.  If an agent needs to stop, it should complete its task and go idle.")
@controls("OWASP-ASI07, SOC2-CC7.2, EU-AI-14")
forbid (
    principal,
    action == Vectimus::Action::"agent_message",
    resource
) when {
    context.command like "*type=shutdown_request*"
};
