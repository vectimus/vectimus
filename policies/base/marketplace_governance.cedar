// VTMS-2026-0029 | OWASP: LLM10 Supply Chain Vulnerabilities | SOC 2: CC6.8
// NIST AI RMF: GV-6 | EU AI Act: Art. 15 | CIS: 2.5, 2.7, 16.1, 16.4
// OpenClaw AI agent framework (135K GitHub stars) experienced the first major AI agent
// supply chain crisis of 2026.  Out of 10,700 ClawHub marketplace skills, 820+ were
// confirmed malicious (delivering Atomic Stealer macOS info-stealer); 1,184 confirmed
// by March.  Additionally CVE-2026-25253 "ClawJacked" (CVSS 8.8) allowed malicious JS
// on any website to hijack local OpenClaw gateway via WebSocket brute-force.
//
// This policy blocks agent-initiated AI marketplace skill installation commands.
// Marketplace skills (OpenClaw/ClawHub and equivalents) MUST be installed by a human
// operator only after completing all four integrity checks:
//   1.  Verify published hash matches the publisher registry
//   2.  Confirm skill age ≥ 30 days
//   3.  Confirm install count ≥ 1,000
//   4.  Confirm absence from known-malicious skill intelligence feeds (e.g. Koi Security)
// Then and only then add the server to the approved list: vectimus mcp allow <server>
//
// NOTE: Browser-to-localhost WebSocket hijack (ClawJacked) and malicious skills already
// installed at setup time are NOT addressable by Cedar policy evaluation.  Those
// vectors require supplementary host-based controls:
//   - Bind MCP/agent gateway to 127.0.0.1, not 0.0.0.0
//   - Enable CSRF token on WebSocket handshake
//   - Enable rate-limiting on WebSocket password attempts
//
// Override: marketplace skill installation is a human-only operation.
// There is no automated override path for this policy.

@id("MKTPL-001a")
@description("Block agent-initiated AI marketplace skill installation via shell (VTMS-2026-0029)")
@incident("VTMS-2026-0029: 820+ malicious OpenClaw ClawHub skills delivering Atomic Stealer, January 2026. 1,184 confirmed by March.")
@controls("OWASP-LLM10, SOC2-CC6.8, NIST-AI-GV-6, EU-AI-15, CIS-2.5, CIS-2.7, CIS-16.1, CIS-16.4")
@suggested_alternative("Marketplace skill installation must be performed by a human operator after completing the four-point integrity checklist (hash verification, age >=30d, installs >=1000, threat-intel clean).  Run: vectimus mcp allow <server-name>")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    context.command like "*openclaw*skill*install*"     ||
    context.command like "*openclaw*install*skill*"     ||
    context.command like "*claw skill install*"         ||
    context.command like "*claw-skill install*"         ||
    context.command like "*claw skills install*"        ||
    context.command like "*clawhub install*"            ||
    context.command like "*agent skill install*"        ||
    context.command like "*agent-skill install*"        ||
    context.command like "*skill-marketplace*install*"
};

@id("MKTPL-001b")
@description("Block agent-initiated AI marketplace skill installation via package_operation (VTMS-2026-0029)")
@incident("VTMS-2026-0029: 820+ malicious OpenClaw ClawHub skills delivering Atomic Stealer, January 2026. 1,184 confirmed by March.")
@controls("OWASP-LLM10, SOC2-CC6.8, NIST-AI-GV-6, EU-AI-15, CIS-2.5, CIS-2.7, CIS-16.1, CIS-16.4")
@suggested_alternative("Marketplace skill installation must be performed by a human operator after completing the four-point integrity checklist (hash verification, age >=30d, installs >=1000, threat-intel clean).  Run: vectimus mcp allow <server-name>")
forbid (
    principal,
    action == Vectimus::Action::"package_operation",
    resource
) when {
    context.command like "*openclaw*skill*install*"     ||
    context.command like "*openclaw*install*skill*"     ||
    context.command like "*claw skill install*"         ||
    context.command like "*claw-skill install*"         ||
    context.command like "*claw skills install*"        ||
    context.command like "*clawhub install*"            ||
    context.command like "*agent skill install*"        ||
    context.command like "*agent-skill install*"        ||
    context.command like "*skill-marketplace*install*"
};
