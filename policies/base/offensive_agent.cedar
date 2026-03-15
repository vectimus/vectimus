// VTMS-2026-0028 | OWASP: LLM01 Excessive Agency | SOC 2: CC6.1 | NIST AI RMF: GV-4.2
// EU AI Act: Art. 14 | CIS: 5.4, 16.1, 18.3
// CodeWall's autonomous offensive AI research agent, operating without human direction
// in target selection, identified McKinsey's Lilli chatbot, found 22 unauthenticated API
// endpoints, and exploited SQL injection to achieve full read-write database access in
// under 2 hours — exposing 46.5M chat messages, 728K client files, 57K user accounts.
// First documented autonomous AI agent achieving C-suite-scale corporate data access
// without any human direction.
//
// Blocks web requests and MCP tool calls from agents whose persona is
// "offensive_researcher" unless an explicit permit policy for the approved target
// is also present.  The forbid always wins over a permit in Cedar, so to allow
// a specific approved target the operator must add an unless clause to this rule
// or (better) change the agent's group membership to "approved_offensive_researcher"
// which is checked in the unless clause below.
//
// Override path:
//   1. Human operator reviews and approves the target scope.
//   2. Operator adds the agent to the "approved_offensive_researcher" group for the
//      duration of the engagement (Cedar entity attribute).
//   3. The unless clause below exempts the approved agent.
//   The group should be removed immediately after the engagement window.

@id("OFFENSE-001a")
@description("Block offensive-research agent web requests without explicit human-confirmed target scope (VTMS-2026-0028)")
@incident("VTMS-2026-0028: CodeWall autonomous agent autonomously selected and compromised McKinsey Lilli with no human direction, February 2026")
@controls("OWASP-LLM01, SOC2-CC6.1, NIST-AI-GV-4.2, EU-AI-14, CIS-5.4, CIS-16.1, CIS-18.3")
@suggested_alternative("Create a human-approved target scope for the engagement and add the agent to the 'approved_offensive_researcher' group for the duration.  Remove the group membership immediately afterwards.")
forbid (
    principal,
    action == Vectimus::Action::"web_request",
    resource
) when {
    principal has persona &&
    principal.persona == "offensive_researcher"
} unless {
    principal has groups &&
    principal.groups.contains("approved_offensive_researcher")
};

@id("OFFENSE-001b")
@description("Block offensive-research agent MCP tool calls without explicit human-confirmed target scope (VTMS-2026-0028)")
@incident("VTMS-2026-0028: CodeWall autonomous agent autonomously selected and compromised McKinsey Lilli with no human direction, February 2026")
@controls("OWASP-LLM01, SOC2-CC6.1, NIST-AI-GV-4.2, EU-AI-14, CIS-5.4, CIS-16.1, CIS-18.3")
@suggested_alternative("Create a human-approved target scope for the engagement and add the agent to the 'approved_offensive_researcher' group for the duration.  Remove the group membership immediately afterwards.")
forbid (
    principal,
    action == Vectimus::Action::"mcp_tool",
    resource
) when {
    principal has persona &&
    principal.persona == "offensive_researcher"
} unless {
    principal has groups &&
    principal.groups.contains("approved_offensive_researcher")
};
