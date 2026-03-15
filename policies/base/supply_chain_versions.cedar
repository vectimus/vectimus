// VTMS-2026-0032 | OWASP: LLM07 Insufficient Input Validation | SOC 2: CC6.8
// NIST AI RMF: MS-2.5 | EU AI Act: Art. 15 | CIS: 2.2, 2.7, 16.1, 18.3
// CVE-2025-68664 "LangGrinch" (CVSS 9.3 Critical, CWE-502, disclosed Christmas Day 2025):
// langchain-core's dumps()/dumpd() serialisation functions failed to escape user-controlled
// dicts containing the reserved 'lc' marker key.  A single crafted prompt causes the LLM
// to generate a structured output that triggers deserialisation with secrets_from_env=True
// (enabled by default), extracting ALL environment variables — cloud credentials, DB
// strings, LLM API keys — in 12 distinct vulnerable flows (event streaming, logging,
// message history, caching).  Patched in langchain-core v0.3.81 (0.3.x) and v1.2.5 (1.x).
//
// SUPPLY-001a: blocks pip install of explicitly pinned vulnerable langchain-core versions
//              (0.3.x where x < 81, 1.2.x where x < 5, and all 0.1/0.2/1.0/1.1 lines).
// SUPPLY-001b: blocks web requests where a base64-encoded query parameter is sent to a
//              domain not on the known-safe list (downstream secret exfiltration pattern).
//
// LIMITATION: SUPPLY-001a only catches explicit version pins.  An unpinned
// 'pip install langchain-core' that resolves to a vulnerable version is not blocked.
// The correct primary mitigation is to pin langchain-core>=0.3.81 or >=1.2.5.
//
// Override for SUPPLY-001a: upgrade to a patched version.  There is no legitimate reason
// to pin a known-vulnerable version.
// Override for SUPPLY-001b: add trusted internal domains to context.allowed_exfil_domains
// via an operator permit policy.

@id("SUPPLY-001a")
@description("Block pip install of known-vulnerable langchain-core version pins (CVE-2025-68664 CVSS 9.3)")
@incident("VTMS-2026-0032: CVE-2025-68664 LangGrinch — langchain-core serialisation injection extracts all env secrets, CVSS 9.3, December 2025")
@controls("OWASP-LLM07, SOC2-CC6.8, NIST-AI-MS-2.5, EU-AI-15, CIS-2.2, CIS-2.7, CIS-16.1, CIS-18.3")
@suggested_alternative("Pin langchain-core>=0.3.81 (0.3.x line) or langchain-core>=1.2.5 (1.x line).  See CVE-2025-68664 / GHSA-c67j-w6g6-q2cm for full affected version list.")
forbid (
    principal,
    action == Vectimus::Action::"package_operation",
    resource
) when {
    // 0.3.x line — all below 0.3.81 are vulnerable (0.3.0 through 0.3.80)
    context.command like "*langchain-core==0.3.0*"  ||
    context.command like "*langchain-core==0.3.1*"  ||
    context.command like "*langchain-core==0.3.2*"  ||
    context.command like "*langchain-core==0.3.3*"  ||
    context.command like "*langchain-core==0.3.4*"  ||
    context.command like "*langchain-core==0.3.5*"  ||
    context.command like "*langchain-core==0.3.6*"  ||
    context.command like "*langchain-core==0.3.7*"  ||
    // 0.2.x and earlier — all vulnerable
    context.command like "*langchain-core==0.2.*"   ||
    context.command like "*langchain-core==0.1.*"   ||
    // 1.x line — 1.0.x, 1.1.x and 1.2.0-1.2.4 are vulnerable
    context.command like "*langchain-core==1.0.*"   ||
    context.command like "*langchain-core==1.1.*"   ||
    context.command like "*langchain-core==1.2.0*"  ||
    context.command like "*langchain-core==1.2.1*"  ||
    context.command like "*langchain-core==1.2.2*"  ||
    context.command like "*langchain-core==1.2.3*"  ||
    context.command like "*langchain-core==1.2.4*"
};

@id("SUPPLY-001b")
@description("Block web requests with base64-padded query parameters to non-allowlisted domains (LangGrinch secret exfiltration vector)")
@incident("VTMS-2026-0032: CVE-2025-68664 post-exploitation — deserialized environment secrets exfiltrated via encoded query parameters")
@controls("OWASP-LLM07, SOC2-CC6.1, NIST-AI-MS-2.5, EU-AI-15, CIS-16.1")
@suggested_alternative("Base64-padded query parameters to unknown domains indicate a compromised serialisation pipeline.  Audit langchain-core version immediately and review all recent LLM outputs for the 'lc' marker pattern.")
forbid (
    principal,
    action == Vectimus::Action::"web_request",
    resource
) when {
    // URL-encoded base64 padding (%3D) in query string to a non-standard domain
    // indicates potential exfiltration of deserialized secrets
    context.url like "*?*%3D*" &&
    !(context.url like "*api.anthropic.com*")  &&
    !(context.url like "*openai.com*")         &&
    !(context.url like "*api.openai.com*")     &&
    !(context.url like "*langchain.com*")      &&
    !(context.url like "*github.com*")         &&
    !(context.url like "*githubusercontent.com*")
};
