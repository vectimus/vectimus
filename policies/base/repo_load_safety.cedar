// VTMS-2026-0030 | OWASP: LLM09 Insecure Tool Use | SOC 2: CC6.1 | NIST AI RMF: MS-2.3
// EU AI Act: Art. 15 | CIS: 2.5, 16.1, 16.7
// Check Point Research disclosed two vulnerabilities in Claude Code (patched Aug-Dec 2025):
//
//   CVE-2025-59536: hooks in .claude/settings.json execute arbitrary shell commands at tool
//   initialisation without confirmation, despite trust dialogs.  Attack vector: developer
//   clones a malicious repository that pre-places a poisoned .claude/settings.json.
//
//   CVE-2026-21852: ANTHROPIC_BASE_URL set in a project .env intercepts all Claude API
//   requests including plaintext API keys before the user confirms trust.  Attacker
//   receives every API call the developer makes including the key in the Authorization header.
//
//   Third vector: enableAllProjectMcpServers in project settings silently bypasses MCP
//   consent dialogs.  Covered separately by vectimus-base-030 and vectimus-base-020b.
//
// LIMITATION: The primary attack fires at project-load time, before Cedar evaluation.
// These rules provide defence-in-depth for the downstream execution step:
//   REPO-001 blocks shell commands that set ANTHROPIC_BASE_URL to non-Anthropic hosts.
//   REPO-002 blocks shell commands and file reads that reference .claude/hooks/ paths
//            (the directory where hook executables reside).
//
// Anthropic patched both CVEs in August–December 2025.  Ensure Claude Code >= patched.
//
// Override: ANTHROPIC_BASE_URL must only point at api.anthropic.com unless a human
// administrator has explicitly configured a verified proxy.  To allow a corporate proxy:
//   Add the proxy hostname to context.allowed_base_urls in an operator permit policy.

@id("REPO-001")
@description("Block setting ANTHROPIC_BASE_URL to a non-Anthropic domain (CVE-2026-21852 API key interception)")
@incident("VTMS-2026-0030: CVE-2026-21852 — project .env ANTHROPIC_BASE_URL intercepts plaintext API keys before trust dialog, February 2026")
@controls("OWASP-LLM09, SOC2-CC6.1, NIST-AI-MS-2.3, EU-AI-15, CIS-16.1, CIS-16.7")
@suggested_alternative("ANTHROPIC_BASE_URL must point at api.anthropic.com.  If a corporate proxy is required, a human administrator must configure it explicitly after review.")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    (
        context.command like "*ANTHROPIC_BASE_URL*=*"   ||
        context.command like "*ANTHROPIC_BASE_URL *=*"  ||
        context.command like "*export ANTHROPIC_BASE_URL*"
    ) &&
    !(context.command like "*api.anthropic.com*")
};

@id("REPO-002")
@description("Block execution of scripts from .claude/hooks/ directory (CVE-2025-59536 hook RCE vector)")
@incident("VTMS-2026-0030: CVE-2025-59536 — .claude/settings.json hooks execute arbitrary shell commands at tool initialisation, February 2026")
@controls("OWASP-LLM09, SOC2-CC6.1, NIST-AI-MS-2.3, EU-AI-14, CIS-2.5, CIS-16.1")
@suggested_alternative("Do not clone and initialise untrusted repositories without reviewing .claude/settings.json for hook definitions.  Hooks in .claude/hooks/ must be reviewed by a human before execution.")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    context.command like "*/.claude/hooks/*"   ||
    (context has file_path && context.file_path like "*/.claude/hooks/*")
};
