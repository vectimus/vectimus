// ASI03: Identity and Privilege Abuse -- detect commands that escalate
// privileges, assume elevated cloud roles or access other users' data.

@id("owasp-007")
@category("ASI03")
@incident("15 Ways to Break Your Copilot, BHUSA 2024 - agent privilege escalation")
@description("Block cloud CLI privilege escalation commands")
@suggested_alternative("Use the cloud credentials already configured for the current session.  Request human approval for role assumption or re-authentication.")
@controls("OWASP-ASI03, SOC2-CC6.1, EU-AI-15")
forbid (
    principal,
    action == Vectimus::Action::"infrastructure",
    resource
) when {
    context.command like "*aws sts assume-role*" ||
    context.command like "*gcloud auth login*" ||
    context.command like "*gcloud auth activate-service-account*" ||
    context.command like "*az login*"
};

@id("owasp-008")
@category("ASI03")
@incident("Docker MCP prompt injection allowed cross-user file access, 2025")
@description("Block file operations targeting other users' home directories")
@suggested_alternative("Operate within your own project directory.  Access to other users' files requires explicit human authorisation.")
@controls("OWASP-ASI03, SOC2-CC6.1")
forbid (
    principal,
    action == Vectimus::Action::"file_read",
    resource
) when {
    // Unix/macOS
    context.file_path like "/home/*/../*" ||
    context.file_path like "/Users/*/../*" ||
    context.file_path like "/root/*" ||
    // Windows
    context.file_path like "*\\Users\\*\\..\\*" ||
    context.file_path like "C:\\Users\\*\\..\\*"
};

@id("owasp-009")
@category("ASI03")
@incident("CVE-2025-31491: agent privilege escalation via sudo")
@description("Block sudo and su execution by agents to prevent privilege escalation")
@suggested_alternative("Run commands with current user permissions.  If elevated privileges are needed, request human approval to run the command manually.")
@controls("OWASP-ASI03, SOC2-CC6.1, EU-AI-14")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    // Unix/macOS
    context.command like "sudo *" ||
    context.command like "*| sudo *" ||
    context.command like "su *" ||
    context.command like "su -c*" ||
    // Windows cmd
    context.command like "*runas /user:*" ||
    context.command like "*runas /noprofile*" ||
    // Windows PowerShell
    context.command like "*Start-Process*-Verb RunAs*" ||
    context.command like "*Start-Process*-Verb runas*"
};
