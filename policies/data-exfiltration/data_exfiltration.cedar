// Data exfiltration -- detect and block data exfiltration patterns that are
// the observable consequence of goal hijack via prompt injection.
// Vectimus cannot detect the goal manipulation itself but can intercept
// the exfiltration actions that typically follow.

@id("vectimus-exfil-001")
@description("Block base64-encoded data exfiltration via curl or wget")
@incident("Amazon Q Developer secrets leaked via DNS and prompt injection, 2025")
@controls("OWASP-ASI01, SOC2-CC6.6, EU-AI-15, NIST-CSF-PR.DS-02, NIST-CSF-DE.CM-01, ISO27001-A.8.23")
@suggested_alternative("If you need to send data to an external service, request human approval and use an approved API endpoint.")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    // Unix/macOS
    context.command like "*base64*|*curl*" ||
    context.command like "*base64*|*wget*" ||
    context.command like "*curl*base64*" ||
    context.command like "*wget*base64*" ||
    // Windows PowerShell
    context.command like "*[Convert]::ToBase64String*Invoke-WebRequest*" ||
    context.command like "*[Convert]::ToBase64String*Invoke-RestMethod*" ||
    context.command like "*certutil*-encode*" ||
    // Windows cmd
    context.command like "*certutil*-encode*|*curl*"
};

@id("vectimus-exfil-002")
@description("Block DNS exfiltration via nslookup or dig with piped input")
@incident("Amazon Q Developer secrets leaked via DNS exfiltration, 2025")
@controls("OWASP-ASI01, SOC2-CC6.6, EU-AI-15, NIST-CSF-PR.DS-02, NIST-CSF-DE.CM-01, ISO27001-A.8.23")
@suggested_alternative("Use standard DNS lookup tools without piped encoded data.  If DNS queries are needed, run them directly with explicit domain names.")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    // Unix/macOS
    context.command like "*nslookup*$(*" ||
    context.command like "*dig*$(*" ||
    context.command like "*nslookup*`*" ||
    context.command like "*dig*`*" ||
    // Windows PowerShell
    context.command like "*Resolve-DnsName*$(*" ||
    context.command like "*Resolve-DnsName*`(*"
};

@id("vectimus-exfil-003")
@description("Block piping credential or system files to network transfer tools")
@incident("EchoLeak: zero-click indirect prompt injection against M365 Copilot, 2025")
@controls("OWASP-ASI01, SOC2-CC6.6, EU-AI-15, NIST-CSF-PR.DS-02, NIST-CSF-DE.CM-01, ISO27001-A.8.23")
@suggested_alternative("Do not pipe sensitive file contents to network tools.  Access files locally and use approved channels for data transfer.")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    // Unix/macOS
    context.command like "*cat /etc/passwd*|*curl*" ||
    context.command like "*cat /etc/shadow*|*curl*" ||
    context.command like "*cat /etc/passwd*|*wget*" ||
    context.command like "*cat /etc/shadow*|*wget*" ||
    context.command like "*cat /etc/passwd*|*nc *" ||
    context.command like "*cat /etc/shadow*|*nc *" ||
    // Windows -- credential database and registry exfiltration
    context.command like "*type*\\SAM*|*curl*" ||
    context.command like "*type*\\SYSTEM*|*curl*" ||
    context.command like "*reg save*HKLM\\SAM*" ||
    context.command like "*reg save*HKLM\\SYSTEM*" ||
    // Windows PowerShell
    context.command like "*Get-Content*SAM*|*Invoke-WebRequest*" ||
    context.command like "*Get-Content*SYSTEM*|*Invoke-RestMethod*"
};
