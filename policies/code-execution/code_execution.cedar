// Code execution -- block reverse shells, eval patterns, download-execute
// chains and other remote code execution attacks that agents may be tricked
// into performing via prompt injection.

@id("vectimus-codexec-001")
@description("Block remote code execution via curl/wget piped to shell")
@incident("Supply-chain attacks via curl|sh pattern, Clinejection February 2026")
@controls("SOC2-CC6.6, SOC2-CC6.8, NIST-AI-MG-3.2, EU-AI-15, NIST-CSF-DE.CM-01, ISO27001-A.8.23")
@suggested_alternative("Download the script to a file first, review its contents, then execute it after inspection.")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    context.command like "*curl*| sh" ||
    context.command like "*curl*| sh *" ||
    context.command like "*curl*| sh;*" ||
    context.command like "*curl*|sh" ||
    context.command like "*curl*|sh *" ||
    context.command like "*curl*|sh;*" ||
    context.command like "*curl*| /bin/sh*" ||
    context.command like "*curl*|/bin/sh*" ||
    context.command like "*curl*| bash*" ||
    context.command like "*curl*|bash*" ||
    context.command like "*wget*| sh" ||
    context.command like "*wget*| sh *" ||
    context.command like "*wget*| sh;*" ||
    context.command like "*wget*|sh" ||
    context.command like "*wget*|sh *" ||
    context.command like "*wget*|sh;*" ||
    context.command like "*wget*| /bin/sh*" ||
    context.command like "*wget*|/bin/sh*" ||
    context.command like "*wget*| bash*" ||
    context.command like "*wget*|bash*" ||
    // Windows PowerShell -- download and execute patterns
    context.command like "*Invoke-WebRequest*|*Invoke-Expression*" ||
    context.command like "*Invoke-WebRequest*| iex*" ||
    context.command like "*iwr*|*iex*" ||
    context.command like "*IEX*(New-Object*Net.WebClient)*DownloadString*" ||
    context.command like "*Invoke-Expression*(New-Object*Net.WebClient)*" ||
    // Windows cmd -- certutil download-execute
    context.command like "*certutil*-urlcache*" ||
    context.command like "*bitsadmin*/transfer*"
};

@id("vectimus-codexec-002")
@description("Block reverse shell patterns in shell commands")
@incident("Auto-GPT RCE and container escape, Positive Security 2024")
@controls("OWASP-ASI05, SOC2-CC6.8, EU-AI-15, NIST-CSF-DE.CM-01, ISO27001-A.8.23")
@suggested_alternative("Do not open reverse shells.  If remote access is needed, use SSH with proper authentication.")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    // Unix/macOS
    context.command like "*bash -i*>*&*/dev/tcp*" ||
    context.command like "nc -e*" ||
    context.command like "*| nc -e*" ||
    context.command like "*; nc -e*" ||
    context.command like "nc -c*" ||
    context.command like "*| nc -c*" ||
    context.command like "*; nc -c*" ||
    context.command like "ncat -e*" ||
    context.command like "*| ncat -e*" ||
    context.command like "*; ncat -e*" ||
    context.command like "*/dev/tcp/*" ||
    context.command like "*mkfifo*/tmp/*nc*" ||
    context.command like "*import socket*connect*" ||
    // Windows PowerShell reverse shells
    context.command like "*New-Object*Net.Sockets.TCPClient*" ||
    context.command like "*System.Net.Sockets.TCPClient*" ||
    context.command like "*TCPClient*GetStream*" ||
    context.command like "*IO.StreamReader*Net.Sockets*" ||
    context.command like "*Invoke-PowerShellTcp*" ||
    // Windows cmd -- ncat/nc on Windows
    context.command like "*ncat.exe*-e*" ||
    context.command like "*nc.exe*-e*"
};

@id("vectimus-codexec-003")
@description("Block python -c with network or socket operations")
@incident("Waclaude memory exploitation RCE via agent-generated Python, 2025")
@controls("OWASP-ASI05, SOC2-CC6.8, EU-AI-15, NIST-CSF-DE.CM-01, ISO27001-A.8.23")
@suggested_alternative("Write Python code to a file for review before execution.  Do not use python -c for network operations.")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    context.command like "*python*-c*socket*" ||
    context.command like "*python*-c*urllib*" ||
    context.command like "*python*-c*requests*" ||
    context.command like "*python3*-c*socket*" ||
    context.command like "*python3*-c*urllib*" ||
    context.command like "*python3*-c*requests*"
};

@id("vectimus-codexec-004")
@description("Block downloading and executing binaries in a single command chain")
@incident("GitHub Copilot RCE via prompt injection, 2025")
@controls("OWASP-ASI05, SOC2-CC6.8, EU-AI-15, NIST-CSF-DE.CM-01, ISO27001-A.8.23")
@suggested_alternative("Download files to disk first, verify their checksums, then execute after human review.")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    // Unix/macOS
    context.command like "*curl*&&*chmod*+x*" ||
    context.command like "*wget*&&*chmod*+x*" ||
    context.command like "*curl*&&*bash*" ||
    context.command like "*wget*&&*bash*" ||
    context.command like "*curl*; chmod*+x*" ||
    context.command like "*wget*; chmod*+x*" ||
    // Windows PowerShell -- download and execute chains
    context.command like "*Invoke-WebRequest*&&*Start-Process*" ||
    context.command like "*Invoke-WebRequest*;*Start-Process*" ||
    context.command like "*iwr*;*Start-Process*" ||
    context.command like "*Invoke-WebRequest*;*&*" ||
    // Windows cmd -- certutil/bitsadmin download-execute
    context.command like "*certutil*-urlcache*&&*" ||
    context.command like "*bitsadmin*/transfer*&&*"
};

@id("vectimus-codexec-005")
@description("Block eval and exec patterns in shell commands that execute dynamic code")
@incident("Agent memory system RCE via unsafe eval, OWASP ASI05 Scenario 6")
@controls("OWASP-ASI05, SOC2-CC6.8, EU-AI-15, NIST-CSF-DE.CM-01, ISO27001-A.8.23")
@suggested_alternative("Write code to a file for review instead of using eval or exec.  Dynamic code execution from untrusted input is dangerous.")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    // Unix/macOS
    context.command like "*eval $(*" ||
    context.command like "*eval \"$(*" ||
    context.command like "*eval `*" ||
    context.command like "*python*-c*exec(*" ||
    context.command like "*python3*-c*exec(*" ||
    context.command like "*node -e*eval(*" ||
    context.command like "*node -e*Function(*" ||
    // Windows PowerShell
    context.command like "*Invoke-Expression*$(*" ||
    context.command like "*Invoke-Expression*DownloadString*" ||
    context.command like "*iex*$(*" ||
    context.command like "*iex*DownloadString*"
};
