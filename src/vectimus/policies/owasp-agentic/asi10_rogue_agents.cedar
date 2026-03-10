// ASI10: Rogue Agents -- detect actions that rogue or compromised agents
// take to persist, hide their tracks or establish scheduled execution.
// The behavioural drift itself is invisible at hook level but the
// observable persistence mechanisms are detectable.

@id("owasp-020")
@category("ASI10")
@incident("Multi-agent systems executing arbitrary malicious code, arXiv 2503.12188, 2025")
@description("Block agents from disabling or clearing log and audit files")
@suggested_alternative("Do not modify log files or audit trails.  If log management is needed, use the designated log rotation tools.")
@controls("OWASP-ASI10, SOC2-CC7.2, EU-AI-15")
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

@id("owasp-021")
@category("ASI10")
@incident("Rogue agent self-replication via provisioning APIs, OWASP ASI10 Scenario 3")
@description("Block creation of cron jobs and scheduled tasks by agents")
@suggested_alternative("Scheduled tasks should be created by a human administrator.  If automation is needed, propose a cron entry for human review.")
@controls("OWASP-ASI10, SOC2-CC7.2, EU-AI-15")
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
