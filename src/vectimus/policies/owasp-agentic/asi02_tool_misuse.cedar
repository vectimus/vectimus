// ASI02: Tool Misuse and Exploitation -- detect agent-specific misuse of
// legitimate tools beyond what the base pack covers.  Focuses on patterns
// where agents write to system configuration, execute self-generated scripts
// or destroy databases.

@id("owasp-004")
@category("ASI02")
@incident("AutoGPT unbounded filesystem permissions led to system config modification, 2023")
@description("Block agent writes to system configuration directories")
@suggested_alternative("Do not modify system configuration files directly.  Propose changes for human review or use configuration management tools.")
@controls("OWASP-ASI02, SOC2-CC6.1, EU-AI-15")
forbid (
    principal,
    action == Vectimus::Action::"file_write",
    resource
) when {
    // Unix/macOS
    context.file_path like "/etc/*" ||
    // Windows system directories
    context.file_path like "*\\Windows\\System32\\*" ||
    context.file_path like "*\\Windows\\SysWOW64\\*" ||
    context.file_path like "*\\Windows\\system32\\*"
};

@id("owasp-005")
@category("ASI02")
@incident("Replit vibe coding runaway execution of agent-generated scripts, 2025")
@description("Block execution of scripts written to /tmp by agents")
@suggested_alternative("Write scripts to the project directory and request human review before execution.  Do not use /tmp for executable scripts.")
@controls("OWASP-ASI02, SOC2-CC6.8, EU-AI-15")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    // Unix/macOS
    context.command like "*bash /tmp/*" ||
    context.command like "*sh /tmp/*" ||
    context.command like "*python /tmp/*" ||
    context.command like "*python3 /tmp/*" ||
    context.command like "*node /tmp/*" ||
    context.command like "*perl /tmp/*" ||
    context.command like "*ruby /tmp/*" ||
    context.command like "*/tmp/*.sh*" ||
    context.command like "*/tmp/*.py*" ||
    // Windows -- temp directory script execution
    context.command like "*\\Temp\\*.ps1*" ||
    context.command like "*\\Temp\\*.bat*" ||
    context.command like "*\\Temp\\*.cmd*" ||
    context.command like "*\\Temp\\*.py*" ||
    context.command like "*\\Temp\\*.js*" ||
    context.command like "*%TEMP%\\*" ||
    context.command like "*$env:TEMP\\*"
};

@id("owasp-006")
@category("ASI02")
@incident("Agent misused database tool to delete entire database, OWASP ASI02 Scenario 3")
@description("Block database destruction commands in shell")
@suggested_alternative("Use specific DELETE statements with WHERE clauses or request human approval before dropping databases or tables.")
@controls("OWASP-ASI02, SOC2-CC6.1, EU-AI-14")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    context.command like "*DROP DATABASE*" ||
    context.command like "*drop database*" ||
    context.command like "*Drop Database*" ||
    context.command like "*DROP TABLE*" ||
    context.command like "*drop table*" ||
    context.command like "*Drop Table*" ||
    context.command like "*dropdb*"
};
