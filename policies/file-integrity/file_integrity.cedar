// File integrity -- protect CI/CD pipelines, certificates, governance
// configs, IDE settings, system directories, agent instruction files and
// agent memory from unauthorised writes.

// ---------------------------------------------------------------------------
// CI/CD and deployment pipelines
// ---------------------------------------------------------------------------

@id("vectimus-fileint-001")
@description("Block writes to GitHub Actions workflow files")
@incident("CI/CD pipeline injection via modified workflow file, BrowseComp evaluation 2026")
@controls("SLSA-L2, SOC2-CC8.1, NIST-CSF-PR.PS-01, ISO27001-A.8.9")
@suggested_alternative("Propose workflow changes via a pull request for human review before modifying CI/CD pipelines.")
forbid (
    principal,
    action == Vectimus::Action::"file_write",
    resource
) when {
    context.file_path like "*.github/workflows/*"
};

@id("vectimus-fileint-002")
@description("Block writes to Dockerfile and docker-compose in production contexts")
@incident("Modified Dockerfile in production introduced cryptominer, container security report 2025")
@controls("SOC2-CC8.1, EU-AI-15, NIST-CSF-PR.PS-01, ISO27001-A.8.9")
@suggested_alternative("Propose Dockerfile changes via a pull request.  Production container configs require human review.")
forbid (
    principal,
    action == Vectimus::Action::"file_write",
    resource
) when {
    context.file_path like "*prod*Dockerfile*" ||
    context.file_path like "*prod*docker-compose*"
};

// ---------------------------------------------------------------------------
// Certificates and private keys
// ---------------------------------------------------------------------------

@id("vectimus-fileint-003")
@description("Block writes to certificate and private key files")
@incident("Agent overwrote TLS certificate causing service outage, incident report 2025")
@controls("SOC2-CC6.1, EU-AI-15, NIST-CSF-PR.DS-01, ISO27001-A.8.3")
@suggested_alternative("Use a certificate management tool or request human approval before writing key/certificate files.")
forbid (
    principal,
    action == Vectimus::Action::"file_write",
    resource
) when {
    context.file_path like "*.pem" ||
    context.file_path like "*.key" ||
    context.file_path like "*.cert"
};

// ---------------------------------------------------------------------------
// Governance and tool configuration
// ---------------------------------------------------------------------------

@id("vectimus-fileint-004")
@description("Block writes to governance config files to prevent policy bypass")
@incident("Agent modified .claude/settings.json to disable safety hooks, prompt injection attack 2026")
@controls("SOC2-CC6.1, EU-AI-14, NIST-CSF-PR.PS-01, ISO27001-A.8.9")
@suggested_alternative("Governance configuration must be changed by a human administrator, not by an agent.")
forbid (
    principal,
    action == Vectimus::Action::"file_write",
    resource
) when {
    context.file_path like "*.claude/settings.json" ||
    context.file_path like "*.cursor/hooks.json" ||
    context.file_path like "*.cursor/mcp.json" ||
    context.file_path like "*.claude/mcp.json" ||
    context.file_path like "*.codex/hooks.json" ||
    context.file_path like "*.codex/config.toml" ||
    context.file_path like "*.github/hooks/*" ||
    context.file_path like "*.vscode/settings.json" ||
    context.file_path like "*.vscode/tasks.json"
};

@id("vectimus-fileint-005")
@description("Block writes to .vectimus config directory to prevent governance bypass")
@incident("Agent modified .vectimus/config.toml to disable safety rules")
@controls("SOC2-CC6.1, EU-AI-14, NIST-GOVERN-1.1, NIST-CSF-PR.PS-01, ISO27001-A.8.9")
@suggested_alternative("Vectimus config must be changed by a human using the vectimus CLI.")
forbid (
    principal,
    action == Vectimus::Action::"file_write",
    resource
) when {
    context.file_path like "*/.vectimus/*" ||
    context.file_path like "*.vectimus/*"
};

@id("vectimus-fileint-006")
@description("Block writes to .git directory to prevent repository corruption")
@incident("Agent corrupted git objects by writing directly to .git directory, 2025")
@controls("SOC2-CC8.1, NIST-CSF-PR.PS-01, ISO27001-A.8.9")
@suggested_alternative("Use git commands to manage the repository instead of writing to .git directory directly.")
forbid (
    principal,
    action == Vectimus::Action::"file_write",
    resource
) when {
    context.file_path like "*/.git/*"
};

@id("vectimus-fileint-007")
@description("Block writes to VS Code launch.json and extensions.json that control debugging and extensions")
@incident("IDE configuration poisoning via launch configurations, IDEsaster research December 2025")
@controls("SOC2-CC6.1, EU-AI-14, NIST-CSF-PR.PS-01, ISO27001-A.8.9")
@suggested_alternative("VS Code launch and extension configuration should be reviewed by a human before modification.")
forbid (
    principal,
    action == Vectimus::Action::"file_write",
    resource
) when {
    context.file_path like "*.vscode/launch.json" ||
    context.file_path like "*.vscode/extensions.json"
};

@id("vectimus-fileint-008")
@description("Block writes to MCP configuration files that control tool access")
@incident("CurXecute: prompt injection rewrote MCP config for remote code execution, CVE-2025-54135")
@controls("SOC2-CC6.1, EU-AI-14, NIST-CSF-PR.PS-01, ISO27001-A.8.9")
@suggested_alternative("MCP configuration files must be edited by a human.  Changes to tool access should be reviewed before taking effect.")
forbid (
    principal,
    action == Vectimus::Action::"file_write",
    resource
) when {
    context.file_path like "*/mcp.json" ||
    context.file_path like "*mcp_config*"
};

// ---------------------------------------------------------------------------
// System configuration
// ---------------------------------------------------------------------------

@id("vectimus-fileint-009")
@description("Block agent writes to system configuration directories")
@incident("AutoGPT unbounded filesystem permissions led to system config modification, 2023")
@controls("OWASP-ASI02, SOC2-CC6.1, EU-AI-15, NIST-CSF-PR.PS-01, ISO27001-A.8.9")
@suggested_alternative("Do not modify system configuration files directly.  Propose changes for human review or use configuration management tools.")
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

@id("vectimus-fileint-010")
@description("Block execution of scripts written to /tmp by agents")
@incident("Replit vibe coding runaway execution of agent-generated scripts, 2025")
@controls("OWASP-ASI02, SOC2-CC6.8, EU-AI-15, NIST-CSF-PR.PS-01, ISO27001-A.8.9")
@suggested_alternative("Write scripts to the project directory and request human review before execution.  Do not use /tmp for executable scripts.")
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

// ---------------------------------------------------------------------------
// Agent instruction and memory files
// ---------------------------------------------------------------------------

@id("vectimus-fileint-011")
@description("Block writes to agent instruction and rules files")
@incident("AgentFlayer: persistent 0click exploit planting false memories in ChatGPT, 2025")
@controls("OWASP-ASI06, SOC2-CC6.1, EU-AI-14, NIST-CSF-PR.PS-01, ISO27001-A.8.9")
@suggested_alternative("Agent instruction files should be edited by a human developer, not modified by the agent itself.  Propose changes for human review.")
forbid (
    principal,
    action == Vectimus::Action::"file_write",
    resource
) when {
    context.file_path like "*CLAUDE.md" ||
    context.file_path like "*AGENTS.md" ||
    context.file_path like "*.cursorrules" ||
    context.file_path like "*.github/copilot-instructions.md" ||
    context.file_path like "*.windsurfrules" ||
    context.file_path like "*.clinerules" ||
    context.file_path like "*.kirorules" ||
    context.file_path like "*.aider.conf.yml" ||
    context.file_path like "*.zed/settings.json" ||
    context.file_path like "*.roorules"
};

@id("vectimus-fileint-012")
@description("Block writes to agent memory and state directories")
@incident("Gemini long-term memory corruption via prompt injection, 2025")
@controls("OWASP-ASI06, SOC2-CC6.1, EU-AI-14, NIST-CSF-PR.PS-01, ISO27001-A.8.9")
@suggested_alternative("Agent configuration and state directories should be managed through proper tooling, not written to directly by agents.")
forbid (
    principal,
    action == Vectimus::Action::"file_write",
    resource
) when {
    context.file_path like "*.continue/*" ||
    context.file_path like "*.aider*" ||
    context.file_path like "*.claude/memory*" ||
    context.file_path like "*.cursor/memory*"
};
