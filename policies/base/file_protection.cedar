// File protection -- block writes to sensitive files including CI/CD
// pipelines, certificates, keys and governance configuration.

@id("vectimus-base-019")
@description("Block writes to GitHub Actions workflow files")
@incident("CI/CD pipeline injection via modified workflow file, BrowseComp evaluation 2026")
@controls("SLSA-L2, SOC2-CC8.1")
@suggested_alternative("Propose workflow changes via a pull request for human review before modifying CI/CD pipelines.")
forbid (
    principal,
    action == Vectimus::Action::"file_write",
    resource
) when {
    context.file_path like "*.github/workflows/*"
};

@id("vectimus-base-020")
@description("Block writes to certificate and private key files")
@incident("Agent overwrote TLS certificate causing service outage, incident report 2025")
@controls("SOC2-CC6.1, EU-AI-15")
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

@id("vectimus-base-020b")
@description("Block writes to governance config files to prevent policy bypass")
@incident("Agent modified .claude/settings.json to disable safety hooks, prompt injection attack 2026")
@controls("SOC2-CC6.1, EU-AI-14")
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
    context.file_path like "*.github/hooks/*" ||
    context.file_path like "*.vscode/settings.json" ||
    context.file_path like "*.vscode/tasks.json"
};

@id("vectimus-base-020e")
@description("Block writes to .vectimus config directory to prevent governance bypass")
@incident("Agent modified .vectimus/config.toml to disable safety rules")
@controls("SOC2-CC6.1, EU-AI-14, NIST-GOVERN-1.1")
@suggested_alternative("Vectimus config must be changed by a human using the vectimus CLI.")
forbid (
    principal,
    action == Vectimus::Action::"file_write",
    resource
) when {
    context.file_path like "*/.vectimus/*" ||
    context.file_path like "*.vectimus/*"
};

@id("vectimus-base-020c")
@description("Block writes to Dockerfile and docker-compose in production contexts")
@incident("Modified Dockerfile in production introduced cryptominer, container security report 2025")
@controls("SOC2-CC8.1, EU-AI-15")
@suggested_alternative("Propose Dockerfile changes via a pull request.  Production container configs require human review.")
forbid (
    principal,
    action == Vectimus::Action::"file_write",
    resource
) when {
    context.file_path like "*prod*Dockerfile*" ||
    context.file_path like "*prod*docker-compose*"
};

@id("vectimus-base-020d")
@description("Block writes to .git directory to prevent repository corruption")
@incident("Agent corrupted git objects by writing directly to .git directory, 2025")
@controls("SOC2-CC8.1")
@suggested_alternative("Use git commands to manage the repository instead of writing to .git directory directly.")
forbid (
    principal,
    action == Vectimus::Action::"file_write",
    resource
) when {
    context.file_path like "*/.git/*"
};

@id("vectimus-base-051")
@description("Block writes to VS Code launch.json and extensions.json that control debugging and extensions")
@incident("IDE configuration poisoning via launch configurations, IDEsaster research December 2025")
@controls("SOC2-CC6.1, EU-AI-14")
@suggested_alternative("VS Code launch and extension configuration should be reviewed by a human before modification.")
forbid (
    principal,
    action == Vectimus::Action::"file_write",
    resource
) when {
    context.file_path like "*.vscode/launch.json" ||
    context.file_path like "*.vscode/extensions.json"
};

@id("vectimus-base-052")
@description("Block writes to MCP configuration files that control tool access")
@incident("CurXecute: prompt injection rewrote MCP config for remote code execution, CVE-2025-54135")
@controls("SOC2-CC6.1, EU-AI-14")
@suggested_alternative("MCP configuration files must be edited by a human.  Changes to tool access should be reviewed before taking effect.")
forbid (
    principal,
    action == Vectimus::Action::"file_write",
    resource
) when {
    context.file_path like "*/mcp.json" ||
    context.file_path like "*mcp_config*"
};
