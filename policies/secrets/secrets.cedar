// Secret access -- protect credentials, keys and environment files from
// being read by AI agents.

@id("vectimus-secrets-001")
@description("Block reading .env files that commonly contain secrets")
@incident("AI agent exfiltrated API keys from .env files, prompt injection attack reports 2025")
@controls("SOC2-CC6.1, CIS-16, EU-AI-15, NIST-CSF-PR.DS-01, ISO27001-A.8.3")
@suggested_alternative("Use environment variables directly or read a .env.example file for configuration structure.")
forbid (
    principal,
    action == Vectimus::Action::"file_read",
    resource
) when {
    context.file_path like "*.env" ||
    context.file_path like "*.env.*"
};

@id("vectimus-secrets-002")
@description("Block reading SSH keys, AWS credentials and npmrc tokens")
@incident("Agent read ~/.ssh/id_rsa and included contents in code comment, credential leak report 2025")
@controls("SOC2-CC6.1, EU-AI-15, NIST-CSF-PR.DS-01, ISO27001-A.8.3")
@suggested_alternative("Use the relevant CLI tool (ssh, aws, npm) to perform operations instead of reading credential files directly.")
forbid (
    principal,
    action == Vectimus::Action::"file_read",
    resource
) when {
    context.file_path like "*.ssh/*" ||
    context.file_path like "*.aws/*" ||
    context.file_path like "*.npmrc"
};

@id("vectimus-secrets-003")
@description("Block reading files in secrets directories or credential/token config files")
@incident("Agents read secret-named config files and logged contents to audit trails, 2025")
@controls("SOC2-CC6.1, EU-AI-15, NIST-CSF-PR.DS-01, ISO27001-A.8.3")
@suggested_alternative("Access secrets through a secrets manager or environment variables instead of reading secret files directly.")
forbid (
    principal,
    action == Vectimus::Action::"file_read",
    resource
) when {
    context.file_path like "*/secrets/*" ||
    context.file_path like "*/.secrets/*" ||
    context.file_path like "*credentials.json" ||
    context.file_path like "*credentials.yaml" ||
    context.file_path like "*/token" ||
    context.file_path like "*/token.json"
};

@id("vectimus-secrets-004")
@description("Block shell commands that cat private keys")
@incident("Agent ran cat ~/.ssh/id_rsa and embedded key in output, credential exposure report 2025")
@controls("SOC2-CC6.1, EU-AI-15, NIST-CSF-PR.DS-01, ISO27001-A.8.3")
@suggested_alternative("Use ssh-agent or the relevant CLI tool to work with keys.  Do not read private keys directly.")
forbid (
    principal,
    action == Vectimus::Action::"shell_command",
    resource
) when {
    // Unix/macOS
    context.command like "*cat*/.ssh/*" ||
    context.command like "*cat*.pem*" ||
    context.command like "*cat*.key*" ||
    // Windows cmd
    context.command like "*type*\\.ssh\\*" ||
    context.command like "*type*.pem*" ||
    context.command like "*type*.key*" ||
    // Windows PowerShell
    context.command like "*Get-Content*\\.ssh\\*" ||
    context.command like "*Get-Content*.pem*" ||
    context.command like "*Get-Content*.key*" ||
    context.command like "*gc *\\.ssh\\*" ||
    context.command like "*gc *.pem*"
};
