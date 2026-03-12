// ASI04: Agentic Supply Chain Vulnerabilities -- detect supply chain
// manipulation through lockfile tampering, registry configuration changes
// and untrusted dependency sources.

@id("owasp-010")
@category("ASI04")
@incident("Dependency lockfile poisoning in ephemeral sandboxes, OWASP ASI05 Scenario 8")
@description("Block agent modification of package lockfiles")
@suggested_alternative("Run the package manager install command to regenerate lockfiles naturally.  Do not edit lockfiles directly.")
@controls("OWASP-ASI04, SOC2-CC8.1, NIST-AI-MG-3.2, EU-AI-15")
forbid (
    principal,
    action == Vectimus::Action::"file_write",
    resource
) when {
    context.file_path like "*package-lock.json" ||
    context.file_path like "*yarn.lock" ||
    context.file_path like "*pnpm-lock.yaml" ||
    context.file_path like "*Pipfile.lock" ||
    context.file_path like "*poetry.lock" ||
    context.file_path like "*uv.lock" ||
    context.file_path like "*Cargo.lock" ||
    context.file_path like "*Gemfile.lock" ||
    context.file_path like "*composer.lock"
};

@id("owasp-011")
@category("ASI04")
@incident("Malicious MCP server impersonating Postmark on npm, 2025")
@description("Block modification of package registry configuration files")
@suggested_alternative("Package registry configuration should be managed by a human administrator, not modified by agents.")
@controls("OWASP-ASI04, SOC2-CC8.1, NIST-AI-MG-3.2, EU-AI-15")
forbid (
    principal,
    action == Vectimus::Action::"file_write",
    resource
) when {
    context.file_path like "*.npmrc" ||
    context.file_path like "*.pypirc" ||
    context.file_path like "*pip.conf" ||
    context.file_path like "*.cargo/config*" ||
    context.file_path like "*.yarnrc*"
};

@id("owasp-012")
@category("ASI04")
@incident("Amazon Q supply chain compromise via poisoned extension, 2025")
@description("Block cargo install from git URLs which bypass registry review")
@suggested_alternative("Install Rust packages from crates.io by name.  Git-sourced dependencies bypass registry verification.")
@controls("OWASP-ASI04, SOC2-CC6.8, NIST-AI-MG-3.2, EU-AI-15")
forbid (
    principal,
    action == Vectimus::Action::"package_operation",
    resource
) when {
    context.command like "*cargo install*--git*"
};

@id("owasp-013")
@category("ASI04")
@incident("Agent-in-the-middle via agent cards in A2A protocol, Trustwave 2025")
@description("Block adding git submodules which can introduce unvetted code")
@suggested_alternative("Use package managers to add dependencies.  If a git submodule is needed, request human review of the source repository first.")
@controls("OWASP-ASI04, SOC2-CC8.1, NIST-AI-MG-3.2")
forbid (
    principal,
    action == Vectimus::Action::"git_operation",
    resource
) when {
    context.command like "*git submodule add*"
};
