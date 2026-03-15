// Supply chain integrity -- block dangerous package management commands,
// lockfile tampering, registry configuration changes and untrusted
// dependency sources.

@id("vectimus-supchain-001")
@description("Block npm publish to prevent supply-chain attacks")
@incident("Clinejection: malicious npm packages published by compromised AI agent, February 2026")
@controls("SLSA-L2, SOC2-CC6.8, NIST-AI-MG-3.2, EU-AI-15, NIST-CSF-GV.SC-05, ISO27001-A.8.25")
@suggested_alternative("Use npm pack to create a tarball for review, then request human approval before publishing.")
forbid (
    principal,
    action == Vectimus::Action::"package_operation",
    resource
) when {
    context.command like "*npm publish*"
};

@id("vectimus-supchain-002")
@description("Block pip install from non-standard indexes")
@incident("Dependency confusion attacks via private index spoofing, 2024-2026")
@controls("SLSA-L2, SOC2-CC6.8, NIST-AI-MG-3.2, EU-AI-15, NIST-CSF-GV.SC-05, ISO27001-A.8.25")
@suggested_alternative("Install packages from the default PyPI index, or request human approval for custom indexes.")
forbid (
    principal,
    action == Vectimus::Action::"package_operation",
    resource
) when {
    context.command like "*pip install*--index-url*" ||
    context.command like "*pip install*-i *"
};

@id("vectimus-supchain-003")
@description("Block npm install with URL sources instead of registry packages")
@incident("Trojanised packages installed via direct URL bypassing registry checks, 2025")
@controls("SLSA-L2, SOC2-CC6.8, EU-AI-15, NIST-CSF-GV.SC-05, ISO27001-A.8.25")
@suggested_alternative("Install packages from the npm registry by name instead of using direct URLs.")
forbid (
    principal,
    action == Vectimus::Action::"package_operation",
    resource
) when {
    context.command like "*npm install http:*"
};

@id("vectimus-supchain-004")
@description("Block global npm installs which affect the system-wide environment")
@incident("Global npm install of compromised package affected all projects on developer machine, 2025")
@controls("SOC2-CC6.8, EU-AI-15, NIST-CSF-GV.SC-05, ISO27001-A.8.25")
@suggested_alternative("Install packages locally to the project with npm install (no -g flag) to limit blast radius.")
forbid (
    principal,
    action == Vectimus::Action::"package_operation",
    resource
) when {
    context.command like "*npm install -g*"
};

@id("vectimus-supchain-005")
@description("Block agent modification of package lockfiles")
@incident("Dependency lockfile poisoning in ephemeral sandboxes, OWASP ASI05 Scenario 8")
@controls("OWASP-ASI04, SOC2-CC8.1, NIST-AI-MG-3.2, EU-AI-15, NIST-CSF-GV.SC-05, ISO27001-A.8.25")
@suggested_alternative("Run the package manager install command to regenerate lockfiles naturally.  Do not edit lockfiles directly.")
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

@id("vectimus-supchain-006")
@description("Block modification of package registry configuration files")
@incident("Malicious MCP server impersonating Postmark on npm, 2025")
@controls("OWASP-ASI04, SOC2-CC8.1, NIST-AI-MG-3.2, EU-AI-15, NIST-CSF-GV.SC-05, ISO27001-A.8.25")
@suggested_alternative("Package registry configuration should be managed by a human administrator, not modified by agents.")
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

@id("vectimus-supchain-007")
@description("Block cargo install from git URLs which bypass registry review")
@incident("Amazon Q supply chain compromise via poisoned extension, 2025")
@controls("OWASP-ASI04, SOC2-CC6.8, NIST-AI-MG-3.2, EU-AI-15, NIST-CSF-GV.SC-05, ISO27001-A.8.25")
@suggested_alternative("Install Rust packages from crates.io by name.  Git-sourced dependencies bypass registry verification.")
forbid (
    principal,
    action == Vectimus::Action::"package_operation",
    resource
) when {
    context.command like "*cargo install*--git*"
};

@id("vectimus-supchain-008")
@description("Block adding git submodules which can introduce unvetted code")
@incident("Agent-in-the-middle via agent cards in A2A protocol, Trustwave 2025")
@controls("OWASP-ASI04, SOC2-CC8.1, NIST-AI-MG-3.2, NIST-CSF-GV.SC-05, ISO27001-A.8.25")
@suggested_alternative("Use package managers to add dependencies.  If a git submodule is needed, request human review of the source repository first.")
forbid (
    principal,
    action == Vectimus::Action::"git_operation",
    resource
) when {
    context.command like "*git submodule add*"
};
