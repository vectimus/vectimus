// Package operations -- block dangerous package management commands that
// could publish malicious packages or install from untrusted sources.

@id("vectimus-base-015")
@description("Block npm publish to prevent supply-chain attacks")
@incident("Clinejection: malicious npm packages published by compromised AI agent, February 2026")
@controls("SLSA-L2, SOC2-CC6.8, NIST-AI-MG-3.2, EU-AI-15")
@suggested_alternative("Use npm pack to create a tarball for review, then request human approval before publishing.")
forbid (
    principal,
    action == Vectimus::Action::"package_operation",
    resource
) when {
    context.command like "*npm publish*"
};

@id("vectimus-base-016")
@description("Block pip install from non-standard indexes")
@incident("Dependency confusion attacks via private index spoofing, 2024-2026")
@controls("SLSA-L2, SOC2-CC6.8, NIST-AI-MG-3.2, EU-AI-15")
@suggested_alternative("Install packages from the default PyPI index, or request human approval for custom indexes.")
forbid (
    principal,
    action == Vectimus::Action::"package_operation",
    resource
) when {
    context.command like "*pip install*--index-url*" ||
    context.command like "*pip install*-i *"
};

@id("vectimus-base-016b")
@description("Block npm install with URL sources instead of registry packages")
@incident("Trojanised packages installed via direct URL bypassing registry checks, 2025")
@controls("SLSA-L2, SOC2-CC6.8, EU-AI-15")
@suggested_alternative("Install packages from the npm registry by name instead of using direct URLs.")
forbid (
    principal,
    action == Vectimus::Action::"package_operation",
    resource
) when {
    context.command like "*npm install http:*"
};

@id("vectimus-base-016c")
@description("Block global npm installs which affect the system-wide environment")
@incident("Global npm install of compromised package affected all projects on developer machine, 2025")
@controls("SOC2-CC6.8, EU-AI-15")
@suggested_alternative("Install packages locally to the project with npm install (no -g flag) to limit blast radius.")
forbid (
    principal,
    action == Vectimus::Action::"package_operation",
    resource
) when {
    context.command like "*npm install -g*"
};
