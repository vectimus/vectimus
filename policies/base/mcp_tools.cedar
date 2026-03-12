// MCP tool governance -- controls for agent-to-MCP-server interactions.
//
// Important: Vectimus intercepts the agent's *request* to call an MCP tool
// before it is sent.  It does not observe what happens on the MCP server.
// These rules inspect tool call metadata visible at request time: the server
// name, the tool name, and whatever input parameters the agent passes.
// A tool that internally accesses credentials or writes to CI/CD pipelines
// without exposing that in its input parameters will not be caught here.
//
// The most effective MCP control is server allowlisting (rules 030-031).
// If a server is not on the approved list the request is blocked regardless
// of what tool or input is involved.  Input inspection rules (032-037) add
// defence in depth for approved servers whose tools receive sensitive paths
// or commands as parameters.


// ---------------------------------------------------------------------------
// Server and tool allowlisting
// ---------------------------------------------------------------------------

@id("vectimus-base-030")
@description("Block MCP tool calls to servers not on the approved list")
@incident("Clinejection: agent communicated with malicious MCP server that instructed it to publish backdoored packages, February 2026")
@controls("OWASP-ASI02, SOC2-CC6.1, NIST-AI-MG-3.2, EU-AI-15")
@suggested_alternative("Add the MCP server to your approved list with: vectimus mcp allow <server-name>")
forbid (
    principal,
    action == Vectimus::Action::"mcp_tool",
    resource
) when {
    // Default: block all MCP servers.  When you run
    // 'vectimus mcp allow <server>', the loader rewrites this rule
    // at load time with an 'unless' clause for your approved servers.
    true
};

@id("vectimus-base-031")
@description("Block MCP tools that execute arbitrary shell commands on the server")
@incident("Compromised MCP server exposed run_command tool used to pivot into internal network, 2026")
@controls("OWASP-ASI02, SOC2-CC6.1")
@suggested_alternative("Do not approve MCP servers that expose arbitrary command execution.  Use purpose-built tools instead.")
forbid (
    principal,
    action == Vectimus::Action::"mcp_tool",
    resource
) when {
    context.mcp_tool like "*run_command*" ||
    context.mcp_tool like "*execute*" ||
    context.mcp_tool like "*shell*" ||
    context.mcp_tool like "*exec*"
};


// ---------------------------------------------------------------------------
// Input parameter inspection (defence in depth)
//
// These rules check the input parameters the agent passes to MCP tools.
// They catch cases where tool inputs contain recognisable sensitive paths
// or dangerous commands.  They cannot catch tools that do sensitive things
// without exposing it in their input schema.
// ---------------------------------------------------------------------------

@id("vectimus-base-032")
@description("Block MCP tool calls whose inputs reference credential or secret paths")
@incident("Clinejection: agent passed credential file paths to malicious MCP tool, February 2026")
@controls("OWASP-ASI02, SOC2-CC6.1, NIST-AI-MG-3.2, EU-AI-15")
@suggested_alternative("Access secrets through environment variables or a secrets manager, not via MCP tool inputs.")
forbid (
    principal,
    action == Vectimus::Action::"mcp_tool",
    resource
) when {
    context.file_path like "*/.ssh/*" ||
    context.file_path like "*/.aws/*" ||
    context.file_path like "*.env" ||
    context.file_path like "*.env.*" ||
    context.file_path like "*credentials.json" ||
    context.file_path like "*/.npmrc" ||
    context.file_path like "*/secrets/*" ||
    context.file_path like "*token.json"
};

@id("vectimus-base-033")
@description("Block MCP tool calls whose inputs reference private key files")
@incident("Agent passed SSH private key path to MCP tool which exfiltrated key contents, 2026")
@controls("OWASP-ASI02, SOC2-CC6.1, EU-AI-15")
@suggested_alternative("Use ssh-agent or the relevant CLI tool to work with keys.  Do not pass key file paths to MCP tools.")
forbid (
    principal,
    action == Vectimus::Action::"mcp_tool",
    resource
) when {
    context.file_path like "*.pem" ||
    context.file_path like "*.key" ||
    context.file_path like "*id_rsa*" ||
    context.file_path like "*id_ed25519*"
};

@id("vectimus-base-034")
@description("Block MCP tool calls whose inputs reference CI/CD pipeline files")
@incident("Agent asked MCP tool to modify GitHub Actions workflow, injecting malicious build step, 2026")
@controls("OWASP-ASI02, SLSA-L2, SOC2-CC8.1")
@suggested_alternative("Propose CI/CD changes via a pull request for human review.  Do not pass pipeline paths to MCP tools.")
forbid (
    principal,
    action == Vectimus::Action::"mcp_tool",
    resource
) when {
    context.file_path like "*.github/workflows/*" ||
    context.file_path like "*.gitlab-ci.yml" ||
    context.file_path like "*Jenkinsfile*" ||
    context.file_path like "*.circleci/*"
};

@id("vectimus-base-035")
@description("Block MCP tool calls whose inputs contain dangerous shell commands")
@incident("Agent passed npm publish command to MCP tool, publishing backdoored package, Clinejection February 2026")
@controls("OWASP-ASI02, SLSA-L2, SOC2-CC6.8")
@suggested_alternative("Package operations and remote code execution must be done directly by the developer, not via MCP tools.")
forbid (
    principal,
    action == Vectimus::Action::"mcp_tool",
    resource
) when {
    context.command like "*npm publish*" ||
    context.command like "*npm install -g*" ||
    context.command like "*pip install*--index-url*" ||
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
    context.command like "*terraform destroy*" ||
    context.command like "*rm -rf*" ||
    // Windows destructive patterns
    context.command like "*rd /s /q*" ||
    context.command like "*rmdir /s /q*" ||
    context.command like "*del /f /s /q*" ||
    context.command like "*Remove-Item*-Recurse*-Force*"
};

@id("vectimus-base-036")
@description("Block MCP tool calls whose inputs reference governance configuration files")
@incident("Agent asked MCP tool to overwrite .claude/settings.json, disabling safety hooks, 2026")
@controls("OWASP-ASI02, SOC2-CC6.1, EU-AI-14")
@suggested_alternative("Governance configuration must be changed by a human administrator, not via MCP tools.")
forbid (
    principal,
    action == Vectimus::Action::"mcp_tool",
    resource
) when {
    context.file_path like "*.claude/settings.json" ||
    context.file_path like "*.cursor/hooks.json" ||
    context.file_path like "*.vectimus/*"
};
