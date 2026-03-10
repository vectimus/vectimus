// ASI06: Memory and Context Poisoning -- detect writes to agent instruction
// files and configuration directories that could alter agent behaviour across
// sessions.  Vectimus cannot inspect RAG stores or conversation memory, but
// it can protect the files agents read for persistent instructions.

@id("owasp-018")
@category("ASI06")
@incident("AgentFlayer: persistent 0click exploit planting false memories in ChatGPT, 2025")
@description("Block writes to agent instruction and rules files")
@suggested_alternative("Agent instruction files should be edited by a human developer, not modified by the agent itself.  Propose changes for human review.")
@controls("OWASP-ASI06, SOC2-CC6.1, EU-AI-14")
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

@id("owasp-019")
@category("ASI06")
@incident("Gemini long-term memory corruption via prompt injection, 2025")
@description("Block writes to agent memory and state directories")
@suggested_alternative("Agent configuration and state directories should be managed through proper tooling, not written to directly by agents.")
@controls("OWASP-ASI06, SOC2-CC6.1, EU-AI-14")
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
