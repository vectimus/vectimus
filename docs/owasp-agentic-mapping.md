# OWASP Agentic Top 10 — Vectimus Mapping Analysis

This document maps the OWASP Top 10 for Agentic Applications 2026 (ASI01–ASI10)
to enforceable Cedar policies within Vectimus.  Vectimus operates at the tool
hook level: it sees one action at a time (a shell command, a file write, a web
request, an MCP tool call).  It does not see conversation history, agent memory,
multi-agent communication or behavioural patterns over time.

Some OWASP categories map cleanly to Cedar rules.  Others do not.  This
document is honest about the distinction.

---

## ASI01: Agent Goal Hijack

**Summary:** Attackers redirect an agent's objectives through prompt injection,
poisoned documents or forged messages, causing the agent to pursue goals it was
not instructed to pursue.

**Enforceability at hook level:** PARTIAL

Goal hijack itself is invisible at the action level.  Vectimus cannot see the
prompt or determine whether the agent's current goal has been altered.  However,
the *consequences* of goal hijack are often visible: data exfiltration via web
requests, DNS tunnelling via shell commands, base64-encoded data sent to
external endpoints.  Vectimus can intercept these exfiltration patterns.

**Detectable patterns:**
- Shell commands encoding data in base64 and sending via curl/wget to external hosts
- DNS exfiltration patterns in shell commands (e.g. `nslookup` or `dig` with
  encoded subdomains)
- Shell commands piping sensitive file contents to network tools
- Web requests to known data-exfiltration patterns (e.g. webhook.site, requestbin)

**Out of scope patterns:**
- Prompt injection detection (requires inspecting LLM input/output, not tool calls)
- Detecting goal drift over multiple steps (requires session-level analysis)
- Forged agent-to-agent messages (requires inter-agent protocol inspection)
- Behavioural deviation from baseline (requires historical pattern matching)

**Proposed rules:**
1. `owasp-001` — Block shell commands that base64-encode data and pipe to
   curl/wget (data exfiltration via encoding)
2. `owasp-002` — Block shell commands using DNS tools with encoded subdomains
   (DNS exfiltration)
3. `owasp-003` — Block shell commands piping /etc/passwd, /etc/shadow or
   credential files to network tools

**Incident references:**
- EchoLeak: zero-click indirect prompt injection against Microsoft 365 Copilot
  (2025)
- AgentFlayer: 0click inception attack causing ChatGPT data exfiltration (2025)
- Amazon Q Developer: secrets leaked via DNS and prompt injection (2025)

---

## ASI02: Tool Misuse and Exploitation

**Summary:** Agents misuse legitimate tools due to prompt injection or
misalignment, leading to data exfiltration, resource overload or unintended
destructive operations.

**Enforceability at hook level:** HIGH

Tool misuse produces visible tool calls.  Destructive shell commands, overuse of
costly APIs, and unintended file modifications are all interceptable at the hook
level.  The base pack already covers many destructive command patterns.  The
OWASP pack adds patterns specific to agentic tool-chaining attacks.

**Detectable patterns:**
- Writing to system configuration files (/etc/*, system paths)
- Shell commands executing agent-generated scripts from /tmp
- Excessive or unusual tool invocations (detectable per-action, not per-session)
- MCP tool calls to unexpected or unregistered servers

**Out of scope patterns:**
- Tool output manipulation (the agent reads a tool's return value, which
  Vectimus does not inspect)
- Detecting over-invocation patterns (requires rate counting across actions)
- Tool chaining logic (Vectimus sees each tool call independently)

**Proposed rules:**
4. `owasp-004` — Block writes to system configuration directories (/etc/*)
5. `owasp-005` — Block execution of agent-written scripts from /tmp
6. `owasp-006` — Block database destruction commands (DROP DATABASE, DROP TABLE)

**Incident references:**
- AutoGPT unintended destructive actions with unbounded permissions (2023)
- Amazon Q Developer data exfiltration (2025)
- Tool poisoning via MCP tool descriptors (Invariant Labs, 2025)

**Base pack overlap:** `vectimus-base-001` through `vectimus-base-006` already
block the most destructive shell commands.  The OWASP rules here target
agent-specific misuse patterns not covered by the base pack.

---

## ASI03: Identity and Privilege Abuse

**Summary:** Agents exploit dynamic trust and delegation to escalate access,
inherit credentials or bypass authorisation controls.

**Enforceability at hook level:** PARTIAL

Vectimus cannot inspect delegation chains, token inheritance or multi-agent
trust relationships.  It can detect specific tool calls that access credential
stores, assume elevated privileges, or operate in other users' directories.

**Detectable patterns:**
- Cloud CLI privilege escalation commands (aws sts assume-role, gcloud auth,
  az login)
- Reading or writing to other users' home directories
- Accessing cloud provider credential files
- Running sudo or su commands

**Out of scope patterns:**
- Delegation chain analysis (requires multi-agent context)
- Token inheritance across agents (requires runtime identity tracking)
- TOCTOU permission drift (requires temporal analysis)
- Synthetic identity injection (requires agent registry inspection)

**Proposed rules:**
7. `owasp-007` — Block cloud CLI privilege escalation commands
8. `owasp-008` — Block file operations in other users' home directories
9. `owasp-009` — Block sudo/su execution by agents

**Incident references:**
- 15 Ways to Break Your Copilot (BHUSA 2024)
- Docker MCP prompt injection (2025)
- CVE-2025-31491: agent privilege escalation

**Base pack overlap:** `vectimus-base-012` blocks reading SSH/AWS credential
files.  `vectimus-base-014` blocks catting private keys.  The OWASP rules here
add privilege-escalation-specific patterns.

---

## ASI04: Agentic Supply Chain Vulnerabilities

**Summary:** Agents consume tools, packages and prompts from third parties that
may be malicious, compromised or tampered with in transit.

**Enforceability at hook level:** HIGH

Supply chain attacks manifest as specific tool calls: installing packages from
untrusted sources, modifying lockfiles, altering CI/CD pipelines, pulling
prompt templates from external URLs.  These are highly detectable at the hook
level.

**Detectable patterns:**
- Modifying package lockfiles (package-lock.json, yarn.lock, Pipfile.lock, uv.lock)
- Installing packages with typosquatting indicators (misspellings of popular packages)
- Adding git submodules from unknown sources
- Cargo install from git URLs
- Modifying .npmrc, .pypirc or pip.conf to point to alternative registries

**Out of scope patterns:**
- Runtime tool descriptor poisoning (requires MCP protocol inspection)
- Poisoned prompt templates loaded dynamically (requires content inspection)
- Compromised agent registries (requires external registry validation)

**Proposed rules:**
10. `owasp-010` — Block modification of package lockfiles by agents
11. `owasp-011` — Block modification of package registry configuration files
12. `owasp-012` — Block cargo install from git URLs
13. `owasp-013` — Block adding git submodules

**Incident references:**
- Amazon Q supply chain compromise (poisoned prompt in VS Code extension, 2025)
- MCP tool descriptor poisoning (Invariant Labs, 2025)
- Malicious MCP server impersonating Postmark on npm (2025)
- Clinejection: compromised npm packages published by AI agent (2026)

**Base pack overlap:** `vectimus-base-015` through `vectimus-base-016c` block
npm publish, pip install from custom indexes, npm install from URLs and global
npm installs.  `vectimus-base-019` blocks writes to CI/CD workflows.

---

## ASI05: Unexpected Code Execution (RCE)

**Summary:** Agents generate and execute code that results in remote code
execution, sandbox escape or persistent compromise.

**Enforceability at hook level:** HIGH

Code execution is directly visible in shell commands and file writes.  Vectimus
can detect eval patterns, script creation and immediate execution, unsafe
deserialization commands and reverse shell patterns.

**Detectable patterns:**
- Python -c with complex inline code from untrusted contexts
- Shell commands using eval on external input
- Writing scripts to /tmp then immediately executing them (covered in ASI02)
- Reverse shell patterns (bash -i >& /dev/tcp, nc -e, python socket connect)
- Node.js eval or Function() execution patterns
- Downloading and executing binaries in one step

**Out of scope patterns:**
- Code hallucination (requires inspecting generated code content)
- Multi-tool chain exploitation (requires session-level analysis)
- Unsafe object deserialization within application code (requires code analysis)

**Proposed rules:**
14. `owasp-014` — Block reverse shell patterns in shell commands
15. `owasp-015` — Block python -c with network/socket operations
16. `owasp-016` — Block downloading and executing binaries in a single command chain
17. `owasp-017` — Block eval/exec patterns in shell commands

**Incident references:**
- Waclaude memory exploitation RCE (Cole Murray, 2025)
- GitHub Copilot RCE via prompt injection (2025)
- Auto-GPT RCE + container escape (Positive Security, 2024)
- Replit vibe coding runaway execution (2025)

**Base pack overlap:** `vectimus-base-006` blocks curl|bash piping.  The OWASP
rules here add reverse shells, eval patterns and binary download-execute chains.

---

## ASI06: Memory and Context Poisoning

**Summary:** Adversaries corrupt stored agent context, conversation memory or
RAG data to bias future reasoning and tool usage.

**Enforceability at hook level:** PARTIAL

Memory poisoning is primarily an internal agent concern.  Vectimus cannot
inspect what gets written to agent memory or RAG stores.  However, it can detect
writes to agent configuration files and instruction files that alter agent
behaviour across sessions.

**Detectable patterns:**
- Writes to agent memory/instruction files (CLAUDE.md, AGENTS.md, .cursorrules,
  .github/copilot-instructions.md)
- Writes to agent configuration directories (.claude/, .cursor/, .continue/)
- Modification of system prompt files or persona definitions

**Out of scope patterns:**
- RAG/embedding poisoning (requires vector DB inspection)
- Shared context contamination across sessions (requires session tracking)
- Long-term memory drift (requires temporal analysis)
- Cross-agent memory propagation (requires multi-agent monitoring)

**Proposed rules:**
18. `owasp-018` — Block writes to agent instruction files (CLAUDE.md, AGENTS.md,
    .cursorrules, copilot-instructions.md)
19. `owasp-019` — Block writes to agent memory directories
    (.continue/, .aider/, agent-specific state directories)

**Incident references:**
- Gemini long-term memory corruption via prompt injection (Ars Technica, 2025)
- AgentFlayer: persistent 0click exploit on ChatGPT memories (2025)
- Hacker plants false memories in ChatGPT to steal user data (2025)

**Base pack overlap:** `vectimus-base-020b` blocks writes to
.claude/settings.json and .cursor/hooks.json (governance bypass).  The OWASP
rules extend this to instruction files and memory directories that influence
agent behaviour.

---

## ASI07: Insecure Inter-Agent Communication

**Summary:** Multi-agent systems lack authentication, integrity or semantic
validation on messages exchanged between agents, allowing interception, spoofing
or manipulation.

**Enforceability at hook level:** LOW

Vectimus intercepts tool calls, not inter-agent messages.  It cannot inspect
message buses, validate agent-to-agent authentication or detect spoofed agent
descriptors.  This category requires architectural controls at the communication
protocol layer.

**Detectable patterns:**
- None that are reliably detectable from individual tool calls.

**Out of scope patterns:**
- Message interception and tampering (requires protocol-level inspection)
- Agent identity spoofing (requires registry validation)
- Protocol downgrade attacks (requires protocol negotiation monitoring)
- Replay attacks (requires message sequence tracking)

**Proposed rules:** None.  This category is not enforceable at the hook level.

---

## ASI08: Cascading Failures

**Summary:** A single fault (hallucination, corrupted tool output, poisoned
memory) propagates across autonomous agents, compounding into system-wide harm.

**Enforceability at hook level:** LOW

Cascading failures describe fault propagation patterns, not individual actions.
Vectimus evaluates one action at a time and cannot detect fan-out rates,
feedback loops or cross-domain spread.  The individual root cause actions may be
caught by other policy categories, but the cascading nature of the failure is
invisible to hook-level evaluation.

**Detectable patterns:**
- None that specifically identify cascading behaviour.  Individual destructive
  actions caught by other categories may prevent cascade triggers.

**Out of scope patterns:**
- Fan-out detection (requires action rate monitoring)
- Feedback loop identification (requires cross-agent analysis)
- Cross-tenant/cross-domain spread (requires system-level monitoring)
- Governance drift (requires temporal policy compliance tracking)

**Proposed rules:** None.  This category is not enforceable at the hook level.
Vectimus contributes to cascade prevention indirectly by blocking the triggering
actions (destructive commands, infrastructure mutations) that often initiate
cascades.

---

## ASI09: Human-Agent Trust Exploitation

**Summary:** Agents exploit human trust through authoritative language,
emotional manipulation or fabricated explanations to steer humans into approving
unsafe actions.

**Enforceability at hook level:** LOW

Trust exploitation operates at the interaction layer between agent output and
human perception.  Vectimus does not inspect agent output or conversation
content.  It cannot detect persuasive language, fabricated rationales or
emotional manipulation.

**Detectable patterns:**
- None.  The attack vector is the agent's conversational output, not its tool
  calls.

**Out of scope patterns:**
- Fake explainability in agent output (requires output inspection)
- Emotional manipulation (requires NLP analysis of conversation)
- Automation bias exploitation (a human factors problem)
- Consent laundering via previews (requires UI-level controls)

**Proposed rules:** None.  This category is not enforceable at the hook level.

---

## ASI10: Rogue Agents

**Summary:** Agents deviate from intended function through emergent
misalignment, persistent compromise or self-replication, acting harmfully within
multi-agent ecosystems.

**Enforceability at hook level:** PARTIAL

Rogue agent behaviour manifests through specific observable actions: data
exfiltration, unauthorised agent spawning, self-replication attempts, and
resource abuse.  While Vectimus cannot detect the behavioural drift itself, it
can block the harmful actions that rogue agents attempt.

**Detectable patterns:**
- Excessive agent spawning (detectable per-action, not per-rate)
- Agents writing or modifying their own source code
- Agents attempting to disable monitoring or logging
- Shell commands that create cron jobs or scheduled tasks

**Out of scope patterns:**
- Goal drift detection (requires behavioural baseline comparison)
- Collusion between agents (requires multi-agent analysis)
- Reward hacking (requires objective function monitoring)
- Self-replication across network boundaries (requires infrastructure monitoring)

**Proposed rules:**
20. `owasp-020` — Block agents from disabling or clearing log/audit files
21. `owasp-021` — Block creation of cron jobs and scheduled tasks by agents

**Incident references:**
- Multi-agent systems executing arbitrary malicious code (arXiv 2503.12188, 2025)
- Preventing rogue agents in multi-agent collaboration (arXiv 2502.05986, 2025)

---

## Summary Table

| Category | Name | Enforceability | Rules | Notes |
|----------|------|----------------|-------|-------|
| ASI01 | Agent Goal Hijack | PARTIAL | 3 | Data exfiltration patterns detectable.  Goal manipulation itself is not. |
| ASI02 | Tool Misuse & Exploitation | HIGH | 3 | Agent-specific misuse patterns.  Base pack covers general destructive commands. |
| ASI03 | Identity & Privilege Abuse | PARTIAL | 3 | Credential access and privilege escalation commands detectable.  Delegation chain abuse is not. |
| ASI04 | Supply Chain Vulnerabilities | HIGH | 4 | Lockfile tampering, registry poisoning, untrusted installs.  Base pack covers npm/pip basics. |
| ASI05 | Unexpected Code Execution | HIGH | 4 | Reverse shells, eval patterns, download-execute chains all detectable. |
| ASI06 | Memory & Context Poisoning | PARTIAL | 2 | Writes to instruction files and config directories detectable.  RAG/embedding poisoning is not. |
| ASI07 | Insecure Inter-Agent Communication | LOW | 0 | Requires protocol-level controls beyond hook evaluation. |
| ASI08 | Cascading Failures | LOW | 0 | Requires system-level monitoring of fault propagation. |
| ASI09 | Human-Agent Trust Exploitation | LOW | 0 | Requires output/conversation inspection, not tool call evaluation. |
| ASI10 | Rogue Agents | PARTIAL | 2 | Log tampering and persistence mechanisms detectable.  Behavioural drift is not. |

**Total OWASP pack rules: 21**

---

## What Vectimus Does NOT Cover

Vectimus enforces deterministic pre-action controls.  It evaluates each tool
call in isolation against Cedar policies.  This design gives it strong coverage
of categories where attacks manifest as specific, recognisable tool invocations
(ASI02, ASI04, ASI05).  It provides partial coverage where attack consequences
produce detectable tool calls even though the root cause is invisible (ASI01,
ASI03, ASI06, ASI10).

Three categories sit entirely outside the scope of pre-action policy evaluation:

- **ASI07 (Insecure Inter-Agent Communication)** requires protocol-level
  controls: mutual authentication, message signing, encrypted channels and
  semantic validation between agents.  These are architectural decisions, not
  per-action checks.

- **ASI08 (Cascading Failures)** describes fault propagation patterns across
  agents and systems.  Detecting cascades requires monitoring action rates,
  identifying feedback loops and tracking cross-domain spread.  A single-action
  policy engine cannot observe these temporal patterns.

- **ASI09 (Human-Agent Trust Exploitation)** operates at the human-agent
  interaction layer.  The attack vector is the agent's conversational output
  (fabricated rationales, emotional manipulation), not its tool calls.
  Addressing this requires output inspection, UI safeguards and human factors
  training.

Organisations should pair Vectimus with complementary controls for these
categories: runtime monitoring for cascading failures, protocol-level security
for inter-agent communication, and output filtering with human oversight for
trust exploitation.
