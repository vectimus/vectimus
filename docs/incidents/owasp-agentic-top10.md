# OWASP Top 10 for Agentic Applications 2026

The OWASP Top 10 for Agentic Applications (version 2026, published December
2025) defines the ten highest-impact threats to autonomous AI agents.  It was
produced by the OWASP Gen AI Security Project's Agentic Security Initiative.

Unlike the OWASP LLM Top 10, which focuses on single model interactions, the
Agentic Top 10 addresses risks that emerge when AI systems plan, decide and act
across multiple steps and systems with varying degrees of autonomy.

**Official resource:**
[OWASP Top 10 for Agentic Applications for 2026](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/)

---

## Vectimus Coverage Matrix

| ASI | Category | Vectimus Coverage | OWASP Rules | Notes |
|-----|----------|-------------------|-------------|-------|
| ASI01 | Agent Goal Hijack | Partially enforced | 3 | Detects data exfiltration patterns (base64+curl, DNS tunnelling, credential piping).  Cannot detect prompt injection or goal drift. |
| ASI02 | Tool Misuse & Exploitation | Enforced | 3 | Blocks system config writes, /tmp script execution, database destruction.  Base pack adds 6 more for destructive commands. |
| ASI03 | Identity & Privilege Abuse | Partially enforced | 3 | Blocks cloud CLI role assumption, /root access, sudo/su.  Cannot detect delegation chains or token inheritance. |
| ASI04 | Supply Chain Vulnerabilities | Enforced | 4 | Blocks lockfile tampering, registry config modification, untrusted cargo installs, git submodule additions.  Base pack adds 4 more for npm/pip. |
| ASI05 | Unexpected Code Execution | Enforced | 4 | Blocks reverse shells, python -c with networking, download-execute chains, eval/exec patterns.  Base pack adds curl\|bash blocking. |
| ASI06 | Memory & Context Poisoning | Partially enforced | 2 | Blocks writes to agent instruction files (CLAUDE.md, AGENTS.md, .cursorrules, copilot-instructions.md) and agent state directories.  Cannot detect RAG poisoning or conversation memory manipulation. |
| ASI07 | Insecure Inter-Agent Comms | Not enforced | 0 | Requires protocol-level controls (mutual auth, message signing, encrypted channels).  Outside hook-level scope. |
| ASI08 | Cascading Failures | Not enforced | 0 | Requires system-level monitoring of fault propagation rates and feedback loops.  Outside single-action scope. |
| ASI09 | Human-Agent Trust Exploitation | Not enforced | 0 | Requires output/conversation analysis and UI safeguards.  Tool calls do not reveal trust exploitation. |
| ASI10 | Rogue Agents | Partially enforced | 2 | Blocks log/audit tampering and persistence mechanisms (cron, systemctl, schtasks).  Cannot detect behavioural drift or agent collusion. |

**Total OWASP Agentic pack rules: 21**
**Combined with base pack: 48 rules**

---

## Enforced Categories

### ASI02: Tool Misuse and Exploitation

Vectimus intercepts every tool call before execution.  This is the core
capability that makes ASI02 the strongest coverage area.  The base pack blocks
destructive shell commands (rm -rf, mkfs, dd), infrastructure mutations
(terraform destroy, kubectl delete namespace) and unsafe package operations (npm
publish).  The OWASP pack adds agent-specific patterns: writes to /etc/*, script
execution from /tmp and database destruction commands.

**What Vectimus detects:** Destructive commands, system configuration
modification, database drops, unsafe script execution from temp directories.

**What Vectimus does not detect:** Tool output manipulation, over-invocation
patterns (requires rate monitoring across actions), logical tool chaining where
individual calls appear benign.

### ASI04: Agentic Supply Chain Vulnerabilities

Supply chain attacks produce visible artifacts: modified lockfiles, altered
registry configurations, untrusted package installs.  The base pack blocks npm
publish, pip install from custom indexes, npm install from URLs and global npm
installs.  The OWASP pack adds lockfile protection (package-lock.json,
yarn.lock, poetry.lock, uv.lock, Cargo.lock and others), registry config
protection (.npmrc, .pypirc, pip.conf), cargo install from git URLs and git
submodule additions.

**What Vectimus detects:** Direct lockfile modification, registry configuration
tampering, untrusted dependency sources, submodule injection.

**What Vectimus does not detect:** Runtime MCP tool descriptor poisoning,
dynamically loaded prompt templates, compromised agent registries.

### ASI05: Unexpected Code Execution (RCE)

Code execution attempts are directly observable in shell commands.  The base pack
blocks curl\|bash piping.  The OWASP pack adds reverse shell patterns (bash -i
\>& /dev/tcp, nc -e, mkfifo+nc), Python one-liner network operations (python -c
with socket/urllib/requests), download-execute chains (curl+chmod+x,
wget+chmod+x) and eval/exec patterns (eval \$(curl), python -c exec(),
node -e eval()).

**What Vectimus detects:** Reverse shells, inline network code, download-execute
chains, eval/exec of dynamic code.

**What Vectimus does not detect:** Code hallucination (requires inspecting
generated code semantics), multi-tool chain exploitation where each step is
benign, unsafe object deserialization within application code.

---

## Partially Enforced Categories

### ASI01: Agent Goal Hijack

Vectimus cannot detect prompt injection or goal manipulation.  It sees tool calls,
not the reasoning that produced them.  However, successful goal hijacks
frequently result in data exfiltration attempts.  The OWASP pack detects
base64-encoded data piped to curl/wget, DNS exfiltration via nslookup/dig with
subshell expansion, and credential file contents piped to network tools.

**Gaps:** The hijack itself is invisible.  An attacker who redirects an agent's
goals toward actions that look legitimate (e.g. modifying code in subtle ways)
will not be caught.  Vectimus only catches the exfiltration phase.

### ASI03: Identity and Privilege Abuse

Vectimus detects specific privilege escalation commands: cloud CLI role
assumption (aws sts assume-role, gcloud auth login, az login), sudo/su
execution, and file access to /root.  These are common mechanisms for privilege
abuse.

**Gaps:** Delegation chain analysis, token inheritance between agents, TOCTOU
permission drift and synthetic identity injection all require runtime identity
systems beyond hook-level evaluation.

### ASI06: Memory and Context Poisoning

Vectimus protects agent instruction files that shape behaviour across sessions:
CLAUDE.md, AGENTS.md, .cursorrules, .github/copilot-instructions.md, .windsurfrules and
.clinerules.  It also blocks writes to agent state directories (.continue/,
.aider, .claude/memory, .cursor/memory).

**Gaps:** RAG/embedding store poisoning, conversation context manipulation,
shared memory contamination between agents, and long-term memory drift are all
invisible at the file-write level.

### ASI10: Rogue Agents

Vectimus detects persistence mechanisms that rogue agents use: log/audit file
tampering (truncate, rm, redirect of /var/log files) and scheduled task creation
(crontab, systemctl enable, schtasks).

**Gaps:** Behavioural drift detection, agent collusion, reward hacking and
self-replication across network boundaries require multi-agent monitoring systems.

---

## Not Enforced Categories

### ASI07: Insecure Inter-Agent Communication

This category describes attacks on the message layer between agents: message
interception, spoofing, replay attacks, protocol downgrades and agent discovery
manipulation.  Vectimus evaluates individual tool calls, not inter-agent message
flows.  Addressing ASI07 requires mutual authentication (mTLS), message signing,
encrypted channels and protocol-level validation.

### ASI08: Cascading Failures

Cascading failures are patterns of fault propagation: fan-out effects, feedback
loops, cross-domain spread.  They are temporal and systemic.  Vectimus evaluates
one action at a time in isolation.  It contributes to cascade prevention
indirectly by blocking triggering actions (infrastructure mutations, destructive
commands) but cannot detect the cascade itself.  Addressing ASI08 requires
runtime monitoring with circuit breakers, rate limiting and system-level
observability.

### ASI09: Human-Agent Trust Exploitation

This category operates at the human-agent interaction layer.  The attack vector
is the agent's conversational output: fabricated rationales, emotional
manipulation, fake explainability.  Vectimus does not inspect agent output or
conversation content.  Addressing ASI09 requires output filtering, UI safeguards
(risk badges, confirmation prompts) and human factors training.

---

## Complementary Controls

Organisations deploying Vectimus should pair it with:

1. **Runtime monitoring** for ASI08 (cascading failures) and rate-based
   detection components of ASI02 and ASI10
2. **Protocol-level security** for ASI07 (inter-agent communication): mTLS,
   message signing, agent registries with attestation
3. **Output filtering and UI safeguards** for ASI09 (trust exploitation):
   risk labels, mandatory confirmation for high-impact actions, provenance
   metadata
4. **Identity management platforms** for ASI03 (privilege abuse): per-agent
   identities, scoped credentials, delegation chain tracking
5. **RAG/embedding security** for ASI06 (memory poisoning): input validation
   on vector stores, tenant isolation, trust-scored memory entries

Vectimus provides the deterministic pre-action enforcement layer.  It is one
component of a complete agentic security posture, not a replacement for all of
it.
