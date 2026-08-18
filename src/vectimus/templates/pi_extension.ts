// VECTIMUS-MANAGED extension-version: 1
//
// Installed by `vectimus init`.  Edits are lost on the next `vectimus init`
// and make the file unmanaged -- `vectimus init` refuses to overwrite a
// modified copy, and `vectimus remove` deletes it.
//
// Evaluates every Pi tool call against Cedar policies by piping it to
// `vectimus hook --source pi`.  The call is allowed only when that process
// takes the whole payload and exits 0 with nothing at all on stdout.
// Anything else -- a deny payload, output that will not parse, whitespace
// where a verdict should be, a non-zero exit, a signal, a spawn failure, a
// missing binary, a child that exits without reading the call, or the
// deadline expiring -- blocks the tool call.
//
// Pi offers two ways to block, and both were verified against 0.73.1.
// Returning `{ block: true, reason }` stops the tool and gives the reason to
// the model.  Throwing also stops it: `emitToolCall` does not catch handler
// errors, and the agent loop turns the throw into an immediate error result
// ("tool_call errors block the tool (fail-safe)").  Decided blocks use the
// structured return because the reason is worth carrying; unexpected
// exceptions are left to propagate, because those block too.  No failure mode
// ends in an allow.
//
// Only node:child_process, node:path and Pi's own types are used, so this
// runs unchanged under both the Node and Bun builds of Pi.  The `vectimus`
// binary is resolved from PATH; no path is baked in at install time.

import { spawn } from "node:child_process"
import { isAbsolute, resolve } from "node:path"

import type { ExtensionAPI, ToolCallEvent, ExtensionContext } from "@mariozechner/pi-coding-agent"

const VECTIMUS_BIN = "vectimus"
const SOURCE = "pi"
const DEFAULT_DEADLINE_MS = 30_000

// The tools whose path argument is resolved against the session cwd before
// the payload is sent.  Pi passes paths through exactly as the model wrote
// them, and a relative path cannot be matched against the absolute patterns
// policies use.  The adapter refuses a relative path that arrives without a
// cwd, so this must not be dropped.
const PATH_TOOLS = new Set(["read", "write", "edit", "grep", "find", "ls"])

// A hung policy check must not hang the agent forever, and must not fall open
// when it does.  Overridable so tests do not have to wait 30 seconds.
function deadlineMs(): number {
  const raw = process.env["VECTIMUS_PLUGIN_TIMEOUT_MS"]
  if (!raw) return DEFAULT_DEADLINE_MS
  const parsed = Number.parseInt(raw, 10)
  if (!Number.isFinite(parsed) || parsed <= 0) return DEFAULT_DEADLINE_MS
  return parsed
}

function reasonFrom(stdout: string): string {
  let parsed: unknown
  try {
    parsed = JSON.parse(stdout)
  } catch {
    return `policy check returned output that is not JSON (fail closed): ${stdout.slice(0, 400)}`
  }
  if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
    const record = parsed as Record<string, unknown>
    if (typeof record["reason"] === "string" && record["reason"].length > 0) {
      return record["reason"]
    }
  }
  // Parsed, but not a deny payload this extension understands.  An allow is
  // signalled by empty stdout, so anything printed here is still a block.
  return `policy check returned an unrecognised response (fail closed): ${stdout.slice(0, 400)}`
}

// Resolves to null when the call is allowed, or to the reason it is blocked.
function evaluate(payload: string): Promise<string | null> {
  return new Promise((resolveVerdict) => {
    let settled = false
    let stdout = ""
    let timer: ReturnType<typeof setTimeout> | undefined
    // An allow needs both ends to have gone right: the check exited 0 with
    // nothing to say, *and* it was handed the call it was meant to judge.
    // Either half alone is what a broken check looks like.
    let exitedSilently = false
    let stdinSettled = false
    let stdinError: string | undefined

    const finish = (reason: string | null) => {
      if (settled) return
      settled = true
      if (timer !== undefined) clearTimeout(timer)
      resolveVerdict(reason)
    }

    // Called from both ends; the last one to arrive decides.
    const allowIfDelivered = () => {
      if (!exitedSilently || !stdinSettled) return
      if (stdinError !== undefined) {
        finish(`policy check did not read the tool call: ${stdinError} (fail closed)`)
        return
      }
      finish(null)
    }

    let child
    try {
      child = spawn(VECTIMUS_BIN, ["hook", "--source", SOURCE], {
        stdio: ["pipe", "pipe", "pipe"],
      })
    } catch (error) {
      finish(`could not run \`${VECTIMUS_BIN}\`: ${String(error)}`)
      return
    }

    timer = setTimeout(() => {
      try {
        child.kill("SIGKILL")
      } catch {
        // Already gone; the close handler is a no-op once settled.
      }
      finish(`policy check did not answer within ${deadlineMs()}ms (fail closed)`)
    }, deadlineMs())

    child.stdout?.setEncoding("utf8")
    child.stdout?.on("data", (chunk: string) => {
      stdout += chunk
    })
    // Drain stderr so a chatty diagnostic cannot fill the pipe and wedge the
    // child.  Its content is for the human, not for the decision.
    child.stderr?.resume()

    child.on("error", (error: Error) => {
      const missing = (error as NodeJS.ErrnoException).code === "ENOENT"
      finish(
        missing
          ? `\`${VECTIMUS_BIN}\` is not on PATH, so tool calls cannot be checked`
          : `could not run \`${VECTIMUS_BIN}\`: ${error.message}`,
      )
    })

    child.on("close", (code: number | null, signal: NodeJS.Signals | null) => {
      if (signal !== null) {
        finish(`policy check was killed by ${signal} (fail closed)`)
        return
      }
      if (code !== 0) {
        finish(`policy check exited ${code} (fail closed)`)
        return
      }
      // The only allow: exit 0 and literally nothing on stdout.  Whitespace
      // is not nothing -- a check that printed a stray newline is a check
      // that did not stay silent, and reading it as consent would trust
      // output nobody meant to produce.
      if (stdout.length === 0) {
        exitedSilently = true
        allowIfDelivered()
        return
      }
      const trimmed = stdout.trim()
      if (trimmed.length === 0) {
        finish("policy check printed only whitespace, not a verdict (fail closed)")
        return
      }
      finish(reasonFrom(trimmed))
    })

    // A child that exits before reading the call never saw what it was asked
    // to judge, and exiting 0 without printing is byte-for-byte what an allow
    // looks like.  So the EPIPE that write leaves behind is a verdict of its
    // own: record it, and let the allow path refuse rather than swallow it.
    child.stdin?.on("error", (error: Error) => {
      stdinError = error.message
      stdinSettled = true
      allowIfDelivered()
    })
    child.stdin?.on("finish", () => {
      stdinSettled = true
      allowIfDelivered()
    })
    child.stdin?.end(payload)
  })
}

// Pi's tool_call event carries only { toolName, toolCallId, input }, so the
// working directory and session id come from the context.  Both are read
// defensively: a missing session id is fine, but a missing cwd would make the
// adapter refuse every relative path, so the process cwd is the fallback.
function buildPayload(event: ToolCallEvent, ctx: ExtensionContext): string {
  const cwd = typeof ctx.cwd === "string" && ctx.cwd.length > 0 ? ctx.cwd : process.cwd()

  // A copy, not the event's own object.  `event.input` is mutable and Pi
  // executes whatever is left in it, so resolving the path in place would
  // change the call being made rather than just the call being described.
  const input: Record<string, unknown> = { ...(event.input as Record<string, unknown>) }
  if (PATH_TOOLS.has(event.toolName) && typeof input["path"] === "string") {
    const given = input["path"] as string
    if (!isAbsolute(given)) {
      input["path"] = resolve(cwd, given)
    }
  }

  let sessionId: string | undefined
  try {
    sessionId = ctx.sessionManager?.getSessionId()
  } catch {
    // Ephemeral sessions (`--no-session`) have none; it is only metadata.
  }

  return JSON.stringify({
    tool_name: event.toolName,
    tool_input: input,
    hook_event_name: "PreToolUse",
    session_id: sessionId,
    call_id: event.toolCallId,
    cwd,
  })
}

export default function (pi: ExtensionAPI) {
  pi.on("tool_call", async (event, ctx) => {
    const reason = await evaluate(buildPayload(event, ctx))
    if (reason !== null) {
      return { block: true, reason: `Blocked by Vectimus: ${reason}` }
    }
    return undefined
  })
}
