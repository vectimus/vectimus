// VECTIMUS-MANAGED plugin-version: 1
//
// Installed by `vectimus init`.  Edits are lost on the next `vectimus init`
// and make the file unmanaged -- `vectimus init` refuses to overwrite a
// modified copy, and `vectimus remove` deletes it.
//
// Evaluates every OpenCode tool call against Cedar policies by piping it to
// `vectimus hook --source opencode`.  The call is allowed only when that
// process takes the whole payload and exits 0 with nothing at all on stdout.
// Anything else -- a deny payload, output that will not parse, whitespace
// where a verdict should be, a non-zero exit, a signal, a spawn failure, a
// missing binary, a child that exits without reading the call, or the
// deadline expiring -- throws, and OpenCode blocks the tool call.  Throwing
// is the only way a plugin can block, so every failure mode has to end in a
// throw for the guard to be worth having.
//
// Only OpenCode's exports and node:child_process are used, so this file runs
// unchanged under both the Bun and Node runtimes.  The `vectimus` binary is
// resolved from PATH; no path is baked in at install time.

import { spawn } from "node:child_process"

const VECTIMUS_BIN = "vectimus"
const SOURCE = "opencode"
const DEFAULT_DEADLINE_MS = 30_000

// A hung policy check must not hang the agent forever, and must not fall open
// when it does.  Overridable so tests do not have to wait 30 seconds.
function deadlineMs(): number {
  const raw = process.env["VECTIMUS_PLUGIN_TIMEOUT_MS"]
  if (!raw) return DEFAULT_DEADLINE_MS
  const parsed = Number.parseInt(raw, 10)
  if (!Number.isFinite(parsed) || parsed <= 0) return DEFAULT_DEADLINE_MS
  return parsed
}

function blocked(reason: string): Error {
  return new Error(`Blocked by Vectimus: ${reason}`)
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
  // Parsed, but not a deny payload this plugin understands.  An allow is
  // signalled by empty stdout, so anything printed here is still a block.
  return `policy check returned an unrecognised response (fail closed): ${stdout.slice(0, 400)}`
}

function evaluate(payload: string): Promise<void> {
  return new Promise((resolve, reject) => {
    let settled = false
    let stdout = ""
    let timer: ReturnType<typeof setTimeout> | undefined
    // An allow needs both ends to have gone right: the check exited 0 with
    // nothing to say, *and* it was handed the call it was meant to judge.
    // Either half alone is what a broken check looks like.
    let exitedSilently = false
    let stdinSettled = false
    let stdinError: string | undefined

    const finish = (error?: Error) => {
      if (settled) return
      settled = true
      if (timer !== undefined) clearTimeout(timer)
      if (error) reject(error)
      else resolve()
    }

    // Called from both ends; the last one to arrive decides.
    const allowIfDelivered = () => {
      if (!exitedSilently || !stdinSettled) return
      if (stdinError !== undefined) {
        finish(blocked(`policy check did not read the tool call: ${stdinError} (fail closed)`))
        return
      }
      finish()
    }

    let child
    try {
      child = spawn(VECTIMUS_BIN, ["hook", "--source", SOURCE], {
        stdio: ["pipe", "pipe", "pipe"],
      })
    } catch (error) {
      finish(blocked(`could not run \`${VECTIMUS_BIN}\`: ${String(error)}`))
      return
    }

    timer = setTimeout(() => {
      try {
        child.kill("SIGKILL")
      } catch {
        // Already gone; the close handler is a no-op once settled.
      }
      finish(blocked(`policy check did not answer within ${deadlineMs()}ms (fail closed)`))
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
        blocked(
          missing
            ? `\`${VECTIMUS_BIN}\` is not on PATH, so tool calls cannot be checked`
            : `could not run \`${VECTIMUS_BIN}\`: ${error.message}`,
        ),
      )
    })

    child.on("close", (code: number | null, signal: NodeJS.Signals | null) => {
      if (signal !== null) {
        finish(blocked(`policy check was killed by ${signal} (fail closed)`))
        return
      }
      if (code !== 0) {
        finish(blocked(`policy check exited ${code} (fail closed)`))
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
        finish(blocked("policy check printed only whitespace, not a verdict (fail closed)"))
        return
      }
      finish(blocked(reasonFrom(trimmed)))
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

export const VectimusPlugin = async (input: {
  directory: string
  worktree: string
}) => {
  return {
    "tool.execute.before": async (
      hook: { tool: string; sessionID: string; callID: string },
      out: { args: unknown },
    ) => {
      const payload = JSON.stringify({
        tool_name: hook.tool,
        tool_input: out.args,
        hook_event_name: "PreToolUse",
        session_id: hook.sessionID,
        call_id: hook.callID,
        // tool.execute.before carries no working directory, so use the one
        // OpenCode gave the plugin at load time.
        cwd: input.directory ?? input.worktree,
      })
      await evaluate(payload)
    },
  }
}
