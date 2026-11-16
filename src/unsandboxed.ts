// The escape tool: one shell command outside the sandbox, gated on the user's
// approval. Registered by the plugin when the policy allows escaping at all
// (unsandboxed "ask" or "allow"); with "deny" it does not exist, so an agent
// cannot even ask. The execute.before hook performs the approval prompt under
// the permission action "shell_escalated", so opencode's own permission rules can
// deny the tool outright, pre-approve command patterns, or let every call ask.

import { spawn } from "node:child_process"
import path from "node:path"
import { realHome } from "./policy.js"

// Enough of the tool contract to register the tool without reaching into
// package-internal type paths; the executor is ours either way.
export interface ToolResult {
  readonly content?: string | ReadonlyArray<{ type: "text"; text: string }>
  readonly metadata?: Record<string, unknown>
}

interface ToolContext {
  readonly sessionID: string
}

// The JSON Schema of the tool input, typed concretely so it satisfies the
// plugin API's ValueSchema (a plain JSON value). Type aliases, not interfaces:
// only aliases carry the implicit index signature JsonSchema requires.
type FieldType = { readonly type: "string" | "number"; readonly description: string }

export type ToolInputSchema = {
  readonly type: "object"
  readonly properties: {
    readonly command: FieldType
    readonly timeout: FieldType
    readonly workdir: FieldType
  }
  readonly required: readonly ["command"]
  readonly additionalProperties: false
}

export interface ToolRegistration {
  readonly name: string
  readonly description: string
  readonly input: ToolInputSchema
  readonly options?: { readonly permission?: string }
  readonly execute: (input: unknown, context: ToolContext) => Promise<ToolResult>
}

// Combined output is capped so a chatty command cannot exhaust memory, and the
// returned text keeps only the tail, like the shell tool's bounded output.
const OUTPUT_LIMIT = 200_000
const RETURN_LIMIT = 50_000

// Which shell runs the command. POSIX uses the user's login shell with sh as the
// portable fallback. Windows has neither /bin/sh nor a SHELL variable, so it goes
// through cmd.exe the way Node's own exec does: /d /s /c with the whole command in
// one pair of quotes, passed verbatim so Node does not re-escape those quotes.
export const shellInvocation = (
  command: string,
  platform: string = process.platform,
  env: Record<string, string | undefined> = process.env,
): { file: string; args: string[]; options: { windowsVerbatimArguments?: boolean } } => {
  if (platform === "win32") {
    return {
      file: env.ComSpec ?? "cmd.exe",
      args: ["/d", "/s", "/c", `"${command}"`],
      options: { windowsVerbatimArguments: true },
    }
  }
  return { file: env.SHELL ?? "/bin/sh", args: ["-c", command], options: {} }
}

// Kill the shell and everything it started. Killing only the shell leaves
// grandchildren alive holding the output pipes open, which hangs the tool call.
const killTree = (child: ReturnType<typeof spawn>) => {
  const pid = child.pid
  if (pid === undefined) return
  if (process.platform === "win32") {
    try {
      const killer = spawn("taskkill", ["/pid", String(pid), "/T", "/F"], { stdio: "ignore" })
      killer.on("error", () => child.kill())
    } catch {
      child.kill()
    }
    return
  }
  try {
    // Negative pid addresses the process group the detached shell leads.
    process.kill(-pid, "SIGKILL")
  } catch {
    // ESRCH: the group is already gone. Anything else: at least take the shell.
    try {
      child.kill("SIGKILL")
    } catch {}
  }
}

// After the kill, how long to wait for the pipes to close before giving up on them.
const KILL_GRACE_MS = 2_000

export const unsandboxedShellTool = (workspace: string): ToolRegistration => ({
  name: "shell_escalated",
  description:
    "Run one shell command escalated: outside the sandbox, on the host. The user approves every call and sees the exact command (or has pre-approved a pattern). " +
    "Use this only for what the sandboxed shell cannot do and the user asked for, such as publishing a package, pushing over SSH, or reaching the network; " +
    "for everything else prefer the sandboxed shell tool.",
  input: {
    type: "object",
    properties: {
      command: { type: "string", description: "The shell command to run unsandboxed" },
      timeout: { type: "number", description: "Timeout in milliseconds (default 120000)" },
      workdir: { type: "string", description: "Working directory (default: the workspace)" },
    },
    required: ["command"],
    additionalProperties: false,
  } as ToolInputSchema,
  // The shared "shell_escalated" action lets opencode's permission rules hide this
  // tool (deny) or pre-approve command patterns (allow) through one vocabulary.
  options: { permission: "shell_escalated" },
  execute: async (raw, context) => {
    const input = (raw ?? {}) as { command?: unknown; timeout?: unknown; workdir?: unknown }
    const command = input.command
    if (typeof command !== "string" || command === "") throw new Error("a command is required")
    const timeout = typeof input.timeout === "number" && input.timeout > 0 ? input.timeout : 120_000
    const cwd = typeof input.workdir === "string" && input.workdir !== "" ? path.resolve(workspace, input.workdir) : workspace

    return await new Promise<ToolResult>((resolve) => {
      // The unsandboxed run behaves like the user typed it: their real home
      // directory (Paseo points the server's HOME at the workspace) and shell.
      // Windows has no HOME convention to repair, so it is left alone there.
      const shell = shellInvocation(command)
      const win = process.platform === "win32"
      const child = spawn(shell.file, shell.args, {
        cwd,
        env: win ? process.env : { ...process.env, HOME: realHome() },
        // Own process group on POSIX, so a timeout can kill the whole tree.
        detached: !win,
        ...shell.options,
      })
      let stdout = ""
      let stderr = ""
      let timedOut = false
      let settled = false
      let timer: ReturnType<typeof setTimeout> | undefined
      let grace: ReturnType<typeof setTimeout> | undefined
      const finish = (result: ToolResult) => {
        if (settled) return
        settled = true
        clearTimeout(timer)
        clearTimeout(grace)
        resolve(result)
      }
      const report = (code: number | null) => {
        const combined = `stdout:\n${stdout}\nstderr:\n${stderr}`
        const tail = combined.length > RETURN_LIMIT ? `...${combined.slice(-RETURN_LIMIT)}` : combined
        finish({
          content: `${timedOut ? "timed out\n" : ""}exit code ${code ?? "unknown"}\n\n${tail}`,
          metadata: { exitCode: code, timedOut },
        })
      }
      timer = setTimeout(() => {
        timedOut = true
        killTree(child)
        // Do not depend on the pipes closing: resolve on exit or after a short grace.
        child.once("exit", (code) => report(code))
        grace = setTimeout(() => report(child.exitCode), KILL_GRACE_MS)
      }, timeout)
      // Append only the remaining allowance so one large chunk cannot overshoot.
      child.stdout?.on("data", (chunk: Buffer) => {
        stdout += chunk.toString().slice(0, Math.max(0, OUTPUT_LIMIT - stdout.length))
      })
      child.stderr?.on("data", (chunk: Buffer) => {
        stderr += chunk.toString().slice(0, Math.max(0, OUTPUT_LIMIT - stderr.length))
      })
      child.on("error", (error) => finish({ content: `failed to start: ${error.message}` }))
      child.on("close", (code) => report(code))
    })
  },
})
