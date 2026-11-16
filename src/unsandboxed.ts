// The escape tool: one shell command outside the sandbox, gated on the user's
// approval. Registered by the plugin when the policy allows escaping at all
// (unsandboxed "ask" or "allow"); with "deny" it does not exist, so an agent
// cannot even ask. The execute.before hook performs the approval prompt under
// the permission action "unsandboxed", so opencode's own permission rules can
// deny the tool outright, pre-approve command patterns, or let every call ask.

import { spawn } from "node:child_process"
import os from "node:os"

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
  // The shared "unsandboxed" action lets opencode's permission rules hide this tool
  // (deny) or pre-approve command patterns (allow) through one vocabulary.
  options: { permission: "unsandboxed" },
  execute: async (raw, context) => {
    const input = (raw ?? {}) as { command?: unknown; timeout?: unknown; workdir?: unknown }
    const command = input.command
    if (typeof command !== "string" || command === "") throw new Error("a command is required")
    const timeout = typeof input.timeout === "number" && input.timeout > 0 ? input.timeout : 120_000
    const cwd = typeof input.workdir === "string" && input.workdir !== "" ? input.workdir : workspace

    return await new Promise<ToolResult>((resolve) => {
      // The unsandboxed run behaves like the user typed it: their real home
      // directory (Paseo points the server's HOME at the workspace) and shell,
      // with POSIX sh as the portable fallback.
      const child = spawn(process.env.SHELL ?? "/bin/sh", ["-c", command], {
        cwd,
        env: { ...process.env, HOME: os.userInfo().homedir },
      })
      let stdout = ""
      let stderr = ""
      let timedOut = false
      const timer = setTimeout(() => {
        timedOut = true
        child.kill("SIGKILL")
      }, timeout)
      child.stdout?.on("data", (chunk: Buffer) => {
        if (stdout.length < OUTPUT_LIMIT) stdout += chunk.toString()
      })
      child.stderr?.on("data", (chunk: Buffer) => {
        if (stderr.length < OUTPUT_LIMIT) stderr += chunk.toString()
      })
      child.on("error", (error) => {
        clearTimeout(timer)
        resolve({ content: `failed to start: ${error.message}` })
      })
      child.on("close", (code) => {
        clearTimeout(timer)
        const combined = `stdout:\n${stdout}\nstderr:\n${stderr}`
        const tail = combined.length > RETURN_LIMIT ? `...${combined.slice(-RETURN_LIMIT)}` : combined
        resolve({
          content: `${timedOut ? "timed out\n" : ""}exit code ${code ?? "unknown"}\n\n${tail}`,
          metadata: { exitCode: code, timedOut },
        })
      })
    })
  },
})
