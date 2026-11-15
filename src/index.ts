// Universal OpenCode sandbox: wraps every agent shell command in an OS-level sandbox
// enforced by Microsoft MXC. One plugin for all three desktop platforms: Seatbelt on
// macOS, bubblewrap on Linux, ProcessContainer on Windows.
//
// The command string is replaced with an invocation of the bundled MXC executor binary
// plus a per-call request file, so the shell tool keeps its own streaming, timeout and
// background behavior while the executor confines the process it spawns.

import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import { Plugin } from "@opencode/plugin"
import { resolvePolicy, toolBlocked } from "./policy.js"
import { quote, resolveExecutor, unsupportedNetwork, wireRequest } from "./wire.js"

interface ShellInput {
  command?: unknown
  workdir?: unknown
  timeout?: unknown
  background?: unknown
  sandbox?: unknown
}

const BLOCKED = "universal-opencode-sandbox unavailable; command blocked"

export default Plugin.define({
  id: "universal-opencode-sandbox",
  setup: async (context) => {
    const policy = resolvePolicy(context.location.directory)
    if (!policy.enabled) return

    const log = (level: "warn" | "error", message: string) =>
      console[level](`[universal-opencode-sandbox] ${message}`)

    const enforce = policy.mode === "enforce"
    const executor = resolveExecutor()
    const gap = unsupportedNetwork(process.platform, policy.network)
    const unavailable = !fs.existsSync(executor)
    const reason = unavailable
      ? executor
      : gap
        ? 'the sandbox backend on Windows cannot enforce network denial yet; set network "allow" in the sandbox config to run sandboxed with filesystem containment only'
        : undefined
    if (reason !== undefined) {
      void log(
        enforce ? "error" : "warn",
        `${reason}; ${enforce ? "shell commands will be blocked (set mode \"permissive\" to run unsandboxed)" : "commands will run without a sandbox"}`,
      )
    }

    // One request file per in-flight call; the after-hook removes it, and stale files
    // from interrupted calls are swept on unload.
    const inFlight = new Map<string, { file: string; command: string; sessionID: string }>()
    const requestDirectory = path.join(os.tmpdir(), "universal-opencode-sandbox")
    fs.mkdirSync(requestDirectory, { recursive: true })

    const cleanup = (callID: string) => {
      const pending = inFlight.get(callID)
      if (pending === undefined) return
      inFlight.delete(callID)
      fs.rmSync(pending.file, { force: true })
    }

    const before = await context.tool.hook("execute.before", async (event) => {
      // Tool blocks hold in every mode: they are an explicit policy choice, like denied
      // paths, not a fallback for a sandbox that cannot run. This closes escape routes
      // outside the sandbox, such as a host app's unsandboxed terminal tools, and unlike
      // opencode's own permission rules it cannot be re-allowed by a repository config.
      if (toolBlocked(event.tool, policy.blockedTools)) {
        void log("warn", `tool call to ${event.tool} blocked by the sandbox config (blocked_tools)`)
        throw new Error(`universal-opencode-sandbox: the tool ${event.tool} is blocked by the sandbox config`)
      }
      if (event.tool !== "shell") return
      const input = (event.input ?? {}) as ShellInput
      const command = input.command
      if (typeof command !== "string" || command === "" || inFlight.has(event.id)) return

      if (input.sandbox === false) {
        // A tool call asking to skip the sandbox never widens the policy: deny, or run
        // unsandboxed only when the user explicitly allowed it in the sandbox config.
        if (policy.unsandboxed === "deny") {
          void log("warn", `tool call asked to skip the sandbox; blocked (set unsandboxed "allow" to permit this)`)
          throw new Error("universal-opencode-sandbox: running this command unsandboxed is not allowed")
        }
        return
      }

      if (unavailable || gap) {
        if (enforce) throw new Error(`${BLOCKED}: ${reason}`)
        return
      }

      try {
        const request = wireRequest({
          command,
          workspace: context.location.directory,
          cwd: typeof input.workdir === "string" ? input.workdir : context.location.directory,
          // A background command runs until it ends; a foreground one gets the tool's timeout.
          timeout: input.background === true ? 0 : (input.timeout as number) || 120_000,
          policy,
        })
        const file = path.join(requestDirectory, `${event.id}.json`)
        fs.writeFileSync(file, JSON.stringify(request), { mode: 0o600 })
        inFlight.set(event.id, { file, command, sessionID: event.sessionID })
        input.command = `${quote(executor)} ${quote(file)}`
      } catch (error) {
        if (enforce) throw new Error(`${BLOCKED}: ${error instanceof Error ? error.message : String(error)}`)
        void log("warn", `failed to wrap the command; running unsandboxed: ${error instanceof Error ? error.message : String(error)}`)
      }
    })

    // When enabled, also sandbox user "!" commands and plugin shells. This hook fires at
    // Shell.Service level for every command, after tool.execute.before has already wrapped
    // agent tool calls, so already-wrapped commands are detected and skipped.
    const shellBefore = policy.userCommands
      ? await context.shell.hook("create.before", async (invocation) => {
          if (invocation.command.startsWith(`${quote(executor)} `)) return
          if (unavailable || gap) {
            if (enforce) throw new Error(`${BLOCKED}: ${reason}`)
            return
          }
          try {
            const request = wireRequest({
              command: invocation.command,
              workspace: context.location.directory,
              cwd: invocation.cwd,
              timeout: invocation.timeout || 0,
              policy,
            })
            const id = `shell_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`
            const file = path.join(requestDirectory, `${id}.json`)
            fs.writeFileSync(file, JSON.stringify(request), { mode: 0o600 })
            invocation.command = `${quote(executor)} ${quote(file)}`
          } catch (error) {
            if (enforce) throw new Error(`${BLOCKED}: ${error instanceof Error ? error.message : String(error)}`)
            void log("warn", `failed to wrap a shell command; running unsandboxed: ${error instanceof Error ? error.message : String(error)}`)
          }
        })
      : undefined

    const after = await context.tool.hook("execute.after", async (event) => {
      const pending = inFlight.get(event.id)
      if (pending === undefined) return
      // Restore the original command so history and transcripts show what actually ran.
      if (event.input && typeof event.input === "object") (event.input as ShellInput).command = pending.command
      cleanup(event.id)
    })

    return async () => {
      await before.dispose()
      await after.dispose()
      if (shellBefore) await shellBefore.dispose()
      for (const callID of [...inFlight.keys()]) cleanup(callID)
    }
  },
})
