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
import { matchesWildcard, resolvePolicy, toolBlocked } from "./policy.js"
import { quote, resolveExecutor, unsupportedNetwork, wireRequest } from "./wire.js"
import { unsandboxedShellTool } from "./unsandboxed.js"

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
    // The policy is re-resolved on every hook invocation, so config edits take
    // effect on the next tool call without a restart - including the "enabled"
    // kill switch, which turns every hook into a no-op while it stays false.
    let policy = resolvePolicy(context.location.directory)
    const refreshPolicy = () => {
      policy = resolvePolicy(context.location.directory)
    }
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

    // The escape tool exists only when the policy allows escaping at all: with
    // unsandboxed "deny" it is not registered, so an agent cannot even ask. Its
    // permission action is "unsandboxed", so opencode's permission rules can hide
    // it (deny) or pre-approve command patterns (allow) through one vocabulary.
    const escapeTool =
      policy.unsandboxed === "deny"
        ? undefined
        : await context.tool.transform((editor) => {
            editor.add(unsandboxedShellTool(context.location.directory))
            // Deprecated alias from 0.4.x: same executor and gate, kept so existing
            // configs and muscle memory keep working through 0.5.x.
            editor.add({
              ...unsandboxedShellTool(context.location.directory),
              name: "shell_unsandboxed",
              description: "Deprecated alias of shell_escalated. Use shell_escalated.",
            })
          })

    // Ask mode must actually ask. Hosts like Paseo give sessions a catch-all allow rule
    // ("*" matches every action), which would make the approval prompt resolve silently.
    // This guard forces the prompt for every unsandboxed escape unless a rule that names
    // this action specifically allows the command: a pre-approval, or a saved "always
    // allow" from an earlier prompt. Deny rules short-circuit before the hook, so they
    // keep blocking without it.
    const askGuard =
      policy.unsandboxed === "ask"
        ? await context.permission.hook("evaluate", async (event) => {
            refreshPolicy()
            // With the kill switch off, the guard stands down: no forced prompts.
            if (!policy.enabled) return
            if (event.action !== "unsandboxed") return
            // The prompt must name the command: it is the only thing the user approves,
            // and hosts render the message but not necessarily the resources.
            event.message = `Run this command outside the sandbox:\n\n${event.resources.join(" ")}`
            if (event.effect !== "allow") return
            const force = () => {
              event.effect = "ask"
            }
            try {
              const session = await context.session.get({ sessionID: event.sessionID })
              const specific = (session.permissions ?? []).some(
                (rule) =>
                  rule.effect === "allow" &&
                  rule.action !== "*" &&
                  matchesWildcard(event.action, rule.action) &&
                  event.resources.every((resource) => matchesWildcard(resource, rule.resource)),
              )
              if (!specific) force()
            } catch {
              // When the session rules cannot be read, fail closed and ask anyway.
              force()
            }
          })
        : undefined

    const before = await context.tool.hook("execute.before", async (event) => {
      refreshPolicy()
      // The kill switch: with enabled false every hook stands down, so nothing is
      // sandboxed, blocked or prompted until the config turns it back on.
      if (!policy.enabled) return
      // Tool blocks hold in every mode: they are an explicit policy choice, like denied
      // paths, not a fallback for a sandbox that cannot run. This closes escape routes
      // outside the sandbox, such as a host app's unsandboxed terminal tools, and unlike
      // opencode's own permission rules it cannot be re-allowed by a repository config.
      if (toolBlocked(event.tool, policy.blockedTools)) {
        void log("warn", `tool call to ${event.tool} blocked by the sandbox config (blocked_tools)`)
        throw new Error(`universal-opencode-sandbox: the tool ${event.tool} is blocked by the sandbox config`)
      }
      if (event.tool === "shell_escalated" || event.tool === "shell_unsandboxed") {
        // The escape tool's own gate: ask mode turns the call into an approval
        // prompt naming the exact command; allow mode is pre-approved by config.
        const escape = (event.input as { command?: unknown } | undefined)?.command
        if (policy.unsandboxed === "ask" && typeof escape === "string" && escape !== "") {
          const preapproved = policy.unsandboxedAllow.some((pattern) => matchesWildcard(escape, pattern))
          if (!preapproved) {
            await context.permission.assert({
              sessionID: event.sessionID,
              action: "unsandboxed",
              resources: [escape],
              metadata: { command: escape },
            })
            void log("warn", `the user approved running a command unsandboxed: ${escape}`)
          }
        }
        return
      }
      if (event.tool !== "shell") return
      const input = (event.input ?? {}) as ShellInput
      const command = input.command
      if (typeof command !== "string" || command === "" || inFlight.has(event.id)) return

      if (input.sandbox === false) {
        // A tool call asking to skip the sandbox never widens the policy: deny, ask the
        // user for this exact command, or run unsandboxed only when explicitly allowed.
        if (policy.unsandboxed === "deny") {
          void log("warn", `tool call asked to skip the sandbox; blocked (set unsandboxed "ask" or "allow" to permit this)`)
          throw new Error("universal-opencode-sandbox: running this command unsandboxed is not allowed")
        }
        if (policy.unsandboxed === "ask") {
          // Commands matching unsandboxed_allow are pre-approved in the user's own
          // config: no prompt. Everything else names the exact command and waits for
          // the reply; a rejection or deny rule fails the call. The dedicated action
          // keeps an allow rule for "shell" from silently approving an escape, and no
          // save scope is offered, so a prompt never persists anything by itself.
          const preapproved = policy.unsandboxedAllow.some((pattern) => matchesWildcard(command, pattern))
          if (!preapproved) {
            await context.permission.assert({
              sessionID: event.sessionID,
              action: "unsandboxed",
              resources: [command],
              metadata: { command },
            })
            void log("warn", `the user approved running a command unsandboxed: ${command}`)
          } else {
            void log("warn", `running a command unsandboxed without a prompt (unsandboxed_allow): ${command}`)
          }
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
          refreshPolicy()
          if (!policy.enabled) return
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
      if (escapeTool) await escapeTool.dispose()
      if (askGuard) await askGuard.dispose()
      for (const callID of [...inFlight.keys()]) cleanup(callID)
    }
  },
})
