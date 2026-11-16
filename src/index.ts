// Universal OpenCode sandbox: wraps every agent shell command in an OS-level sandbox
// enforced by Microsoft MXC. One plugin for all three desktop platforms: Seatbelt on
// macOS, bubblewrap on Linux, ProcessContainer on Windows.
//
// The command string is replaced with an invocation of the bundled MXC executor binary
// plus a per-call request file, so the shell tool keeps its own streaming, timeout and
// background behavior while the executor confines the process it spawns.

import fs from "node:fs"
import path from "node:path"
import { Plugin } from "@opencode/plugin"
import {
  adminConfigPath,
  configDirectory,
  expandHome,
  matchesWildcard,
  preapproved,
  resolvePolicy,
  stateDirectory,
  toolBlocked,
} from "./policy.js"
import { executorCommand, quote, resolveExecutor, unsupportedNetwork, wireRequest } from "./wire.js"
import { unsandboxedShellTool } from "./unsandboxed.js"

interface ShellInput {
  command?: unknown
  workdir?: unknown
  timeout?: unknown
  background?: unknown
  sandbox?: unknown
}

const BLOCKED = "universal-opencode-sandbox unavailable; command blocked"
const WINDOWS_GAP =
  'the sandbox backend on Windows cannot enforce network denial yet; set network "allow" in the sandbox config to run sandboxed with filesystem containment only'
const STALE_REQUEST_MS = 24 * 60 * 60 * 1000

// Only the shell tool runs inside the sandbox. OpenCode's own file tools (write, edit,
// apply_patch) run in the host process, so a catch-all allow rule would let an agent
// rewrite this plugin's hot-reloaded config (enabled: false) through them. The guard is
// generic on purpose: it looks at every string under a path-like key in the tool input,
// which also covers file tools that host apps and MCP servers add.
const PATH_KEY = /path|file|dir|target|dest|source|src|cwd|location|uri|from|^to$/i
const PATCH_HEADER = /^\*\*\* (?:Add File|Update File|Delete File|Move to):[ \t]*(.+?)\s*$/gm

/** Collects path-like strings from a tool input: top level plus one level of arrays and objects. */
function candidatePaths(input: unknown): string[] {
  if (!input || typeof input !== "object") return []
  const found: string[] = []
  const visit = (value: unknown, key: string, depth: number) => {
    if (typeof value === "string") {
      if (PATH_KEY.test(key)) found.push(value)
    } else if (depth > 0 && value && typeof value === "object") {
      if (Array.isArray(value)) for (const item of value) visit(item, key, depth - 1)
      else for (const [name, item] of Object.entries(value)) visit(item, name, depth - 1)
    }
  }
  for (const [key, value] of Object.entries(input)) {
    visit(value, key, 2)
    // apply_patch carries its target paths inside the patch text, under any key.
    if (typeof value === "string" && value.includes("*** ")) {
      for (const match of value.matchAll(PATCH_HEADER)) found.push(match[1])
    }
  }
  return found
}

/** Resolves a path the way the OS will: symlinks followed on the deepest existing ancestor. */
function realish(target: string, base: string): string {
  let current = path.resolve(base, expandHome(target))
  const tail: string[] = []
  for (;;) {
    try {
      return path.join(fs.realpathSync(current), ...tail.reverse())
    } catch {
      const parent = path.dirname(current)
      if (parent === current) return path.join(current, ...tail.reverse())
      tail.push(path.basename(current))
      current = parent
    }
  }
}

function inside(candidate: string, directory: string): boolean {
  const fold = process.platform === "darwin" || process.platform === "win32"
  const relative = path.relative(fold ? directory.toLowerCase() : directory, fold ? candidate.toLowerCase() : candidate)
  return relative === "" || (relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative))
}

/** The first path in a tool input that lands in the sandbox's own config, state or admin directory. */
function touchesGuarded(input: unknown, workspace: string): string | undefined {
  const guarded = [configDirectory(), stateDirectory(), path.dirname(adminConfigPath())]
  const roots = guarded.flatMap((directory) => [path.resolve(directory), realish(directory, workspace)])
  for (const candidate of candidatePaths(input)) {
    if (candidate === "") continue
    const resolved = realish(candidate, workspace)
    const plain = path.resolve(workspace, expandHome(candidate))
    if (roots.some((root) => inside(resolved, root) || inside(plain, root))) return candidate
  }
  return undefined
}

/** Best effort: drops request files that an interrupted run left behind. Never throws. */
function sweepStale(directory: string) {
  try {
    const cutoff = Date.now() - STALE_REQUEST_MS
    for (const name of fs.readdirSync(directory)) {
      if (!name.endsWith(".json")) continue
      const file = path.join(directory, name)
      try {
        const stat = fs.lstatSync(file)
        if (stat.isFile() && stat.mtimeMs < cutoff) fs.rmSync(file, { force: true })
      } catch {
        // A file that vanished or cannot be removed is not worth failing over.
      }
    }
  } catch {
    // The directory itself is already reported as a setup failure when it matters.
  }
}

export default Plugin.define({
  id: "universal-opencode-sandbox",
  setup: async (context) => {
    // The policy is re-resolved on every hook invocation, so config edits take
    // effect on the next tool call without a restart - including the "enabled"
    // kill switch, which turns every hook into a no-op while it stays false.
    // Everything that depends on the policy (enforce, the Windows network gap,
    // the ask guard, user commands) is read from the live value at call time.
    // Only registration happens once, at load: with enabled false nothing is
    // registered, and the escape tools exist only when unsandboxed was not "deny".
    // Going from "deny" to "ask"/"allow" therefore still needs a restart.
    let policy = resolvePolicy(context.location.directory)
    const refreshPolicy = () => {
      policy = resolvePolicy(context.location.directory)
    }
    if (!policy.enabled) return

    const log = (level: "warn" | "error", message: string) =>
      console[level](`[universal-opencode-sandbox] ${message}`)

    // The two always-on companion hooks are registered through this wrapper: a host
    // whose plugin API lacks one of them must not make setup throw, because a plugin
    // that fails to load leaves the shell tool itself unsandboxed.
    const optional = async <T>(name: string, register: () => Promise<T>): Promise<T | undefined> => {
      try {
        return await register()
      } catch (error) {
        void log("warn", `the host does not support the ${name} hook; continuing without it: ${error instanceof Error ? error.message : String(error)}`)
        return undefined
      }
    }

    // Request files live in the state directory, never in the temp dir: the temp dir is
    // a writable root of the sandbox, so a sandboxed command could delete the directory
    // (making every later wrap fail, and in permissive mode run unsandboxed) or rewrite
    // the request file of a later call before the executor reads it. The state directory
    // is also passed as a guarded path, so a workspace that covers it cannot reopen that.
    const requestDirectory = path.join(stateDirectory(), "requests")
    const executor = resolveExecutor()
    // Setup must never throw: a plugin whose setup throws may simply be skipped by the
    // host, leaving every command unsandboxed. Any failure here becomes the same
    // "unavailable" state as a missing executor, handled per mode at call time.
    let setupFailure: string | undefined = fs.existsSync(executor) ? undefined : executor
    if (setupFailure === undefined) {
      try {
        fs.mkdirSync(requestDirectory, { recursive: true, mode: 0o700 })
        sweepStale(requestDirectory)
      } catch (error) {
        setupFailure = `the sandbox request directory ${requestDirectory} cannot be created: ${error instanceof Error ? error.message : String(error)}`
      }
    }
    // Why a command cannot be sandboxed right now, or undefined when it can.
    const unavailableReason = (): string | undefined =>
      setupFailure ?? (unsupportedNetwork(process.platform, policy.network) ? WINDOWS_GAP : undefined)

    const startup = unavailableReason()
    if (startup !== undefined) {
      const strict = policy.mode === "enforce"
      void log(
        strict ? "error" : "warn",
        `${startup}; ${strict ? "shell commands will be blocked (set mode \"permissive\" to run unsandboxed)" : "commands will run without a sandbox"}`,
      )
    }

    // One request file per in-flight call; the after-hook removes it. User-command files
    // have no after-hook to hang on (the shell hook only fires before the command), so
    // they are tracked separately and removed on unload; anything an interrupted run
    // leaves behind is swept at the next setup once it is a day old.
    const inFlight = new Map<string, { file: string; command: string; sessionID: string; background: boolean }>()
    const userRequests = new Set<string>()

    const cleanup = (callID: string) => {
      const pending = inFlight.get(callID)
      if (pending === undefined) return
      inFlight.delete(callID)
      // A background command's tool call returns before the executor it spawned has read
      // its request file, so an immediate delete makes the executor fail with the MXC
      // "Configuration file not found" parse error. The removal is delayed long enough
      // for the executor to have read the file at startup.
      const remove = () => fs.rmSync(pending.file, { force: true })
      if (pending.background) setTimeout(remove, 10_000).unref?.()
      else remove()
    }

    // Writes the per-call request file for a command and returns its path.
    const writeRequest = (id: string, command: string, cwd: string, timeout: number): string => {
      const request = wireRequest({
        command,
        workspace: context.location.directory,
        cwd,
        timeout,
        policy,
        // Read-only for the sandboxed command even when a writable root covers them.
        guarded: [configDirectory(), stateDirectory()],
      })
      // The id comes from the host; keep it from steering the file out of the directory.
      const file = path.join(requestDirectory, `${id.replace(/[^A-Za-z0-9_.-]/g, "_")}.json`)
      fs.mkdirSync(requestDirectory, { recursive: true, mode: 0o700 })
      fs.writeFileSync(file, JSON.stringify(request), { mode: 0o600 })
      return file
    }

    // The escape tool exists only when the policy allows escaping at all: with
    // unsandboxed "deny" at load it is not registered, so an agent cannot even ask.
    // Its permission action is "unsandboxed", so opencode's permission rules can hide
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
    // keep blocking without it. Always registered and checked against the live policy,
    // so turning "ask" on in the config works without a restart and off stands it down.
    const askGuard = await optional("permission evaluate", () => context.permission.hook("evaluate", async (event) => {
      refreshPolicy()
      // With the kill switch off, the guard stands down: no forced prompts.
      if (!policy.enabled || policy.unsandboxed !== "ask") return
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
        // A wildcard rule never silently approves chaining or substitution syntax,
        // the same rule as unsandboxed_allow (see preapproved).
        const specific = (session.permissions ?? []).some(
          (rule) =>
            rule.effect === "allow" &&
            rule.action !== "*" &&
            matchesWildcard(event.action, rule.action) &&
            event.resources.every((resource) => preapproved(resource, [rule.resource])),
        )
        if (!specific) force()
      } catch {
        // When the session rules cannot be read, fail closed and ask anyway.
        force()
      }
    }))

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
        // The tool may have been registered while escaping was allowed; the live policy
        // decides, so tightening the config to "deny" takes effect on the next call.
        if (policy.unsandboxed === "deny") {
          void log("warn", `escape tool call blocked; unsandboxed is "deny" in the sandbox config`)
          throw new Error("universal-opencode-sandbox: running this command unsandboxed is not allowed")
        }
        // The escape tool's own gate: ask mode turns the call into an approval
        // prompt naming the exact command; allow mode is pre-approved by config.
        const escape = (event.input as { command?: unknown } | undefined)?.command
        if (policy.unsandboxed === "ask" && typeof escape === "string" && escape !== "") {
          if (!preapproved(escape, policy.unsandboxedAllow)) {
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
      if (event.tool !== "shell") {
        // File tools run in the host process, outside the sandbox: keep them away from
        // the sandbox's own config and state, which the next call would hot-reload.
        const target = touchesGuarded(event.input, context.location.directory)
        if (target !== undefined) {
          void log("warn", `tool call to ${event.tool} blocked: ${target} is inside the sandbox's own config or state`)
          throw new Error(`universal-opencode-sandbox: the tool ${event.tool} may not touch the sandbox's own config or state: ${target}`)
        }
        return
      }
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
          if (!preapproved(command, policy.unsandboxedAllow)) {
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

      const unavailable = unavailableReason()
      if (unavailable !== undefined) {
        if (policy.mode === "enforce") throw new Error(`${BLOCKED}: ${unavailable}`)
        return
      }

      try {
        const file = writeRequest(
          event.id,
          command,
          typeof input.workdir === "string" ? input.workdir : context.location.directory,
          // A background command runs until it ends; a foreground one gets the tool's timeout.
          input.background === true ? 0 : (input.timeout as number) || 120_000,
        )
        inFlight.set(event.id, { file, command, sessionID: event.sessionID, background: input.background === true })
        input.command = executorCommand(executor, file)
      } catch (error) {
        if (policy.mode === "enforce") throw new Error(`${BLOCKED}: ${error instanceof Error ? error.message : String(error)}`)
        void log("warn", `failed to wrap the command; running unsandboxed: ${error instanceof Error ? error.message : String(error)}`)
      }
    })

    // Sandboxes user "!" commands and plugin shells when sandbox_user_commands is on.
    // This hook fires at Shell.Service level for every command, after tool.execute.before
    // has already wrapped agent tool calls, so already-wrapped commands are detected and
    // skipped. Always registered and gated on the live policy, so the option works
    // without a restart.
    const shellBefore = await optional("shell create.before", () => context.shell.hook("create.before", async (invocation) => {
      refreshPolicy()
      if (!policy.enabled || !policy.userCommands) return
      if (invocation.command.startsWith(`${quote(executor)} `)) return
      const unavailable = unavailableReason()
      if (unavailable !== undefined) {
        if (policy.mode === "enforce") throw new Error(`${BLOCKED}: ${unavailable}`)
        return
      }
      try {
        const id = `shell_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`
        const file = writeRequest(id, invocation.command, invocation.cwd, invocation.timeout || 0)
        userRequests.add(file)
        invocation.command = executorCommand(executor, file)
      } catch (error) {
        if (policy.mode === "enforce") throw new Error(`${BLOCKED}: ${error instanceof Error ? error.message : String(error)}`)
        void log("warn", `failed to wrap a shell command; running unsandboxed: ${error instanceof Error ? error.message : String(error)}`)
      }
    }))

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
      if (askGuard) await askGuard.dispose()
      if (escapeTool) await escapeTool.dispose()
      for (const callID of [...inFlight.keys()]) cleanup(callID)
      for (const file of userRequests) fs.rmSync(file, { force: true })
      userRequests.clear()
    }
  },
})
