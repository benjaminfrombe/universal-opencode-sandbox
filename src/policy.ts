// Policy loading for the universal sandbox. Configuration is read only from sources a
// sandboxed command cannot reach: the plugin's own config directory outside every
// workspace, and an environment variable. OpenCode plugin options are ignored on
// purpose: they can be set from a repository's opencode.json, which is untrusted.

import fs from "node:fs"
import os from "node:os"
import path from "node:path"

export interface Policy {
  readonly enabled: boolean
  /** "enforce" blocks a command when the sandbox cannot run it; "permissive" runs it unsandboxed with a warning. */
  readonly mode: "enforce" | "permissive"
  readonly filesystem: {
    readonly mode: "read-only" | "workspace-write"
    readonly writableRoots: string[]
    /** Paths the sandboxed command can neither read nor write, resolved against the home directory. */
    readonly deniedPaths: string[]
  }
  readonly network: "deny" | "allow"
  /** What happens when a tool call asks to skip the sandbox (shell input "sandbox: false"). */
  readonly unsandboxed: "deny" | "allow"
}

interface RawConfig {
  enabled?: unknown
  mode?: unknown
  filesystem?: { mode?: unknown; writable_roots?: unknown; denied_paths?: unknown }
  network?: unknown
  unsandboxed?: unknown
  projects?: Record<string, RawConfig>
}

// Only fields a config layer set explicitly; unset fields fall back to the strictest
// default at the end, so a default never pins over an explicit looser value.
interface Merged {
  enabled?: boolean
  mode?: "enforce" | "permissive"
  filesystemMode?: "read-only" | "workspace-write"
  network?: "deny" | "allow"
  unsandboxed?: "deny" | "allow"
  writableRoots: string[]
  deniedPaths: string[]
}

const configDirectory = () =>
  path.join(process.env.XDG_CONFIG_HOME ?? path.join(os.homedir(), ".config"), "universal-opencode-sandbox")

const configPath = () => path.join(configDirectory(), "config.json")

export const defaultPolicy: Policy = {
  enabled: true,
  mode: "enforce",
  filesystem: { mode: "read-only", writableRoots: [], deniedPaths: [] },
  network: "deny",
  unsandboxed: "deny",
}

/**
 * Resolves the sandbox policy for a workspace: the global config file, tightened by the
 * matching per-project override, tightened by UNIVERSAL_SANDBOX_CONFIG. Security fields
 * only ever get stricter across explicit values; roots and denied paths accumulate.
 */
export function resolvePolicy(
  workspace: string,
  environment: NodeJS.ProcessEnv = process.env,
  globalFile: string = configPath(),
): Policy {
  let merged: Merged = { writableRoots: [], deniedPaths: [] }
  const global = readConfig(globalFile)
  if (global) merged = tighten(merged, global)
  const project = global?.projects?.[workspace]
  if (project) merged = tighten(merged, project)
  const injected = environment.UNIVERSAL_SANDBOX_CONFIG
  if (injected) {
    try {
      merged = tighten(merged, JSON.parse(injected) as RawConfig)
    } catch {
      // A malformed injected config is ignored rather than disabling the sandbox.
    }
  }
  return {
    enabled: merged.enabled ?? true,
    mode: merged.mode ?? "enforce",
    filesystem: {
      mode: merged.filesystemMode ?? "read-only",
      writableRoots: [...new Set(merged.writableRoots)],
      deniedPaths: [...new Set(merged.deniedPaths)],
    },
    network: merged.network ?? "deny",
    unsandboxed: merged.unsandboxed ?? "deny",
  }
}

function readConfig(file: string): RawConfig | undefined {
  try {
    return JSON.parse(fs.readFileSync(file, "utf8")) as RawConfig
  } catch {
    return undefined
  }
}

// Explicit values only get stricter across layers: any layer choosing the strict value
// wins for good, and a layer that does not mention a field leaves it untouched.
function tighten(merged: Merged, raw: RawConfig): Merged {
  if (Array.isArray(raw.filesystem?.writable_roots)) {
    for (const root of raw.filesystem.writable_roots) if (typeof root === "string") merged.writableRoots.push(root)
  }
  if (Array.isArray(raw.filesystem?.denied_paths)) {
    for (const item of raw.filesystem.denied_paths) if (typeof item === "string") merged.deniedPaths.push(item)
  }
  return {
    // Any layer can turn the sandbox off; all layers here are user-owned, so false wins.
    enabled: raw.enabled === undefined ? merged.enabled : raw.enabled === false ? false : merged.enabled === false ? false : true,
    mode: strictest(merged.mode, raw.mode, "enforce", "permissive"),
    filesystemMode: strictest(merged.filesystemMode, raw.filesystem?.mode, "read-only", "workspace-write"),
    network: strictest(merged.network, raw.network, "deny", "allow"),
    unsandboxed: strictest(merged.unsandboxed, raw.unsandboxed, "deny", "allow"),
    writableRoots: merged.writableRoots,
    deniedPaths: merged.deniedPaths,
  }
}

// Keeps the current value when a layer does not mention the field, otherwise the
// strictest of the explicit values: any layer choosing `strict` wins for good.
function strictest<T extends string>(current: T | undefined, incoming: unknown, strict: T, loose: T): T | undefined {
  if (current === strict || incoming === strict) return strict
  if (incoming === loose) return loose
  return current
}

// Expands a leading "~" against the home directory, like a shell would.
export function expandHome(item: string, home = os.homedir()) {
  return item === "~" ? home : item.startsWith("~/") ? path.join(home, item.slice(2)) : item
}
