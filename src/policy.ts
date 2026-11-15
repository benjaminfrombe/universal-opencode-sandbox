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
  readonly unsandboxed: "deny" | "ask" | "allow"
  /** Also sandbox user "!" commands and plugin shells, not just agent shell tool calls. */
  readonly userCommands: boolean
  /** Tool names the agent may not call at all, with "*" as a wildcard ("paseo_*"). */
  readonly blockedTools: string[]
  /** Commands pre-approved to run unsandboxed without a prompt, with "*" wildcards. */
  readonly unsandboxedAllow: string[]
}

interface RawConfig {
  enabled?: unknown
  mode?: unknown
  filesystem?: { mode?: unknown; writable_roots?: unknown; denied_paths?: unknown }
  network?: unknown
  unsandboxed?: unknown
  /** Also sandbox user "!" commands and plugin shells, not just agent shell tool calls. */
  sandbox_user_commands?: unknown
  /** Tool names the agent may not call at all, with "*" as a wildcard ("paseo_*"). */
  blocked_tools?: unknown
  /** Commands pre-approved to run unsandboxed without a prompt, with "*" wildcards. */
  unsandboxed_allow?: unknown
  projects?: Record<string, RawConfig>
}

// Only fields a config layer set explicitly; unset fields fall back to the strictest
// default at the end, so a default never pins over an explicit looser value.
interface Merged {
  enabled?: boolean
  mode?: "enforce" | "permissive"
  filesystemMode?: "read-only" | "workspace-write"
  network?: "deny" | "allow"
  unsandboxed?: "deny" | "ask" | "allow"
  userCommands?: boolean
  blockedTools: string[]
  unsandboxedAllow: string[]
  writableRoots: string[]
  deniedPaths: string[]
  /** True once any layer set denied_paths: the user's list then replaces the defaults. */
  deniedPathsExplicit?: boolean
}

// The real home directory from the system password database, not the HOME env var:
// Paseo and some sandboxes set HOME to the workspace, which would break config lookup.
const realHome = () => os.userInfo().homedir

/**
 * Credential stores a sandboxed command can neither read nor write by default: the
 * classic identity directories plus the plaintext credential files of the major
 * CLIs, cloud SDKs and agent tools. A stolen long-lived credential cannot be undone
 * by a restart, so reading is denied even though the network usually is too: a secret
 * read once can be copied into the workspace and walk out through a commit. Setting
 * denied_paths in the config replaces this list; the entries are then the user's.
 *
 * Paths that live in a platform's app-data directory are listed per platform: the
 * Windows variants are nonexistent (and therefore no-ops) on macOS and Linux, and
 * vice versa. Entries under the profile directory itself (~/.ssh and friends) are
 * identical everywhere.
 */
export const defaultDeniedPaths = [
  "~/.ssh",
  "~/.aws",
  "~/.gnupg",
  "~/.netrc",
  "~/_netrc",
  "~/.kube",
  "~/.azure",
  "~/.config/gcloud",
  "~/AppData/Roaming/gcloud",
  "~/.npmrc",
  "~/.pypirc",
  "~/.cargo/credentials",
  "~/.docker/config.json",
  "~/.config/gh/hosts.yml",
  "~/Library/Application Support/gh/hosts.yml",
  "~/AppData/Roaming/gh/hosts.yml",
  "~/.local/share/opencode/auth.json",
  "~/.claude/.credentials.json",
  "~/.codex/auth.json",
]

const configDirectory = () =>
  path.join(process.env.XDG_CONFIG_HOME ?? path.join(realHome(), ".config"), "universal-opencode-sandbox")

const configPath = () => path.join(configDirectory(), "config.json")

export const defaultPolicy: Policy = {
  enabled: true,
  mode: "enforce",
  // workspace-write out of the box: read-only would break git and builds on first
  // use. Everything outside the workspace, the temp directory and writable_roots
  // stays write-denied, and the network stays denied.
  filesystem: { mode: "workspace-write", writableRoots: [], deniedPaths: defaultDeniedPaths },
  network: "deny",
  unsandboxed: "deny",
  userCommands: false,
  blockedTools: [],
  unsandboxedAllow: [],
}

/**
 * Resolves the sandbox policy for a workspace: the global config file, tightened by the
 * matching per-project override, tightened by UNIVERSAL_SANDBOX_CONFIG. Security fields
 * only ever get stricter across explicit values; roots and blocked tools accumulate.
 * Denied paths start from defaultDeniedPaths and are replaced wholesale by the first
 * layer that sets denied_paths, then extended by later layers.
 */
export function resolvePolicy(
  workspace: string,
  environment: NodeJS.ProcessEnv = process.env,
  globalFile: string = configPath(),
): Policy {
  let merged: Merged = { writableRoots: [], deniedPaths: [], blockedTools: [], unsandboxedAllow: [] }
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
      mode: merged.filesystemMode ?? "workspace-write",
      writableRoots: [...new Set(merged.writableRoots)],
      deniedPaths: merged.deniedPathsExplicit ? [...new Set(merged.deniedPaths)] : defaultDeniedPaths,
    },
    network: merged.network ?? "deny",
    unsandboxed: merged.unsandboxed ?? "deny",
    userCommands: merged.userCommands ?? false,
    blockedTools: [...new Set(merged.blockedTools)],
    unsandboxedAllow: [...new Set(merged.unsandboxedAllow)],
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
    // The first layer to set denied_paths replaces the defaults; later layers only
    // add. All layers here are user-owned, so the user's own list is the authority.
    const items = raw.filesystem.denied_paths.filter((item): item is string => typeof item === "string")
    merged.deniedPaths = merged.deniedPathsExplicit ? [...merged.deniedPaths, ...items] : items
    merged.deniedPathsExplicit = true
  }
  if (Array.isArray(raw.blocked_tools)) {
    for (const item of raw.blocked_tools) if (typeof item === "string") merged.blockedTools.push(item)
  }
  if (Array.isArray(raw.unsandboxed_allow)) {
    for (const item of raw.unsandboxed_allow) if (typeof item === "string") merged.unsandboxedAllow.push(item)
  }
  return {
    // Any layer can turn the sandbox off; all layers here are user-owned, so false wins.
    enabled: raw.enabled === undefined ? merged.enabled : raw.enabled === false ? false : merged.enabled === false ? false : true,
    mode: strictest(merged.mode, raw.mode, "enforce", "permissive"),
    filesystemMode: strictest(merged.filesystemMode, raw.filesystem?.mode, "read-only", "workspace-write"),
    network: strictest(merged.network, raw.network, "deny", "allow"),
    unsandboxed: strictestUnsandboxed(merged.unsandboxed, raw.unsandboxed),
    userCommands: raw.sandbox_user_commands === true || merged.userCommands === true,
    blockedTools: merged.blockedTools,
    unsandboxedAllow: merged.unsandboxedAllow,
    writableRoots: merged.writableRoots,
    deniedPaths: merged.deniedPaths,
    deniedPathsExplicit: merged.deniedPathsExplicit,
  }
}

// Keeps the current value when a layer does not mention the field, otherwise the
// strictest of the explicit values: any layer choosing `strict` wins for good.
function strictest<T extends string>(current: T | undefined, incoming: unknown, strict: T, loose: T): T | undefined {
  if (current === strict || incoming === strict) return strict
  if (incoming === loose) return loose
  return current
}

// The strictest of the explicit unsandboxed choices across layers: deny beats ask
// beats allow, and a layer that does not mention the field leaves it untouched.
function strictestUnsandboxed(
  current: "deny" | "ask" | "allow" | undefined,
  incoming: unknown,
): "deny" | "ask" | "allow" | undefined {
  if (incoming !== "deny" && incoming !== "ask" && incoming !== "allow") return current
  if (current === "deny" || incoming === "deny") return "deny"
  if (current === "ask" || incoming === "ask") return "ask"
  return "allow"
}

// Expands a leading "~" against the home directory, like a shell would.
export function expandHome(item: string, home = os.homedir()) {
  return item === "~" ? home : item.startsWith("~/") ? path.join(home, item.slice(2)) : item
}

/**
 * Matches a value against a pattern the way OpenCode's own permission rules do:
 * "*" matches any sequence, "?" one character, a trailing " *" also matches the bare
 * prefix, and backslashes normalize to forward slashes.
 */
export function matchesWildcard(value: string, pattern: string): boolean {
  const normalized = value.replaceAll("\\", "/")
  let escaped = pattern
    .replaceAll("\\", "/")
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*")
    .replace(/\?/g, ".")
  if (escaped.endsWith(" .*")) escaped = escaped.slice(0, -3) + "( .*)?"
  return new RegExp(`^${escaped}$`, "s").test(normalized)
}

/** True when the tool name matches a blocked pattern; "*" in a pattern matches any sequence. */
export function toolBlocked(tool: string, patterns: readonly string[]): boolean {
  return patterns.some((pattern) => matchesWildcard(tool, pattern))
}
