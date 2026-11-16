// Builds the MXC 1.0.0 wire request the bundled executor binaries consume, and resolves
// the executor for the current platform. Verified against mxc-exec-mac (Seatbelt),
// lxc-exec (bubblewrap) and wxc-exec.exe (ProcessContainer).

import { randomBytes } from "node:crypto"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { expandHome, type Policy } from "./policy.js"

/** Workspace paths a sandboxed command must never plant or overwrite. */
export const PROTECTED = ["opencode.json", "opencode.jsonc", ".opencode", ".claude", ".agents"] as const

export interface WireRequest {
  version: "1.0.0"
  containerId: string
  containment: "seatbelt" | "bubblewrap" | "processcontainer"
  seatbelt?: Record<string, never>
  processContainer?: { capabilities: string[]; ui: Record<string, unknown>; filesystem: undefined; network: undefined }
  lifecycle: { destroyOnExit: boolean; preservePolicy: boolean }
  process: {
    commandLine: string
    timeout: number
    cwd?: string
    inheritDefaultEnv?: boolean
  }
  filesystem: { readwritePaths: string[]; readonlyPaths: string[]; deniedPaths: string[] }
  network?: { egress?: unknown; ingress?: unknown }
}

export interface WireInput {
  readonly command: string
  readonly workspace: string
  readonly cwd: string
  readonly timeout: number
  readonly policy: Policy
  readonly tmpRoots?: string[]
  /** Extra KEY=VALUE environment entries layered over the backend default (used by the sandboxed-shell CLI). */
  readonly environment?: string[]
  /** Absolute paths the sandboxed command must never write, even when a writable root covers them (the sandbox's own config and request directories). */
  readonly guarded?: string[]
}

/** Maps a policy and one command onto the wire request, platform-aware. */
export function wireRequest(input: WireInput, platform: NodeJS.Platform = process.platform): WireRequest {
  // Seatbelt and bwrap match real paths, and the workspace can sit behind a symlinked
  // ancestor (/tmp -> /private/tmp on macOS), so every path is resolved first.
  const workspace = real(input.workspace)
  const cwd = real(input.cwd)
  const writable = [
    workspace,
    ...(input.tmpRoots ?? [os.tmpdir()]).map(real),
    ...input.policy.filesystem.writableRoots.map((root) => real(expandHome(root))),
  ]
  const protectedPaths = PROTECTED.map((item) => path.join(workspace, item))
  const deniedPaths = input.policy.filesystem.deniedPaths.map((item) => real(expandHome(item)))
  const guarded = (input.guarded ?? []).map(real)

  let filesystem: WireRequest["filesystem"]
  if (input.policy.filesystem.mode !== "workspace-write") {
    filesystem = { readwritePaths: [], readonlyPaths: [workspace], deniedPaths: existing(deniedPaths, platform) }
  } else if (platform === "win32") {
    // ProcessContainer does not enforce read-only carve-outs under writable roots, so
    // protected paths are denied outright; opencode's own read tool still reads them.
    // Guarded paths are ignored here: they cannot be carved out, and denying them would
    // also stop the executor from reading its own request file.
    // ProcessContainer aborts the launch with ERROR_PATH_NOT_FOUND when a denied path
    // sits under a parent directory that does not exist (verified against MXC 1.1.0 on
    // Windows 11 ARM64: a missing file or a path with a missing parent kills every
    // command), so such entries are dropped, matching the Linux behavior.
    filesystem = {
      readwritePaths: writable,
      readonlyPaths: [],
      deniedPaths: [...protectedPaths, ...deniedPaths].filter((item) => exists(path.dirname(item))),
    }
  } else if (platform === "linux") {
    // bwrap cannot bind a read-only source that does not exist (the launch fails), and
    // denying a missing path makes the backend create it as a stray directory on the
    // host (microsoft/mxc#1780), so only paths that exist are protected on Linux.
    filesystem = {
      readwritePaths: writable,
      readonlyPaths: unique([...protectedPaths, ...guarded].filter((item) => exists(item))),
      deniedPaths: existing(deniedPaths, platform),
    }
  } else {
    // Seatbelt enforces read-only carve-outs for existing and not-yet-existing paths.
    filesystem = { readwritePaths: writable, readonlyPaths: unique([...protectedPaths, ...guarded]), deniedPaths }
  }

  const request: WireRequest = {
    version: "1.0.0",
    containerId: randomBytes(16).toString("hex"),
    containment: platform === "darwin" ? "seatbelt" : platform === "win32" ? "processcontainer" : "bubblewrap",
    ...(platform === "darwin" ? { seatbelt: {} } : {}),
    ...(platform === "win32"
      ? {
          processContainer: {
            capabilities: input.policy.network === "allow" ? ["internetClient"] : [],
            ui: { isolation: "container", desktopSystemControl: false, systemSettings: "none", ime: false },
            filesystem: undefined,
            network: undefined,
          },
        }
      : {}),
    lifecycle: { destroyOnExit: true, preservePolicy: false },
    process: {
      // ProcessContainer spawns the command line directly, so shell builtins (echo,
      // dir, type) cannot be resolved and the launch fails with ERROR_PATH_NOT_FOUND
      // (verified against MXC 1.1.0 on Windows 11 ARM64); commands are routed through
      // cmd the way Windows shell tools always run them. /d skips AutoRun, /s makes
      // the outer quotes of the wrapped command strip reliably.
      commandLine: platform === "win32" ? `cmd.exe /d /s /c ${quote(input.command, platform)}` : input.command,
      timeout: input.timeout,
      cwd,
      inheritDefaultEnv: true,
      ...(input.environment === undefined ? {} : { env: input.environment }),
    },
    filesystem,
    ...(input.policy.network === "deny"
      ? { network: { egress: { default: "deny" }, ingress: { default: "deny", hostLoopback: "deny" } } }
      : { network: { egress: { default: "allow" } } }),
  }
  return request
}

function unique(paths: string[]) {
  return [...new Set(paths)]
}

function exists(item: string) {
  try {
    fs.statSync(item)
    return true
  } catch {
    return false
  }
}

// Resolves symlinks so OS sandboxes that match real paths (Seatbelt) honor the policy.
function real(item: string) {
  try {
    return fs.realpathSync(item)
  } catch {
    return item
  }
}

// On Linux the deny fallback for a missing path creates it as a stray host directory,
// so denied paths are also filtered to the ones that exist there.
function existing(paths: string[], platform: NodeJS.Platform) {
  return platform === "linux" ? paths.filter(exists) : paths
}

/**
 * A network-deny policy the Windows backend accepts but does not enforce (verified
 * against Windows 11 and MXC 1.1.0: direct egress still works). Callers fail closed
 * instead of running a command with network access the user denied.
 */
export function unsupportedNetwork(platform: NodeJS.Platform, network: "deny" | "allow") {
  return platform === "win32" && network === "deny"
}

/** Resolves the bundled MXC executor binary for this platform and architecture. */
export function resolveExecutor(platform: NodeJS.Platform = process.platform, arch: string = process.arch): string {
  const name =
    platform === "darwin" ? "mxc-exec-mac" : platform === "win32" ? "wxc-exec.exe" : platform === "linux" ? "lxc-exec" : undefined
  if (!name) return `no MXC executor exists for ${platform}`
  // A missing or unresolvable SDK must come back as a reason, never as a throw: a host
  // that survives a failed plugin setup would otherwise run commands unsandboxed.
  let sdk: string
  try {
    sdk = path.dirname(fileURLToPath(import.meta.resolve("@microsoft/mxc-sdk/package.json")))
  } catch (error) {
    return `the @microsoft/mxc-sdk package could not be resolved: ${error instanceof Error ? error.message : String(error)}`
  }
  const executor = path.join(sdk, "bin", arch === "arm64" ? "arm64" : "x64", name)
  if (!fs.existsSync(executor)) {
    // MXC 1.1.0 ships no darwin-x64 runtime: Intel Macs fail closed until it does.
    return platform === "darwin" && arch === "x64"
      ? "the installed @microsoft/mxc-sdk ships no Intel macOS executor yet"
      : `the MXC executor is missing from the @microsoft/mxc-sdk package: ${executor}`
  }
  return executor
}

/** Quotes one argument for the platform's command-line parser. */
export function quote(value: string, platform: NodeJS.Platform = process.platform) {
  if (platform === "win32") return windowsArgument(value)
  return `'${value.replaceAll("'", `'\\''`)}'`
}

function windowsArgument(value: string) {
  if (!/[\s"]/.test(value)) return value
  let quoted = '"'
  let backslashes = 0
  for (const character of value) {
    if (character === "\\") {
      backslashes++
      continue
    }
    if (character === '"') {
      quoted += "\\".repeat(backslashes * 2 + 1) + '"'
      backslashes = 0
      continue
    }
    quoted += "\\".repeat(backslashes) + character
    backslashes = 0
  }
  return quoted + "\\".repeat(backslashes * 2) + '"'
}
