import { describe, expect, test } from "bun:test"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import { defaultPolicy, expandHome, resolvePolicy, toolBlocked } from "../src/policy"

const home = os.tmpdir()

describe("resolvePolicy", () => {
  test("is enabled with the strictest defaults when no config exists", () => {
    expect(resolvePolicy("/project", {}, "/nonexistent/universal-opencode-sandbox/config.json")).toEqual(defaultPolicy)
  })

  test("defaults to workspace-write with the standard credential list, no config needed", () => {
    const policy = resolvePolicy("/project", {}, "/nonexistent/universal-opencode-sandbox/config.json")
    expect(policy.filesystem.mode).toBe("workspace-write")
    expect(policy.filesystem.deniedPaths).toContain("~/.ssh")
    expect(policy.filesystem.deniedPaths).toContain("~/.local/share/opencode/auth.json")
    // The app-data tools are covered per platform, Windows variants included.
    expect(policy.filesystem.deniedPaths).toContain("~/_netrc")
    expect(policy.filesystem.deniedPaths).toContain("~/AppData/Roaming/gcloud")
    expect(policy.filesystem.deniedPaths).toContain("~/AppData/Roaming/gh/hosts.yml")
  })

  test("an explicit denied_paths list replaces the defaults and later layers only add", () => {
    const global = {
      filesystem: { denied_paths: ["~/.ssh"] },
      projects: { "/project": { filesystem: { denied_paths: ["~/.kube"] } } },
    }
    const file = path.join(home, "universal-opencode-sandbox-test-deniedpaths.json")
    fs.writeFileSync(file, JSON.stringify(global))
    try {
      const policy = resolvePolicy("/project", {}, file)
      // The global list replaced the defaults; the project override extended it.
      expect(policy.filesystem.deniedPaths).toEqual(["~/.ssh", "~/.kube"])
    } finally {
      fs.rmSync(file, { force: true })
    }
  })

  test("reads the global config and keeps security fields strictest across layers", () => {
    const global = {
      mode: "permissive",
      filesystem: { mode: "workspace-write", writable_roots: ["dist"], denied_paths: ["~/.ssh"] },
      network: "allow",
      unsandboxed: "allow",
      projects: { "/project": { mode: "enforce", network: "deny", filesystem: { mode: "read-only" } } },
    }
    const file = path.join(home, "universal-opencode-sandbox-test-global.json")
    fs.writeFileSync(file, JSON.stringify(global))
    try {
      const policy = resolvePolicy("/project", { UNIVERSAL_SANDBOX_CONFIG: JSON.stringify({ network: "deny" }) }, file)
      // The project override tightened mode and network back; roots and denied paths accumulate.
      expect(policy.mode).toBe("enforce")
      expect(policy.network).toBe("deny")
      expect(policy.filesystem.mode).toBe("read-only")
      expect(policy.filesystem.writableRoots).toEqual(["dist"])
      // Denied paths stay as written; the wire request expands "~" per command.
      expect(policy.filesystem.deniedPaths).toEqual(["~/.ssh"])
    } finally {
      fs.rmSync(file, { force: true })
    }
  })

  test("a malformed injected config never disables the sandbox", () => {
    const policy = resolvePolicy("/project", { UNIVERSAL_SANDBOX_CONFIG: "{not json" })
    expect(policy.enabled).toBe(true)
  })

  test("any layer can disable, and per-project overrides match by absolute path only", () => {
    const global = { enabled: false, projects: { "/other": { enabled: true } } }
    const file = path.join(home, "universal-opencode-sandbox-test-disabled.json")
    fs.writeFileSync(file, JSON.stringify(global))
    try {
      expect(resolvePolicy("/project", {}, file).enabled).toBe(false)
      // The override for a different directory does not leak into this one.
      expect(resolvePolicy("/other", {}, file).enabled).toBe(false)
    } finally {
      fs.rmSync(file, { force: true })
    }
  })

  test("blocked tools accumulate across layers and a layer can never unblock", () => {
    const global = { blocked_tools: ["paseo_create_terminal"] }
    const file = path.join(home, "universal-opencode-sandbox-test-blocked.json")
    fs.writeFileSync(file, JSON.stringify(global))
    try {
      const policy = resolvePolicy(
        "/project",
        { UNIVERSAL_SANDBOX_CONFIG: JSON.stringify({ blocked_tools: ["paseo_send_terminal_keys"] }) },
        file,
      )
      expect(policy.blockedTools).toEqual(["paseo_create_terminal", "paseo_send_terminal_keys"])
    } finally {
      fs.rmSync(file, { force: true })
    }
  })
})

describe("toolBlocked", () => {
  const patterns = ["paseo_create_terminal", "paseo_send_*", "exact"]

  test("matches exact names and wildcards, and nothing else", () => {
    expect(toolBlocked("paseo_create_terminal", patterns)).toBe(true)
    expect(toolBlocked("paseo_send_terminal_keys", patterns)).toBe(true)
    expect(toolBlocked("exact", patterns)).toBe(true)
    expect(toolBlocked("paseo_capture_terminal", patterns)).toBe(false)
    expect(toolBlocked("paseo_sendterminal", patterns)).toBe(false)
    expect(toolBlocked("shell", [])).toBe(false)
  })

  test("treats pattern characters in a tool name literally", () => {
    expect(toolBlocked("a.b", ["a*b"])).toBe(true)
    expect(toolBlocked("a.b", ["a.b"])).toBe(true)
    expect(toolBlocked("axb", ["a.b"])).toBe(false)
  })
})

describe("expandHome", () => {
  test("expands a leading tilde", () => {
    expect(expandHome("~", home)).toBe(home)
    expect(expandHome("~/.ssh", home)).toBe(path.join(home, ".ssh"))
    expect(expandHome("/abs", home)).toBe("/abs")
  })
})
