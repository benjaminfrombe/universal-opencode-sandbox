import { describe, expect, test } from "bun:test"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import { defaultPolicy, expandHome, resolvePolicy } from "../src/policy"

const home = os.tmpdir()

describe("resolvePolicy", () => {
  test("is enabled with the strictest defaults when no config exists", () => {
    expect(resolvePolicy("/project", {}, "/nonexistent/universal-opencode-sandbox/config.json")).toEqual(defaultPolicy)
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
})

describe("expandHome", () => {
  test("expands a leading tilde", () => {
    expect(expandHome("~", home)).toBe(home)
    expect(expandHome("~/.ssh", home)).toBe(path.join(home, ".ssh"))
    expect(expandHome("/abs", home)).toBe("/abs")
  })
})
