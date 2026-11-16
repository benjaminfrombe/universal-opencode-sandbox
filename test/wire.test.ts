import { describe, expect, test } from "bun:test"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import { defaultPolicy } from "../src/policy"
import { PROTECTED, quote, resolveExecutor, unsupportedNetwork, wireRequest, type WireInput } from "../src/wire"

// The wire request resolves symlinks (macOS /var -> /private/var), so expectations use real paths.
const tmp = fs.realpathSync(os.tmpdir())

const workspace = "/project"
const input = (overrides: Partial<WireInput> = {}): WireInput => ({
  command: "echo hi",
  workspace,
  cwd: workspace,
  timeout: 5_000,
  policy: defaultPolicy,
  ...overrides,
})

describe("wireRequest", () => {
  test("read-only keeps the workspace read-only and denies the network", () => {
    const request = wireRequest(
      input({ policy: { ...defaultPolicy, filesystem: { mode: "read-only", writableRoots: [], deniedPaths: [] } } }),
      "darwin",
    )
    expect(request.containment).toBe("seatbelt")
    expect(request.seatbelt).toEqual({})
    expect(request.filesystem).toEqual({ readwritePaths: [], readonlyPaths: [workspace], deniedPaths: [] })
    expect(request.network).toEqual({ egress: { default: "deny" }, ingress: { default: "deny", hostLoopback: "deny" } })
    expect(request.process.commandLine).toBe("echo hi")
    expect(request.process.timeout).toBe(5_000)
    expect(request.process.cwd).toBe(workspace)
    expect(request.lifecycle).toEqual({ destroyOnExit: true, preservePolicy: false })
  })

  test("workspace-write carves protected paths read-only on macOS, including missing ones", () => {
    const request = wireRequest(
      input({ policy: { ...defaultPolicy, filesystem: { mode: "workspace-write", writableRoots: [], deniedPaths: [] } } }),
      "darwin",
    )
    expect(request.filesystem).toEqual({
      readwritePaths: [workspace, tmp],
      readonlyPaths: PROTECTED.map((item) => path.join(workspace, item)),
      deniedPaths: [],
    })
  })

  test("workspace-write carves out only existing protected paths on Linux", () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "universal-sandbox-test-"))
    try {
      fs.mkdirSync(path.join(directory, ".claude"))
      const request = wireRequest(
        input({
          workspace: directory,
          cwd: directory,
          policy: {
            ...defaultPolicy,
            filesystem: { mode: "workspace-write", writableRoots: [], deniedPaths: [path.join(directory, "missing-secret")] },
          },
        }),
        "linux",
      )
      expect(request.containment).toBe("bubblewrap")
      expect(request.filesystem.readonlyPaths).toEqual([path.join(fs.realpathSync(directory), ".claude")])
      // A missing denied path is dropped on Linux: the backend would create it as a
      // stray directory on the host (microsoft/mxc#1780).
      expect(request.filesystem.deniedPaths).toEqual([])
    } finally {
      fs.rmSync(directory, { recursive: true, force: true })
    }
  })

  test("workspace-write denies protected paths outright on Windows", () => {
    const request = wireRequest(
      input({
        policy: {
          ...defaultPolicy,
          network: "allow",
          filesystem: { mode: "workspace-write", writableRoots: [], deniedPaths: ["~/.ssh"] },
        },
      }),
      "win32",
    )
    expect(request.containment).toBe("processcontainer")
    expect(request.filesystem).toEqual({
      readwritePaths: [workspace, tmp],
      readonlyPaths: [],
      deniedPaths: [...PROTECTED.map((item) => path.join(workspace, item)), path.join(os.homedir(), ".ssh")],
    })
    expect(request.processContainer?.capabilities).toEqual(["internetClient"])
    expect(request.network).toEqual({ egress: { default: "allow" } })
  })
})

describe("wireRequest symlinked workspace and guarded paths", () => {
  const writeMode = { ...defaultPolicy, filesystem: { mode: "workspace-write" as const, writableRoots: [], deniedPaths: [] } }
  const readMode = { ...defaultPolicy, filesystem: { mode: "read-only" as const, writableRoots: [], deniedPaths: [] } }

  test("read-only mode emits the symlink-resolved workspace", () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "universal-sandbox-test-"))
    try {
      const target = path.join(directory, "target")
      const link = path.join(directory, "link")
      fs.mkdirSync(target)
      fs.symlinkSync(target, link)
      const request = wireRequest(input({ workspace: link, cwd: link, policy: readMode }), "darwin")
      expect(request.filesystem.readonlyPaths).toEqual([fs.realpathSync(target)])
    } finally {
      fs.rmSync(directory, { recursive: true, force: true })
    }
  })

  test("guarded paths are read-only on macOS, existing or not, without duplicates", () => {
    const request = wireRequest(
      input({ policy: writeMode, guarded: ["/guard/config", "/guard/config", path.join(workspace, ".claude")] }),
      "darwin",
    )
    expect(request.filesystem.readonlyPaths).toEqual([
      ...PROTECTED.map((item) => path.join(workspace, item)),
      "/guard/config",
    ])
  })

  test("guarded paths are read-only on Linux only when they exist", () => {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "universal-sandbox-test-"))
    try {
      const present = path.join(directory, "present")
      fs.mkdirSync(present)
      const request = wireRequest(
        input({ workspace: directory, cwd: directory, policy: writeMode, guarded: [present, path.join(directory, "missing")] }),
        "linux",
      )
      expect(request.filesystem.readonlyPaths).toEqual([fs.realpathSync(present)])
    } finally {
      fs.rmSync(directory, { recursive: true, force: true })
    }
  })

  test("guarded paths are ignored on Windows", () => {
    const request = wireRequest(input({ policy: writeMode, guarded: ["/guard/config"] }), "win32")
    expect(request.filesystem.readonlyPaths).toEqual([])
    expect(request.filesystem.deniedPaths).not.toContain("/guard/config")
  })
})

describe("resolveExecutor", () => {
  test("resolves an existing executor on this platform", () => {
    expect(fs.existsSync(resolveExecutor())).toBe(true)
  })

  test("returns a reason string for an unsupported platform instead of throwing", () => {
    const result = resolveExecutor("freebsd")
    expect(fs.existsSync(result)).toBe(false)
    expect(result).toContain("freebsd")
  })
})

describe("quote", () => {
  test("quotes POSIX arguments and leaves plain Windows tokens alone", () => {
    expect(quote("echo 'hi'", "darwin")).toBe(`'echo '\\''hi'\\'''`)
    expect(quote("/bin/sh", "darwin")).toBe(`'/bin/sh'`)
    expect(quote("/c", "win32")).toBe("/c")
    expect(quote('say "hi" there\\', "win32")).toBe(`"say \\"hi\\" there\\\\"`)
  })
})

describe("unsupportedNetwork", () => {
  test("flags a network-deny policy the Windows backend cannot enforce", () => {
    expect(unsupportedNetwork("win32", "deny")).toBe(true)
    expect(unsupportedNetwork("win32", "allow")).toBe(false)
    expect(unsupportedNetwork("darwin", "deny")).toBe(false)
    expect(unsupportedNetwork("linux", "deny")).toBe(false)
  })
})
