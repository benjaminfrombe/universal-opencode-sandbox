import { describe, expect, test } from "bun:test"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import { defaultPolicy } from "../src/policy"
import { PROTECTED, quote, wireRequest, type WireInput } from "../src/wire"

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
    const request = wireRequest(input(), "darwin")
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

describe("quote", () => {
  test("quotes POSIX arguments and leaves plain Windows tokens alone", () => {
    expect(quote("echo 'hi'", "darwin")).toBe(`'echo '\\''hi'\\'''`)
    expect(quote("/bin/sh", "darwin")).toBe(`'/bin/sh'`)
    expect(quote("/c", "win32")).toBe("/c")
    expect(quote('say "hi" there\\', "win32")).toBe(`"say \\"hi\\" there\\\\"`)
  })
})
