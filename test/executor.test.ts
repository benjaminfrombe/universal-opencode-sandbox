import { afterAll, describe, expect, test } from "bun:test"
import { spawnSync } from "node:child_process"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import { defaultPolicy } from "../src/policy"
import { resolveExecutor, wireRequest } from "../src/wire"

// Live enforcement tests: they run only where the bundled MXC executor exists (Seatbelt
// on macOS, bubblewrap on Linux, ProcessContainer on Windows) and prove the wire request
// the plugin writes is enforced by the real OS backend.
const executor = resolveExecutor()
const live = fs.existsSync(executor) ? describe : describe.skip

const run = (command: string, workspace: string) => {
  const request = wireRequest(
    {
      command,
      workspace,
      cwd: workspace,
      timeout: 15_000,
      policy: { ...defaultPolicy, filesystem: { mode: "workspace-write", writableRoots: [], deniedPaths: [] } },
    },
  )
  const file = path.join(os.tmpdir(), `universal-sandbox-live-${process.pid}.json`)
  fs.writeFileSync(file, JSON.stringify(request), { mode: 0o600 })
  const result = spawnSync(executor, [file], { encoding: "utf8", timeout: 20_000 })
  fs.rmSync(file, { force: true })
  return result
}

live("executor enforcement", () => {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "universal-sandbox-live-"))
  const canary = path.join(os.homedir(), `.universal-sandbox-live-${process.pid}.txt`)

  test("streams output and passes the exit code through", () => {
    const result = run(`sh -c 'printf out; printf err >&2; exit 7'`, workspace)
    expect(result.status).toBe(7)
    expect(result.stdout).toBe("out")
    expect(result.stderr).toBe("err")
  })

  test("allows writes inside the workspace and denies writes outside it", () => {
    const inside = run(`sh -c 'echo hi > ${path.join(workspace, "inside.txt")}'`, workspace)
    expect(inside.status).toBe(0)
    expect(fs.readFileSync(path.join(workspace, "inside.txt"), "utf8")).toBe("hi\n")

    const outside = run(`sh -c 'echo pwned > ${canary}'`, workspace)
    expect(outside.status).not.toBe(0)
    expect(fs.existsSync(canary)).toBe(false)
  })

  test("denies planting a protected config file outside the known Linux gap", () => {
    const planted = run(`sh -c 'echo evil > ${path.join(workspace, "opencode.json")}'`, workspace)
    if (process.platform === "linux") {
      // Known gap: bwrap cannot protect a path that does not exist yet (microsoft/mxc#1780).
      expect(planted.status).toBe(0)
      return
    }
    expect(planted.status).not.toBe(0)
    expect(fs.existsSync(path.join(workspace, "opencode.json"))).toBe(false)
  })

  test("denies network egress", () => {
    const net = run(`sh -c 'command -v curl >/dev/null || exit 42; curl -m 3 -s https://example.com >/dev/null; echo CURL=$?'`, workspace)
    if (net.status === 42) return
    expect(net.status).toBe(0)
    expect(net.stdout).not.toContain("CURL=0")
  })

  afterAll(() => {
    fs.rmSync(workspace, { recursive: true, force: true })
    fs.rmSync(canary, { force: true })
  })
})
