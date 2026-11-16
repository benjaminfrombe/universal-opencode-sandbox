import { describe, expect, test } from "bun:test"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import { shellInvocation, unsandboxedShellTool } from "../src/unsandboxed"

const run = async (workspace: string, input: Record<string, unknown>) => {
  const tool = unsandboxedShellTool(workspace)
  return (await tool.execute(input, { sessionID: "s" })) as {
    content: string
    metadata: { exitCode: number | null; timedOut: boolean }
  }
}

const alive = (pid: number) => {
  try {
    process.kill(pid, 0)
    return true
  } catch {
    return false
  }
}

describe("shellInvocation", () => {
  test("uses SHELL with -c on POSIX, falling back to /bin/sh", () => {
    for (const platform of ["linux", "darwin"]) {
      expect(shellInvocation("echo hi", platform, { SHELL: "/bin/zsh" })).toEqual({
        file: "/bin/zsh",
        args: ["-c", "echo hi"],
        options: {},
      })
      expect(shellInvocation("echo hi", platform, {}).file).toBe("/bin/sh")
    }
  })

  test("uses ComSpec with /d /s /c and verbatim arguments on win32", () => {
    expect(shellInvocation("echo hi", "win32", { ComSpec: "C:\\Windows\\System32\\cmd.exe" })).toEqual({
      file: "C:\\Windows\\System32\\cmd.exe",
      args: ["/d", "/s", "/c", '"echo hi"'],
      options: { windowsVerbatimArguments: true },
    })
    expect(shellInvocation("dir", "win32", {}).file).toBe("cmd.exe")
  })
})

describe("shell_escalated execution", () => {
  test("returns the exit code and output", async () => {
    const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "unsandboxed-")))
    const result = await run(dir, { command: "echo out; echo err >&2; exit 3" })
    expect(result.metadata).toEqual({ exitCode: 3, timedOut: false })
    expect(result.content).toContain("exit code 3")
    expect(result.content).toContain("out")
    expect(result.content).toContain("err")
  })

  test("resolves a relative workdir against the workspace", async () => {
    const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "unsandboxed-")))
    fs.mkdirSync(path.join(dir, "sub"))
    const result = await run(dir, { command: "pwd", workdir: "sub" })
    expect(result.content).toContain(path.join(dir, "sub"))
  })

  test("a timeout kills the whole process tree and still resolves", async () => {
    const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "unsandboxed-")))
    const started = Date.now()
    // The background sleep inherits the pipes; killing only the shell would leave
    // them open and the call would hang for the full 30 seconds.
    const result = await run(dir, { command: "sleep 30 & echo $!; sleep 30", timeout: 300 })
    expect(Date.now() - started).toBeLessThan(3_000)
    expect(result.metadata.timedOut).toBe(true)
    const pid = Number(/^stdout:\n(\d+)/.exec(result.content.split("\n\n").slice(1).join("\n\n"))?.[1])
    expect(pid).toBeGreaterThan(0)
    // Give the kernel a moment to reap the killed group.
    await new Promise((r) => setTimeout(r, 200))
    expect(alive(pid)).toBe(false)
  })
})
