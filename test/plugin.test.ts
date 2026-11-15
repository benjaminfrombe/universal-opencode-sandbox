import { describe, expect, test } from "bun:test"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import plugin from "../src/index"
import { resolveExecutor } from "../src/wire"

// Exercises the plugin hooks end to end without a running OpenCode server: a call
// through execute.before must wrap the command with the executor and write a request
// file; execute.after must restore the command and remove the file.
type Hook = (event: any) => Promise<void>

const start = async (workspace: string, injected?: string) => {
  if (injected) process.env.UNIVERSAL_SANDBOX_CONFIG = injected
  try {
    const hooks: Record<string, Hook> = {}
    const dispose = await plugin.setup({
      location: { directory: workspace },
      tool: {
        hook: async (name: string, callback: Hook) => {
          hooks[name] = callback
          return { dispose: async () => undefined }
        },
      },
    } as never)
    return { hooks, dispose }
  } finally {
    if (injected) delete process.env.UNIVERSAL_SANDBOX_CONFIG
  }
}

const requests = path.join(os.tmpdir(), "universal-opencode-sandbox")
const live = fs.existsSync(resolveExecutor()) ? describe : describe.skip

live("plugin hooks", () => {
  const workspace = fs.mkdtempSync(path.join(os.tmpdir(), "universal-sandbox-plugin-"))

  test("wraps a shell command and cleans up after it", async () => {
    const { hooks, dispose } = await start(workspace)
    fs.rmSync(path.join(requests, "call_1.json"), { force: true })
    const input: { command?: string; timeout?: number } = { command: "echo wrapped", timeout: 1_000 }
    const before = fs.existsSync(requests) ? fs.readdirSync(requests) : []

    await hooks["execute.before"]({ tool: "shell", sessionID: "ses_1", id: "call_1", input })

    expect(input.command).toContain(resolveExecutor())
    const written = fs.readdirSync(requests).filter((item) => !before.includes(item))
    expect(written).toEqual(["call_1.json"])
    const request = JSON.parse(fs.readFileSync(path.join(requests, "call_1.json"), "utf8"))
    expect(request.process.commandLine).toBe("echo wrapped")
    expect(request.process.timeout).toBe(1_000)

    await hooks["execute.after"]({ tool: "shell", sessionID: "ses_1", id: "call_1", input, status: "completed" })
    expect(input.command).toBe("echo wrapped")
    expect(fs.existsSync(path.join(requests, "call_1.json"))).toBe(false)
    await dispose?.()
  })

  test("blocks a tool call that asks to skip the sandbox", async () => {
    const { hooks, dispose } = await start(workspace)
    const input: { command?: string; sandbox?: boolean } = { command: "echo escape", sandbox: false }
    await expect(
      hooks["execute.before"]({ tool: "shell", sessionID: "ses_1", id: "call_2", input }),
    ).rejects.toThrow()
    expect(input.command).toBe("echo escape")
    await dispose?.()
  })

  test("ignores other tools, and a disabled sandbox registers no hooks", async () => {
    const { hooks, dispose } = await start(workspace)
    const input: { command?: string } = { command: "echo read" }
    await hooks["execute.before"]({ tool: "read", sessionID: "ses_1", id: "call_3", input })
    expect(input.command).toBe("echo read")
    await dispose?.()

    const disabled = await start(workspace, JSON.stringify({ enabled: false }))
    expect(Object.keys(disabled.hooks)).toEqual([])
  })

  test("sweeps in-flight request files on unload", async () => {
    const { hooks, dispose } = await start(workspace)
    const input: { command?: string } = { command: "echo sweep" }
    await hooks["execute.before"]({ tool: "shell", sessionID: "ses_1", id: "call_4", input })
    expect(fs.existsSync(path.join(requests, "call_4.json"))).toBe(true)
    await dispose?.()
    expect(fs.existsSync(path.join(requests, "call_4.json"))).toBe(false)
  })

  fs.rmSync(workspace, { recursive: true, force: true })
})
