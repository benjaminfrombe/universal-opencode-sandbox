import { spawn } from "node:child_process"
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

const start = async (
  workspace: string,
  injected?: string,
  options?: {
    assert?: (input: never) => Promise<void>
    sessionPermissions?: { action: string; resource: string; effect: string }[]
  },
) => {
  if (injected) process.env.UNIVERSAL_SANDBOX_CONFIG = injected
  try {
    const hooks: Record<string, Hook> = {}
    const tools: { name: string; execute: (input: unknown, context: { sessionID: string }) => Promise<unknown> }[] = []
    const dispose = await plugin.setup({
      location: { directory: workspace },
      tool: {
        hook: async (name: string, callback: Hook) => {
          hooks[name] = callback
          return { dispose: async () => undefined }
        },
        transform: async (callback: (editor: unknown) => void) => {
          callback({
            add: (tool: { name: string; execute: (input: unknown, context: { sessionID: string }) => Promise<unknown> }) => {
              tools.push(tool)
            },
            list: () => tools,
            get: () => undefined,
            namespace: () => undefined,
            update: () => undefined,
            remove: () => undefined,
          })
          return { dispose: async () => undefined }
        },
      },
      permission: {
        assert: options?.assert ?? (async () => undefined),
        hook: async (name: string, callback: Hook) => {
          hooks[`permission:${name}`] = callback
          return { dispose: async () => undefined }
        },
      },
      session: {
        get: async () => ({
          permissions: options?.sessionPermissions ?? [{ action: "*", resource: "*", effect: "allow" }],
        }),
      },
    } as never)
    return { hooks, tools, dispose }
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

  test("ask mode prompts the user and passes the command through only after approval", async () => {
    const asks: unknown[] = []
    const { hooks, dispose } = await start(workspace, JSON.stringify({ unsandboxed: "ask" }), {
      assert: async (input: never) => {
        asks.push(input)
        const resources = (input as { resources: string[] }).resources
        if (resources[0] === "echo denied") throw new Error("rejected by the user")
      },
    })
    const approved: { command?: string; sandbox?: boolean } = { command: "echo outside", sandbox: false }
    await hooks["execute.before"]({ tool: "shell", sessionID: "ses_1", id: "call_2a", input: approved })
    // The prompt names the exact command under the dedicated "unsandboxed" action.
    expect(asks).toEqual([
      { sessionID: "ses_1", action: "unsandboxed", resources: ["echo outside"], save: ["echo outside"], metadata: { command: "echo outside" } },
    ])
    // An approval leaves the command unwrapped: it runs outside the sandbox.
    expect(approved.command).toBe("echo outside")

    const denied: { command?: string; sandbox?: boolean } = { command: "echo denied", sandbox: false }
    await expect(
      hooks["execute.before"]({ tool: "shell", sessionID: "ses_1", id: "call_2b", input: denied }),
    ).rejects.toThrow("rejected by the user")
    expect(denied.command).toBe("echo denied")
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

  test("deny mode (the default) registers no escape tool, so an agent cannot even ask", async () => {
    const { tools, dispose } = await start(workspace)
    expect(tools).toEqual([])
    await dispose?.()
  })

  test("ask mode registers the escape tool and prompts per command", async () => {
    const asks: unknown[] = []
    const { hooks, tools, dispose } = await start(workspace, JSON.stringify({ unsandboxed: "ask" }), {
      assert: async (input: never) => {
        asks.push(input)
      },
    })
    expect(tools.map((tool) => tool.name)).toEqual(["shell_unsandboxed"])
    const input = { command: "echo outside" }
    await hooks["execute.before"]({ tool: "shell_unsandboxed", sessionID: "ses_1", id: "call_e1", input })
    expect(asks).toEqual([
      { sessionID: "ses_1", action: "unsandboxed", resources: ["echo outside"], save: ["echo outside"], metadata: { command: "echo outside" } },
    ])
    await dispose?.()
  })

  test("the escape tool runs a command and reports the exit code", async () => {
    const { tools, dispose } = await start(workspace, JSON.stringify({ unsandboxed: "allow" }))
    const tool = tools.find((item) => item.name === "shell_unsandboxed")
    const shell = process.env.SHELL
    // POSIX sh everywhere; a sandboxed test run denies nested spawns, so probe first.
    process.env.SHELL = "/bin/sh"
    const canSpawn = await new Promise<boolean>((resolve) => {
      const probe = spawn("/bin/sh", ["-c", "echo ok"])
      probe.on("error", () => resolve(false))
      probe.on("close", () => resolve(true))
    })
    try {
      if (!canSpawn) return
      // The describe-scope workspace is already cleaned up by the time tests run
      // (the other tests only use it as a string), so give the run a real cwd.
      const dir = fs.mkdtempSync(path.join(os.tmpdir(), "universal-sandbox-escape-"))
      const result = (await tool?.execute(
        { command: "echo hello-from-escape", workdir: dir },
        { sessionID: "ses_1" },
      )) as {
        content?: string
      }
      expect(String(result?.content)).toContain("hello-from-escape")
      expect(String(result?.content)).toContain("exit code 0")
    } finally {
      if (shell === undefined) delete process.env.SHELL
      else process.env.SHELL = shell
      await dispose?.()
    }
  })

  test("ask mode forces the prompt when the session auto-allows everything", async () => {
    const { hooks, dispose } = await start(workspace, JSON.stringify({ unsandboxed: "ask" }), {
      sessionPermissions: [{ action: "*", resource: "*", effect: "allow" }],
    })
    const event = {
      sessionID: "ses_1",
      action: "unsandboxed",
      resources: ["echo x"],
      effect: "allow" as string,
      message: undefined as string | undefined,
    }
    await hooks["permission:evaluate"](event)
    expect(event.effect).toBe("ask")
    // The prompt names the command: it is the only thing the user approves.
    expect(event.message).toBe("Run this command outside the sandbox: echo x")
    await dispose?.()
  })

  test("a rule that names the unsandboxed action keeps a pre-approval silent", async () => {
    const { hooks, dispose } = await start(workspace, JSON.stringify({ unsandboxed: "ask" }), {
      sessionPermissions: [{ action: "unsandboxed", resource: "git push *", effect: "allow" }],
    })
    const preapproved = { sessionID: "ses_1", action: "unsandboxed", resources: ["git push origin main"], effect: "allow" as string }
    await hooks["permission:evaluate"](preapproved)
    expect(preapproved.effect).toBe("allow")
    const other = { sessionID: "ses_1", action: "unsandboxed", resources: ["rm -rf /"], effect: "allow" as string }
    await hooks["permission:evaluate"](other)
    expect(other.effect).toBe("ask")
    await dispose?.()
  })

  test("the guard leaves other actions and deny mode alone", async () => {
    const { hooks, dispose } = await start(workspace, JSON.stringify({ unsandboxed: "ask" }))
    const shell = { sessionID: "ses_1", action: "shell", resources: ["echo x"], effect: "allow" as string }
    await hooks["permission:evaluate"](shell)
    expect(shell.effect).toBe("allow")
    await dispose?.()

    const denied = await start(workspace)
    expect(denied.hooks["permission:evaluate"]).toBeUndefined()
    await denied.dispose?.()
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
