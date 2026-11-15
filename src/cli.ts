#!/usr/bin/env node
// sandboxed-shell: an interactive terminal confined by the same MXC sandbox policy
// as the universal-opencode-sandbox plugin. Gives you a "safe terminal" next to a
// normal "admin terminal": everything typed inside runs under Seatbelt (macOS),
// bubblewrap (Linux) or ProcessContainer (Windows), with the filesystem and network
// policy from ~/.config/universal-opencode-sandbox/config.json.
//
// Fails closed: if the sandbox cannot run, the shell is never started unsandboxed.

import { spawn } from "node:child_process"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import { resolvePolicy } from "./policy.js"
import { quote, resolveExecutor, unsupportedNetwork, wireRequest } from "./wire.js"

const HELP = `sandboxed-shell: an interactive shell inside the MXC sandbox

Usage: sandboxed-shell [--workspace <dir>] [--shell <path>]

Options:
  -w, --workspace <dir>  The workspace the policy treats as writable (default: cwd)
  -s, --shell <path>     The shell to run inside the sandbox (default: $SHELL, /bin/zsh)
  -h, --help             Show this help

The policy comes from the same config as the plugin:
  ~/.config/universal-opencode-sandbox/config.json

Fails closed: when the sandbox cannot run, nothing runs.`

function fail(message: string): never {
  console.error(`sandboxed-shell: ${message}`)
  process.exit(1)
}

let workspace = process.cwd()
let shell = process.env.SHELL ?? "/bin/zsh"
const args = process.argv.slice(2)
for (let index = 0; index < args.length; index++) {
  const arg = args[index]
  if (arg === "-h" || arg === "--help") {
    console.log(HELP)
    process.exit(0)
  } else if (arg === "-w" || arg === "--workspace") {
    workspace = args[++index] ?? fail(`${arg} needs a value`)
  } else if (arg === "-s" || arg === "--shell") {
    shell = args[++index] ?? fail(`${arg} needs a value`)
  } else {
    fail(`unknown argument: ${arg}\n\n${HELP}`)
  }
}

if (!fs.existsSync(workspace)) fail(`workspace does not exist: ${workspace}`)

const policy = resolvePolicy(workspace)
if (!policy.enabled) {
  fail("the sandbox is disabled in the config; refusing to start an unsandboxed shell (set enabled true to use this terminal)")
}

const executor = resolveExecutor()
if (!fs.existsSync(executor)) fail(executor)
if (unsupportedNetwork(process.platform, policy.network)) {
  fail('the sandbox backend on Windows cannot enforce network denial yet; set network "allow" in the sandbox config to use this terminal')
}

// The interactive shell inherits the caller's environment (PATH, TERM, ...) layered
// over the backend defaults, so the terminal behaves like a normal one. Secrets in
// the environment stay inside: network egress is denied and the filesystem policy
// still applies to everything the shell and its children touch.
const environment = Object.entries(process.env)
  .filter((entry): entry is [string, string] => typeof entry[1] === "string")
  .map(([key, value]) => `${key}=${value}`)

const request = wireRequest({
  // An interactive shell runs until the user exits it.
  command: quote(shell),
  workspace,
  cwd: workspace,
  timeout: 0,
  policy,
  environment,
})

const requestDirectory = path.join(os.tmpdir(), "universal-opencode-sandbox")
fs.mkdirSync(requestDirectory, { recursive: true })
const file = path.join(requestDirectory, `terminal_${Date.now()}_${Math.random().toString(36).slice(2, 8)}.json`)
fs.writeFileSync(file, JSON.stringify(request), { mode: 0o600 })

const child = spawn(executor, [file], { stdio: "inherit" })
const remove = () => fs.rmSync(file, { force: true })
child.on("error", (error) => {
  remove()
  fail(error.message)
})
child.on("exit", (code, signal) => {
  remove()
  if (signal !== null) process.kill(process.pid, signal)
  process.exit(code ?? 1)
})
