# universal-opencode-sandbox

A [OpenCode](https://opencode.ai) 2.x plugin that runs every agent shell command inside an
OS-level sandbox enforced by [Microsoft MXC](https://github.com/microsoft/mxc). One
plugin, all three desktop platforms:

| Platform | Mechanism | Requirement |
|----------|-----------|-------------|
| macOS 15+ (Apple Silicon) | Seatbelt | none beyond this plugin |
| Linux | bubblewrap | `bwrap` >= 0.5.0 installed, unprivileged user namespaces |
| Windows 11 | ProcessContainer | native process-container support (probed automatically) |

Commands keep OpenCode's own streaming output, timeout and background behavior: the
plugin swaps the command string for an invocation of the bundled MXC executor with a
per-call policy file, so the sandboxed process is spawned by the executor while the
shell tool watches it like any other command.

## Install

Requires OpenCode 2.x (the `@opencode/plugin` 2.x contract).

```jsonc title="opencode.jsonc"
{
  "plugins": ["universal-opencode-sandbox"],
}
```

The sandbox is on by default once the plugin is installed, in its strictest useful
mode: the workspace is writable (and the system temp directory), everything else is
read-only, the network is denied, and a command the sandbox cannot run is blocked
rather than run unconfined.

## Configure

Policy is read only from places a sandboxed command cannot reach, so a repository
can never enable, loosen or tighten your sandbox. OpenCode plugin options are ignored
on purpose: they can be set from a repository's own config.

`~/.config/universal-opencode-sandbox/config.json` (respecting `XDG_CONFIG_HOME`):

```jsonc
{
  "enabled": true,
  // "enforce" (default) blocks a command when the sandbox cannot run it;
  // "permissive" runs it unsandboxed with a warning.
  "mode": "enforce",
  "filesystem": {
    // "read-only" (default) denies every write; "workspace-write" allows writes to
    // the workspace, the temp directory, and writable_roots.
    "mode": "workspace-write",
    "writable_roots": [],
    // Paths the sandboxed command can neither read nor write, e.g. credentials.
    "denied_paths": ["~/.ssh", "~/.aws"]
  },
  // "deny" (default) blocks all network access for sandboxed commands.
  "network": "deny",
  // What happens when a tool call asks to skip the sandbox (shell input
  // "sandbox: false"): "deny" (default) blocks it, "allow" runs it unsandboxed.
  "unsandboxed": "deny",
  // Per-project overrides, keyed by the workspace's absolute path. Every field is
  // optional and can only make the policy stricter, never looser.
  "projects": {
    "/home/me/src/scratch": { "network": "allow" }
  }
}
```

`UNIVERSAL_SANDBOX_CONFIG` (a JSON string) tightens the same fields per invocation.

## What is enforced

- **Filesystem**: in `workspace-write` mode, writes are allowed in the workspace and
  the temp directory only. In `read-only` mode no write is allowed at all.
- **Protected paths**: `opencode.json`, `opencode.jsonc`, `.opencode`, `.claude` and
  `.agents` in the workspace can never be written or planted by a sandboxed command,
  so a command cannot install a config or plugin that would run unsandboxed after a
  restart. Per platform: macOS enforces this for existing and not-yet-existing paths;
  Linux enforces it for paths that exist (bwrap cannot bind a missing read-only
  source, and the deny fallback has an upstream bug, microsoft/mxc#1780); Windows
  denies the paths outright.
- **Network**: denied by default. On Windows the backend currently cannot enforce a
  network-deny policy (verified against Windows 11 and MXC 1.1.0), so with
  `network: "deny"` (the default) sandboxed commands fail closed there with an
  explanation; set `network: "allow"` for filesystem-only containment on Windows.
- **Fail-closed**: an unsupported platform, a missing backend (install `bubblewrap` on
  Linux), or a missing executor blocks the command in `enforce` mode instead of
  running it unconfined. `mode: "permissive"` trades that guarantee for convenience.

## Known limitations

- With the sandbox enabled, OpenCode's per-command shell permission rules see the
  sandbox wrapper invocation, not the inner command. The OS sandbox is the real
  boundary here; command-pattern rules are weaker than it anyway (and trivially
  bypassed by an adversarial agent). If you rely on `deny` rules for specific
  commands, prefer this plugin's `denied_paths` and filesystem policy.
- Intel macOS is unsupported: the MXC npm package ships no darwin-x64 runtime yet.
- MXC release builds on Windows emit required Microsoft diagnostic telemetry; see the
  [MXC documentation](https://github.com/microsoft/mxc).
- MXC's process streams do not deliver under Bun (microsoft/mxc#1782). This plugin is
  unaffected: the executor is a native binary whose output the shell tool captures.

## Verification

Tested against the real backends on macOS (Seatbelt), Debian 13 with bubblewrap 0.12
and Windows 11 (ProcessContainer): output and exit codes stream through, writes inside
the workspace succeed, writes outside are denied, protected config files cannot be
planted, and network egress is blocked (except the documented Windows gap). Also
verified end to end inside a real OpenCode 2.2.7 session: an agent's shell command
writes inside the workspace and is denied outside it.

## License

MIT
