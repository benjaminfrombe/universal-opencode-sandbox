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
mode: the workspace and the system temp directory are writable, everything else is
write-denied, the network is denied, credential stores are unreadable (see the
default list below), and a command the sandbox cannot run is blocked rather than
run unconfined. No configuration is required for that; the config file below only
changes it.

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
    // "workspace-write" (default) allows writes to the workspace, the temp
    // directory, and writable_roots; "read-only" denies every write.
    "mode": "workspace-write",
    "writable_roots": [],
    // Paths the sandboxed command can neither read nor write. Unset (default):
    // the standard credential list below. Setting the list replaces it: the
    // entries are then yours, and per-project overrides only add to them.
    "denied_paths": ["~/.ssh", "~/.aws"]
  },
  // "deny" (default) blocks all network access for sandboxed commands.
  "network": "deny",
  // What happens when a tool call asks to skip the sandbox (shell input
  // "sandbox: false"): "deny" (default) blocks it, "allow" runs it unsandboxed.
  "unsandboxed": "deny",
  // Also sandbox user "!" commands and plugin shells, protecting the user from
  // social engineering ("run this for me") and accidental damage. Default: false.
  "sandbox_user_commands": true,
  // Tool names the agent may not call at all; "*" is a wildcard. Use this to close
  // escape routes outside the sandbox, such as a host app's unsandboxed terminal
  // tools (an agent can otherwise spawn or drive a raw shell there). Unlike
  // opencode's own permission rules, a repository config cannot re-allow these.
  "blocked_tools": ["paseo_create_terminal", "paseo_send_terminal_keys"],
  // Per-project overrides, keyed by the workspace's absolute path. Every field is
  // optional and can only make the policy stricter, never looser.
  "projects": {
    "/home/me/src/scratch": { "network": "allow" }
  }
}
```

`UNIVERSAL_SANDBOX_CONFIG` (a JSON string) tightens the same fields per invocation.

### Default denied paths

Without a `denied_paths` entry, the sandbox denies reading and writing these
credential stores. A stolen long-lived credential cannot be undone by a restart,
so reading is denied even though the network usually is too: a secret read once
can be copied into the workspace and walk out through a commit.

- `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.netrc`, `~/.kube`, `~/.azure` - identity
  directories: keys, cloud credentials, cluster tokens
- `~/.config/gcloud` - GCP credentials and service-account keys
- `~/.npmrc`, `~/.pypirc`, `~/.cargo/credentials`, `~/.docker/config.json` -
  registry tokens of the major package managers and Docker
- `~/.config/gh/hosts.yml` and `~/Library/Application Support/gh/hosts.yml` -
  the GitHub CLI token (both config-directory conventions)
- `~/.local/share/opencode/auth.json` - OpenCode provider API keys
- `~/.claude/.credentials.json`, `~/.codex/auth.json` - credentials of the
  other agent CLIs

Setting `denied_paths` replaces this list. On Linux only paths that exist are
enforced (an upstream deny bug would otherwise create stray directories,
microsoft/mxc#1780); on macOS not-yet-existing paths are protected too.

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

## Sandboxed terminal

The package also ships `sandboxed-shell`, a small CLI that starts an **interactive
shell inside the same sandbox**: the same filesystem and network policy as the agent
commands, applied to everything you (or anything else) type into it.

```bash
# Safe terminal: interactive zsh under Seatbelt/bubblewrap/ProcessContainer
sandboxed-shell --workspace /path/to/project
```

This gives you two terminal types next to each other:

| Terminal type | How | What runs inside |
|---|---|---|
| Safe terminal | `sandboxed-shell` (or `exec` it in an existing terminal) | The MXC sandbox policy from your config |
| Admin terminal | your normal shell | Unconfined, for server restarts and admin work |

The safe terminal fails closed: if the sandbox cannot run, no shell is started, and
exiting it ends the session with no unsandboxed fallback. It inherits your
environment (PATH, TERM, HOME) so it behaves like a normal terminal; secrets in the
environment stay put because egress is denied and the filesystem policy still applies.

**Locking it down for other users**: the two-type design is exactly what lets you
disable the admin terminal for regular users. The plugin confines opencode agents;
terminals spawned by a host app (for example Paseo) are confined by having the host
start them through `sandboxed-shell` instead of a plain shell. Whoever controls
terminal creation controls the choice: point every terminal at the wrapper and nobody
gets an unsandboxed one. Inside opencode itself, two layers close the agent's route
to a host app's terminals: `blocked_tools` denies the terminal tools at every tool
call (a repository config cannot re-allow it), and opencode's own `permissions` rules
hide them from the agent's tool catalog entirely:

```jsonc
// opencode.jsonc, next to this plugin in your config
{
  "permissions": [
    { "action": "paseo_create_terminal", "resource": "*", "effect": "deny" },
    { "action": "paseo_send_terminal_keys", "resource": "*", "effect": "deny" },
    { "action": "paseo_capture_terminal", "resource": "*", "effect": "deny" }
  ]
}
```

Use the `permissions` array: the older `permission` object is deprecated and, on
current releases, silently ignored.

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
writes inside the workspace and is denied outside it. The `sandboxed-shell` terminal
was verified interactively on macOS: commands run with full environment, writes inside
the workspace succeed, writes outside are denied, network egress is blocked, and
`denied_paths` (for example `~/.ssh`) cannot be read.

## License

MIT
