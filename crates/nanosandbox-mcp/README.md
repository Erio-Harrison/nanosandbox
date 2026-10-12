# nanosandbox-mcp

An [MCP](https://modelcontextprotocol.io) server that lets an AI agent run commands in a
[nanosandbox](https://github.com/Erio-Harrison/nanosandbox) sandbox. It speaks MCP over stdio and
offers one tool, `run_command`.

## Install

```bash
npx -y nanosandbox-mcp --help        # npm, nothing to install first
uvx nanosandbox-mcp --help           # PyPI, via uv
cargo install nanosandbox-mcp        # crates.io, builds from source
```

Prebuilt binaries cover macOS (Apple silicon and Intel) and Linux (x86_64 and aarch64, glibc 2.17+).
Linux and macOS only. Windows isn't supported yet: the sandbox there is a resource limiter, not a
security boundary.

## Use

Add it to an MCP client's configuration (Claude Desktop, Cursor, Zed, ...):

```json
{
  "mcpServers": {
    "sandbox": {
      "command": "npx",
      "args": ["-y", "nanosandbox-mcp", "--workspace", "/path/to/project"]
    }
  }
}
```

(With `uvx`: `"command": "uvx", "args": ["nanosandbox-mcp", "--workspace", ...]`. With a
`cargo install`ed binary: `"command": "nanosandbox-mcp"`.)

The agent can now run programs, with their files limited to that workspace and no network.

## Who decides what the sandbox may do

You do, when you launch the server. The model chooses *what to run*; it never chooses *what the
sandbox may touch*. The tool takes only `command`, `args` and `stdin`. There is no parameter for
paths, network, memory or time, so a model can't ask for more than you allowed. An extra argument
is refused.

| Option | Meaning | Default |
|---|---|---|
| `--workspace <DIR>` | Working directory and the only place commands can write. **Required.** | |
| `--read-only <PATH>`, `--writable <PATH>` | Also allow reading / writing a path (repeatable). A `--read-only` path inside the workspace is read-only again, so `.git/hooks` or a settings file there can't be changed by a command (on Linux this needs mounting, refused where AppArmor denies it) | |
| `--deny-read <PATH>`, `--no-hide-home` | Hide a path; stop hiding the home directory | home hidden |
| `--allow-network <HOST>` | Allow these hosts, comma-separated or repeated; `*.example.com` works | network off |
| `--host-network` | Unrestricted network. Use with care. | |
| `--memory <SIZE>`, `--timeout <SECS>` | Per-command limits | 512M, 30 s |
| `--cpu <N>`, `--max-pids <N>` | Linux only | pids: 128 on Linux |
| `--max-output <SIZE>` | Cap on each of stdout and stderr per command, so one call can't flood the model | 1M |
| `--max-concurrent <N>` | Commands running at once | CPU count |
| `--env <KEY=VALUE>` | Environment variable for commands (repeatable) | see below |
| `--no-cache` | Don't keep npm's and pip's download caches in `<workspace>/.nanosandbox-cache/` | cache kept |
| `--strict-tmp` | macOS only: make `/tmp` and the other system temp directories read-only; commands get a private `$TMPDIR`. Breaks `/tmp` by name, `mktemp -t` and `/usr/bin/clang`/`cc`; see [platform-macos.md](https://github.com/Erio-Harrison/nanosandbox/blob/master/docs/platform-macos.md#shared_tmpfalse) | off |
| `--host-uid`, `--host-gid`, `--no-seccomp` | Linux only | |
| `--log-io` | Also log stdin/stdout/stderr bodies | off |

Run `nanosandbox-mcp --help` for the full text. A limit this platform can't enforce (for example
`--max-pids` on macOS) makes the server refuse to start, rather than run without it.

## What a command's environment holds

Not your whole environment: `PATH`, a `HOME`, `TMPDIR`, cache locations (below), and whatever you pass
with `--env`.

- `PATH` is the server's own, so what your terminal finds, commands find. A client that starts the
  server from a GUI often gives it a bare `PATH` (`/usr/bin:/bin`): then pass the real one with
  `--env PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin`. An explicit `--env PATH=` wins.
- `HOME` is the command's private temp directory, writable and gone after the call. npm, pip and
  git keep caches and config under `HOME`; without one they find your real home, which the sandbox
  can't write, and fail. Config and credentials they write there (an `.npmrc` with a token, a
  `.gitconfig`) don't outlive the call either.
- Downloads are kept, though, in `<workspace>/.nanosandbox-cache/`: `npm_config_cache`,
  `PIP_CACHE_DIR` and `XDG_CACHE_HOME` point into it. So a reinstall after deleting `node_modules`
  or a venv doesn't download again (tried: `npm install --offline` works afterwards). It's in the
  workspace, not in `HOME`, because `HOME` is a private temp directory capped at 256 MB, which a
  large package overflows (tried: a 300 MB write there is cut off; in the workspace it isn't). The
  directory holds a `.gitignore` with `*`, so it isn't in `git status`. It only grows; delete it to
  clear it. `--no-cache` turns it off, and an `--env` for one of those variables wins.
- Everything else (API keys included) is absent unless you pass it with `--env`.

## Recipes

What follows is what was tried, on macOS and Linux, not a promise for every setup.

**Python**: `--allow-network pypi.org,files.pythonhosted.org`. Make the environment in the workspace
(`python3 -m venv .venv`, then `.venv/bin/pip install ...`); `pip` goes through the proxy.

**Node**: `--allow-network registry.npmjs.org`, and the right `PATH` for where `node` lives (see
above). `npm install` works, and what it downloads is cached in the workspace (see above).

**Git**: `--allow-network github.com` to clone over https. `git config --global` writes to the
private `HOME` and is gone after the call, so if git asks who you are, give it
`git -c user.name=... -c user.email=...` on the command.

**Rust**: the toolchain lives in your home (`~/.cargo`, `~/.rustup`), which is hidden by default,
so `cargo` fails with `Operation not permitted`. Add `--no-hide-home` and `~/.cargo/bin` to `PATH`
(`--env PATH=$HOME/.cargo/bin:/usr/bin:/bin`, with `$HOME` filled in by your shell or client). That
makes your home readable, apart from the credentials and shell history that stay unreadable
regardless. Fetching dependencies also needs `--allow-network index.crates.io,static.crates.io`.

**Starting a server and testing it in the same call** doesn't work on macOS (a program can't bind or
connect to loopback there, by design) or on Linux without `--allow-network`. With it on Linux, a
program's own `127.0.0.1` servers work and aren't sent through the proxy.

**Ubuntu 23.10+ with AppArmor's `unprivileged_userns` restriction** (the default on 24.04) refuses
`--allow-network` at startup, since a network namespace's loopback can't be brought up. That leaves
`--host-network` (everything allowed, nothing filtered), or lifting the restriction for the
binary: `kernel.apparmor_restrict_unprivileged_userns=0`, or an AppArmor profile that allows `userns`
for `nanosandbox-mcp`. Until one of those, the allowlist isn't available there.

## The tool

`run_command` runs one program in a fresh sandbox and returns:

```json
{ "stdout": "...", "stderr": "...", "exit_code": 0, "duration_ms": 15,
  "timed_out": false, "out_of_memory": false, "cpu_limit_hit": false,
  "tmp_limit_hit": false, "output_truncated": false, "blocked_hosts": [] }
```

A command that runs and fails (non-zero exit, killed by a limit) is a normal result, so the model
can read the output and react. Only a call that couldn't run at all comes back with `isError`.

There is no shell: `args` is the argument vector. For pipes or `&&`, run `sh` with
`["-c", "..."]`. Every call is a new sandbox; files in the workspace are what carry over.
Calls run in parallel up to `--max-concurrent`. A client cancelling a call stops its reply, but the
command runs until it ends or hits the time limit.

One line per call goes to stderr (command, exit code, duration, which limit hit, blocked hosts).
Stdin and output are only logged with `--log-io`, since they can contain secrets.

## Protocol

Stdio transport, tools only. Both generations of the protocol are served on the same stream: the
stateless 2026-07-28 revision (`server/discover`, per-request `_meta`) and the earlier `initialize`
handshake (2025-11-25 down to 2024-11-05). HTTP, OAuth, resources, prompts and sampling are not
offered: a local command runner has no use for them.

## What this isn't

This is a process-level sandbox on a shared kernel, suited to one developer's agent or one trusted
service. It is not isolation between mutually distrusting tenants. Read the
[threat model](https://github.com/Erio-Harrison/nanosandbox/blob/master/docs/THREAT_MODEL.md)
before relying on it, including the platform differences: macOS is structurally weaker than Linux.

Running as root on Linux, commands run as `nobody` unless `--host-uid`/`--host-gid` say otherwise,
and the workspace must be writable by that user; the server says so at startup if it isn't.
On macOS, `/tmp` and the other temp directories are the host's own: commands can write there and
what they write stays, unless you start the server with `--strict-tmp`; writes anywhere else
outside the workspace are denied.
On Ubuntu 23.10+ under AppArmor's `unprivileged_userns` restriction, `--allow-network` is refused
at startup, and `/var/tmp` and `/dev/shm` are the host's shared paths.
