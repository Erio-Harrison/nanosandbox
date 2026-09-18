# nanosandbox

A lightweight, embeddable sandbox for running untrusted code. Works on Linux, macOS, and Windows.

## Why?

Docker is overkill for running a single script. Cloud sandboxes (E2B, etc.) add latency and cost money. nanosandbox uses OS-native isolation primitives directly—no VMs, no containers, no network calls.

| Platform | How it works |
|----------|--------------|
| Linux | namespaces + cgroups v2 + seccomp |
| macOS | sandbox-exec (Seatbelt/SBPL) |
| Windows | Job Objects + Restricted Tokens |

## Install

```toml
[dependencies]
nanosandbox = "0.1"
```

## Usage

```rust
use nanosandbox::{Sandbox, Permission, MB};
use std::time::Duration;

let sandbox = Sandbox::builder()
    .mount("/data/input", "/input", Permission::ReadOnly)
    .memory_limit(256 * MB)
    .wall_time_limit(Duration::from_secs(30))
    .no_network()
    .build()?;

let result = sandbox.run("python3", &["-c", "print('hello')"])?;
println!("{}", result.stdout);  // hello
```

### Presets

```rust
// For AI agents that need specific API access
let sandbox = Sandbox::agent_executor("/workspace")
    .allow_network(&["api.openai.com", "api.anthropic.com"])
    .build()?;

// For online judges / code evaluation
let sandbox = Sandbox::code_judge("/submission")
    .build()?;

// For data processing pipelines
let sandbox = Sandbox::data_analysis("/input", "/output")
    .build()?;
```

### Python Bindings

```python
from nanosandbox import Sandbox, Permission, MB

sandbox = (Sandbox.builder()
    .working_dir("/tmp")
    .memory_limit(128 * MB)
    .build())

result = sandbox.run("echo", ["hello"])
print(result.stdout)
```

Install with: `pip install nanosandbox`

## Network Control

Block all network access:
```rust
.no_network()
```

Allow specific domains only (uses a local HTTP proxy):
```rust
.allow_network(&["api.github.com", "*.amazonaws.com"])
```

## Features

| | Linux | macOS | Windows |
|---|:---:|:---:|:---:|
| Memory limits | ✓ | ~ | ✓ |
| CPU limits | ✓ | - | ✓ |
| Process limits | ✓ | - | ✓ |
| Wall-clock timeout | ✓ | ✓ | ✓ |
| Filesystem isolation | ✓ | ✓ | ~ |
| Network isolation | ✓ | ✓ | - |
| Syscall filtering | ✓ | ~ | - |

`✓` = full support, `~` = partial, `-` = not available

## Building

```bash
cargo build
cargo test
cargo bench --no-run  # compile benchmarks
```

Run on Linux with cgroups v2. On macOS, sandbox-exec is available by default. Windows needs no special setup.

## Documentation

- [Architecture](docs/ARCHITECTURE.md) - Platform internals and design decisions
- [API Reference](docs/API.md) - Complete API documentation
- [Benchmarks](docs/BENCHMARKS.md) - Performance comparison with other solutions

### Platform Details

- [Linux Implementation](docs/platform-linux.md) - Namespaces, cgroups v2, seccomp
- [macOS Implementation](docs/platform-macos.md) - sandbox-exec, SBPL profiles
- [Windows Implementation](docs/platform-windows.md) - Job Objects, Restricted Tokens

## References

### Linux

- [namespaces(7)](https://man7.org/linux/man-pages/man7/namespaces.7.html) - Linux namespaces overview
- [cgroups v2](https://docs.kernel.org/admin-guide/cgroup-v2.html) - Unified control group hierarchy
- [seccomp(2)](https://man7.org/linux/man-pages/man2/seccomp.2.html) - Syscall filtering
- [bubblewrap](https://github.com/containers/bubblewrap) - Unprivileged sandboxing tool

### macOS

- [App Sandbox Design Guide](https://developer.apple.com/library/archive/documentation/Security/Conceptual/AppSandboxDesignGuide/) - Apple's sandboxing documentation
- [SBPL Reference](https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v1.0.pdf) - Sandbox Profile Language syntax
- [sandbox-exec(1)](https://www.manpagez.com/man/1/sandbox-exec/) - Command-line sandbox tool

### Windows

- [Job Objects](https://docs.microsoft.com/en-us/windows/win32/procthread/job-objects) - Process group management
- [Access Tokens](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-tokens) - Security tokens
- [AppContainer Isolation](https://docs.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation) - UWP-style isolation

### Related Projects

- [gVisor](https://github.com/google/gvisor) - Application kernel for containers
- [Firecracker](https://github.com/firecracker-microvm/firecracker) - Lightweight microVMs
- [nsjail](https://github.com/google/nsjail) - Light-weight process isolation tool
- [minijail](https://chromium.googlesource.com/chromiumos/platform/minijail) - Chrome OS sandboxing
- [E2B](https://e2b.dev/) - Cloud code interpreters

## License

MIT
