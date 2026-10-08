# Nanosandbox Production Roadmap

## P0: Critical Security Fixes (Must Have)

### Process Management
- [x] **Zombie process prevention** - Add `wait()` after `kill()` in timeout handling
  - macOS: Using `wait4()` with `WNOHANG` for proper process reaping
  - Linux: Cgroup cleanup handles this
- [x] **Process group killing** - Use `killpg()` to kill entire process group
  - macOS: `setpgid(0, 0)` + `kill(-pid, SIGKILL)` in pre_exec
  - Linux: PID namespace ensures all children die with init
- [x] **Signal handler cleanup** - Handled via process group killing

### Resource Limits (macOS)
- [x] **Resource limits implemented** - `setrlimit` for open files/file size/CPU
  time; `memory_limit` via polled `rusage` instead (the kernel rejects
  `RLIMIT_AS`)
  - Note: `RLIMIT_NPROC` intentionally not used (affects entire user)

### Resource Limits (Linux)
- [x] **Cgroup cleanup** - `CgroupManager::cleanup()` with freeze + kill + rmdir
- [x] **OOM detection** - `was_oom_killed()` reads `memory.events` for oom_kill counter

### Network Proxy
- [x] **Prevent IP bypass** - Linux: its own network namespace, with the proxy as the only way out. macOS: the sandbox profile allows outbound only to the proxy's port.

## P1: Robustness (Production Required)

### Error Handling
- [x] **Graceful degradation** - Handle missing permissions without panic
- [x] **Detailed error types** - `SandboxError` enum with context
- [x] **Resource pre-check** - Verify cgroup/namespace permissions before execution
  - Linux: Check cgroup v2, user namespace support
  - macOS: Check sandbox-exec availability

### Concurrency
- [x] **Thread-safe sandbox ID** - AtomicU64 counter
- [x] **Parallel execution safety** - Tested with concurrent sandboxes

### Resource Statistics
- [x] **Peak memory collection**
  - macOS: `rusage.ru_maxrss` from `wait4()`
  - Linux: `memory.peak` from cgroup
- [x] **CPU time collection**
  - macOS: `rusage.ru_utime + ru_stime`
  - Linux: `cpu.stat usage_usec`

### Proxy Improvements
- [x] **Chunked transfer encoding** - Fixed BufReader buffering + URL rewriting
- [x] **Connection keep-alive** - Skipped (low value for sandbox use cases)
- [x] **Timeout handling** - Connection timeout (30s) and transfer timeout (5min)
- [x] **Error retry** - Not needed (proxy returns 502/504, client can retry)

## P2: Observability

### Logging
- [ ] **Structured logging** - Use tracing with structured fields
- [ ] **Log levels** - Debug for internal, Info for operations, Warn for issues
- [x] **Execution tracing** - Sandbox ID available via `sandbox.id()`

### Metrics
- [ ] **Execution counter** - Total executions, success/failure
- [ ] **Duration histogram** - Execution time distribution
- [x] **Resource usage** - Memory, CPU per execution in `ExecutionResult`
- [ ] **Optional Prometheus export**

### Audit
- [ ] **Security audit log** - Log blocked network requests, permission denials
- [ ] **Configurable audit destination** - File, syslog, custom handler

## P3: Platform Completeness

### Linux
- [x] **Seccomp BPF rules** - One fixed filter, `seccomp(bool)`
- [ ] **User namespace mapping** - Proper uid/gid mapping for rootless operation
- [ ] **Nested container support** - Handle running inside Docker/Kubernetes

### macOS
- [x] **SBPL profile generation** - Dynamic profile based on config
- [ ] **App Sandbox entitlements** - For GUI apps (low priority)
- [ ] **Hardened runtime** - Code signing considerations

### Windows
- Direction undecided: weighing native Windows support against dropping it
  for WSL2 (i.e. Linux support) instead. Native work below is on hold until
  that's settled.
- [ ] **Actual testing** - Code compiles but never tested on real Windows
- [ ] **Job Object limits** - Verify memory/CPU limits work
- [ ] **AppContainer** - Consider for stronger isolation

## P4: Testing

### Security Testing
- [x] **Escape testing** - `tests/security/escape_attempts.rs`
- [x] **Resource exhaustion** - `tests/security/resource_exhaustion.rs`
- [ ] **Fuzz testing** - Fuzz command inputs, profile generation

### Integration Testing
- [x] **Basic integration tests** - 185 tests passing (macOS; Linux adds its own platform-specific set)
- [ ] **Multi-distro Linux** - Ubuntu, Alpine, Fedora, Arch
- [ ] **macOS versions** - Ventura, Sonoma, Sequoia
- [ ] **Windows versions** - Windows 10, 11, Server

### Performance Testing
- [x] **Benchmark suite** - `benches/sandbox_bench.rs`
- [ ] **Startup latency** - Target <100ms
- [ ] **Memory overhead** - Measure per-sandbox overhead
- [ ] **Concurrent scaling** - 10, 100, 1000 parallel sandboxes

## P5: Documentation & Bindings

- [x] **Python bindings** - `crates/nanosandbox-python/` (PyO3), published to PyPI
- [x] **Node.js bindings** - `crates/nanosandbox-node/` (napi-rs), published to npm
- [x] **API reference** - `docs/API.md`
- [x] **Architecture doc** - `docs/ARCHITECTURE.md`
- [x] **Benchmark comparison** - `docs/BENCHMARKS.md`
- [x] **Security guide** - `docs/THREAT_MODEL.md`
- [ ] **Deployment guide** - Linux capabilities, macOS permissions, Windows UAC

---

## Progress Summary

| Phase | Status | Completed |
|-------|--------|-----------|
| P0 | 100% | All items complete |
| P1 | 100% | All items complete |
| P2 | 2/9 | Basic tracing + resource usage only |
| P3 | 2/9 | Linux seccomp + macOS SBPL done; Windows on hold (see above) |
| P4 | 4/11 | Security + basic integration tests done |
| P5 | 6/7 | Docs + Python/Node bindings + threat model done; deployment guide pending |

## Documentation

- [Architecture](docs/ARCHITECTURE.md) - Platform internals
- [API Reference](docs/API.md) - Complete API documentation
- [Threat Model](docs/THREAT_MODEL.md) - What's protected, what isn't, per platform
- [Benchmarks](docs/BENCHMARKS.md) - Performance comparison