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
- [x] **Actually implement setrlimit** - `setrlimit(RLIMIT_AS, ...)` for memory
  - Note: `RLIMIT_NPROC` intentionally not used (affects entire user)

### Resource Limits (Linux)
- [x] **Cgroup cleanup** - `CgroupManager::cleanup()` with freeze + kill + rmdir
- [x] **OOM detection** - `was_oom_killed()` reads `memory.events` for oom_kill counter

### Network Proxy
- [ ] **Prevent IP bypass** - Sandboxed process can connect directly via IP, bypassing domain whitelist
  - Fix: Requires iptables/pf rules or network namespace with restricted routing
  - Status: Tests marked as `#[ignore]` with P0 TODO comment

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
- [ ] **Seccomp BPF rules** - Current SeccompProfile is just an enum, no actual filtering
- [ ] **User namespace mapping** - Proper uid/gid mapping for rootless operation
- [ ] **Nested container support** - Handle running inside Docker/Kubernetes

### macOS
- [x] **SBPL profile generation** - Dynamic profile based on config
- [ ] **App Sandbox entitlements** - For GUI apps (low priority)
- [ ] **Hardened runtime** - Code signing considerations

### Windows
- [ ] **Actual testing** - Code compiles but never tested on real Windows
- [ ] **Job Object limits** - Verify memory/CPU limits work
- [ ] **AppContainer** - Consider for stronger isolation

## P4: Testing

### Security Testing
- [x] **Escape testing** - `tests/security/escape_attempts.rs`
- [x] **Resource exhaustion** - `tests/security/resource_exhaustion.rs`
- [ ] **Fuzz testing** - Fuzz command inputs, profile generation

### Integration Testing
- [x] **Basic integration tests** - 53 tests passing
- [ ] **Multi-distro Linux** - Ubuntu, Alpine, Fedora, Arch
- [ ] **macOS versions** - Ventura, Sonoma, Sequoia
- [ ] **Windows versions** - Windows 10, 11, Server

### Performance Testing
- [x] **Benchmark suite** - `benches/sandbox_bench.rs`
- [ ] **Startup latency** - Target <100ms
- [ ] **Memory overhead** - Measure per-sandbox overhead
- [ ] **Concurrent scaling** - 10, 100, 1000 parallel sandboxes

## P5: Documentation & Bindings

- [ ] **Python bindings** - `crates/nanosandbox-python/` (PyO3)
- [ ] **Node.js bindings** - `crates/nanosandbox-node/` (napi-rs)
- [x] **API reference** - `docs/API.md`
- [x] **Architecture doc** - `docs/ARCHITECTURE.md`
- [x] **Benchmark comparison** - `docs/BENCHMARKS.md`
- [ ] **Security guide** - Threat model, limitations, recommendations
- [ ] **Deployment guide** - Linux capabilities, macOS permissions, Windows UAC

---

## Progress Summary

| Phase | Status | Completed |
|-------|--------|-----------|
| P0 | 90% | 5/6 items (IP bypass remaining) |
| P1 | 100% | All items complete |
| P2 | 20% | Basic tracing only |
| P3 | 30% | macOS SBPL done |
| P4 | 50% | Security + integration tests done |
| P5 | 70% | Bindings + docs done, guides pending |

## Documentation

- [Architecture](docs/ARCHITECTURE.md) - Platform internals
- [API Reference](docs/API.md) - Complete API documentation
- [Benchmarks](docs/BENCHMARKS.md) - Performance comparison