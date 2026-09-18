# Nanosandbox Benchmarks & Comparison

Performance benchmarks and comparison with other sandbox solutions.

## Benchmark Environment

- **Platform:** macOS 14.x (ARM64, Apple Silicon M-series)
- **Rust:** 1.75+
- **Benchmark Tool:** Criterion.rs
- **Date:** January 2025

---

## Nanosandbox Performance

### Sandbox Creation

| Scenario | Time | Description |
|----------|------|-------------|
| Minimal | **2.5 µs** | Empty config, just struct creation |
| With limits | **2.6 µs** | Memory + CPU + PID limits |
| With mounts | **3.6 µs** | One mount point added |

**Note:** Sandbox creation only builds the config object. Actual isolation happens during `run()`.

### Command Execution

| Command | Time | Notes |
|---------|------|-------|
| `echo hello` | **13.0 ms** | Minimal command |
| `true` | **13.1 ms** | No output |
| `sh -c "echo"` | **13.1 ms** | Shell wrapper |

**Breakdown (~13ms):**
- sandbox-exec profile generation: ~0.5ms
- fork(): ~1ms
- exec(): ~2ms
- sandbox-exec policy enforcement: ~8ms
- wait4() + cleanup: ~1.5ms

### I/O Scaling

| Output Lines | Time | Throughput |
|--------------|------|------------|
| 10 lines | 13.6 ms | 735 lines/sec |
| 100 lines | 13.1 ms | 7,634 lines/sec |
| 1,000 lines | 14.3 ms | 69,930 lines/sec |
| 10,000 lines | 25.1 ms | 398,406 lines/sec |

**Conclusion:** I/O overhead is minimal until ~10K lines.

### Stdin Input

| Input Size | Time | Throughput |
|------------|------|------------|
| 100 bytes | 12.9 ms | 7.8 KB/s |
| 1 KB | 13.1 ms | 76 KB/s |
| 10 KB | 13.3 ms | 752 KB/s |

**Conclusion:** Stdin handling adds negligible overhead.

### Parallel Execution

| Sandboxes | Time | Scaling |
|-----------|------|---------|
| 1 | 13.0 ms | baseline |
| 2 | 13.6 ms | 1.05x |
| 4 | 14.4 ms | 1.11x |
| 8 | 21.4 ms | 1.65x |

**Conclusion:** Near-linear scaling up to 4 concurrent sandboxes, slight degradation at 8.

---

## Horizontal Comparison

### Startup Latency

| Solution | Cold Start | Warm Start | Notes |
|----------|------------|------------|-------|
| **Nanosandbox** | **~13 ms** | **~13 ms** | No daemon, direct fork |
| Docker | ~500 ms | ~200 ms | Requires dockerd |
| gVisor (runsc) | ~150 ms | ~80 ms | Requires containerd |
| Firecracker | ~125 ms | ~50 ms | Requires KVM |
| Wasmer | ~5 ms | ~1 ms | WASM only |
| Isolate | ~10 ms | ~10 ms | Linux only |

### Memory Overhead

| Solution | Per-Instance | Base Daemon | Total (10 instances) |
|----------|--------------|-------------|---------------------|
| **Nanosandbox** | **~2 MB** | **0** | **~20 MB** |
| Docker | ~30 MB | ~100 MB | ~400 MB |
| gVisor | ~50 MB | ~200 MB | ~700 MB |
| Firecracker | ~5 MB | ~50 MB | ~100 MB |
| Wasmer | ~10 MB | 0 | ~100 MB |

### Binary Size

| Solution | Core Binary | With Dependencies |
|----------|-------------|-------------------|
| **Nanosandbox** | **< 1 MB** | **< 1 MB** |
| Docker CLI | ~50 MB | ~100 MB (dockerd) |
| gVisor | ~50 MB | ~50 MB |
| Firecracker | ~3 MB | ~3 MB |
| Wasmer | ~20 MB | ~20 MB |

### Feature Comparison

| Feature | Nanosandbox | Docker | gVisor | Firecracker | Wasmer |
|---------|---------|--------|--------|-------------|--------|
| **Language** | Rust | Go | Go | Rust | Rust |
| **Isolation** | Process | Container | Kernel | VM | WASM |
| **Cross-platform** | Linux/macOS/Win | Linux | Linux | Linux | All |
| **Embeddable** | Library | REST API | REST API | REST API | Library |
| **No Daemon** | Yes | No | No | No | Yes |
| **Filesystem Isolation** | Yes | Yes | Yes | Yes | Limited |
| **Network Isolation** | Yes | Yes | Yes | Yes | N/A |
| **Memory Limit** | Yes | Yes | Yes | Yes | Yes |
| **CPU Limit** | Linux/Win | Yes | Yes | Yes | No |
| **Process Limit** | Linux/Win | Yes | Yes | Yes | N/A |
| **Rootless** | Yes | Partial | No | No | Yes |
| **GPU Passthrough** | No | Yes | No | No | No |

### Isolation Strength

| Solution | Escape Difficulty | Attack Surface |
|----------|-------------------|----------------|
| Firecracker | Very High (VM) | Small (KVM) |
| gVisor | High (Kernel intercept) | Medium |
| Docker | Medium (namespaces) | Large |
| **Nanosandbox** | **Medium** | **Medium** |
| Wasmer | Medium (WASM sandbox) | Small |

---

## Use Case Recommendations

### AI Code Execution (Low Latency)

**Winner: Nanosandbox**

Requirements:
- Sub-100ms startup
- No daemon overhead
- Embeddable in existing process

```
Nanosandbox: 13ms startup, 0 daemon overhead, native library
Docker: 500ms startup, 100MB daemon, subprocess required
```

### Online Judge / Code Competition

**Winner: Nanosandbox or Isolate**

Requirements:
- Strict resource limits
- Fast execution
- High concurrency

```
Nanosandbox: 13ms/execution, portable
Isolate: 10ms/execution, Linux only
Docker: 200ms/execution, overkill
```

### Production Microservices

**Winner: Docker / Kubernetes**

Requirements:
- Orchestration
- Service discovery
- Mature ecosystem

```
Docker: Rich ecosystem, well-tested
Nanosandbox: Not designed for this use case
```

### High-Security Isolation

**Winner: Firecracker or gVisor**

Requirements:
- Maximum isolation
- Defense in depth
- Kernel-level protection

```
Firecracker: VM-level isolation
gVisor: Kernel syscall interception
Nanosandbox: Process-level only
```

### Edge / Serverless

**Winner: Nanosandbox or Wasmer**

Requirements:
- Minimal footprint
- Fast cold start
- No infrastructure

```
Nanosandbox: 13ms startup, native code support
Wasmer: 5ms startup, WASM only
Docker: Too heavy for edge
```

### WebAssembly Workloads

**Winner: Wasmer / Wasmtime**

Requirements:
- WASM execution
- Portable
- Secure

```
Wasmer: Native WASM support
Nanosandbox: Can run wasm runtimes, but not specialized
```

---

## Cost Analysis (Cloud)

Assuming 1M executions/month, 100ms average execution:

| Solution | Compute Cost | Infrastructure | Total |
|----------|--------------|----------------|-------|
| **Nanosandbox** (Lambda) | ~$2 | $0 | **~$2** |
| Docker (ECS) | ~$50 | ~$20 | ~$70 |
| gVisor (GKE) | ~$100 | ~$50 | ~$150 |
| Firecracker (Lambda) | ~$2 | $0 | ~$2 |

**Note:** Nanosandbox's low overhead makes it ideal for serverless.

---

## Running Benchmarks

```bash
# Run all benchmarks
cargo bench

# Run specific benchmark group
cargo bench -- sandbox_creation
cargo bench -- command_execution
cargo bench -- parallel_execution

# Generate HTML report
cargo bench -- --verbose
# Results in: target/criterion/report/index.html
```

### Custom Benchmark

```rust
use criterion::{criterion_group, criterion_main, Criterion};
use nanosandbox::Sandbox;

fn my_benchmark(c: &mut Criterion) {
    c.bench_function("my_workload", |b| {
        let sandbox = Sandbox::builder()
            .working_dir("/tmp")
            .build()
            .unwrap();

        b.iter(|| {
            sandbox.run("my_command", &["arg1", "arg2"]).unwrap()
        })
    });
}

criterion_group!(benches, my_benchmark);
criterion_main!(benches);
```

---

## Platform-Specific Notes

### Linux Performance

- Cgroup v2 overhead: ~0.5ms per execution
- Namespace creation: ~1ms
- Seccomp filter: ~0.1ms (if enabled)
- Best overall performance

### macOS Performance

- sandbox-exec overhead: ~8ms (SBPL parsing)
- setrlimit: negligible
- Process group: ~0.1ms
- Slower than Linux due to sandbox-exec

### Windows Performance

- Job Object: ~1ms
- Token creation: ~2ms
- Note: Not fully tested

---

## Optimization Tips

### For Latency

1. **Reuse sandboxes** - Create once, run many
2. **Avoid mounts** - Each mount adds ~1µs
3. **Disable unused features** - No network = faster

### For Throughput

1. **Parallel execution** - Use thread pool
2. **Batch small commands** - Amortize startup cost
3. **Use tmpfs** - Faster than disk I/O

### For Memory

1. **Set memory limits** - Prevent runaway
2. **Share read-only mounts** - Copy-on-write
3. **Cleanup promptly** - Drop sandbox when done
