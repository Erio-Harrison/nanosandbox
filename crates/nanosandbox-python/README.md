# nanosandbox (Python)

Python bindings for [nanosandbox](https://github.com/Erio-Harrison/nanosandbox), built with [PyO3](https://pyo3.rs) and [maturin](https://www.maturin.rs).

```bash
pip install nanosandbox
```

```python
from nanosandbox import Sandbox, MB

sandbox = (Sandbox.builder()
    .read_only("/data/input")
    .memory_limit(512 * MB)
    .build())

result = sandbox.run("python3", ["-c", "print('hello')"])
print(result.stdout)
```

See the [main README](https://github.com/Erio-Harrison/nanosandbox#readme) for the full API.

## Threads

`run()` and `run_with_input()` release the GIL while the sandboxed command runs, so other Python
threads keep going, and several runs can overlap. Four threads each running a one-second command
finish in about one second, not four:

```python
import threading

sandbox = Sandbox.builder().working_dir("/tmp").build()
threads = [threading.Thread(target=sandbox.run, args=("sleep", ["1"])) for _ in range(4)]
for t in threads:
    t.start()
for t in threads:
    t.join()
```

One `Sandbox` can be shared across threads.

## Temp directories (macOS)

On macOS `/tmp` and the other system temp directories are the host's own, and writable. To make
them read-only and leave only the run's private `$TMPDIR`:

```python
sandbox = Sandbox.builder().working_dir("/tmp").shared_tmp(False).build()
```

This breaks programs that write `/tmp` by name, `mktemp -t` and Apple's `/usr/bin/clang`/`cc`
shims; see [docs/platform-macos.md](https://github.com/Erio-Harrison/nanosandbox/blob/master/docs/platform-macos.md#shared_tmpfalse).
macOS only; the method doesn't exist elsewhere.

## Running as root (Linux)

When the calling process is root, commands run as `nobody`, so a directory you pass to `writable()`
has to be writable by `nobody`. A directory only its owner can write to (typical for ones a
root-run container created for another user) is refused at `build()` with a message saying so.
Run as that owner instead:

```python
sandbox = (Sandbox.builder()
    .writable("/data/out")
    .host_uid(1000)
    .host_gid(1000)
    .build())
```

`host_uid`/`host_gid` are the ids permission checks on the host's files use; `uid()`/`gid()` stay
what the program sees inside. 0 is refused, and so is setting them when the caller isn't root.
Whatever that user can reach on the host, the program can, within the rest of the sandbox's limits.
Linux only. See [docs/platform-linux.md](https://github.com/Erio-Harrison/nanosandbox/blob/master/docs/platform-linux.md#running-as-root).

## Building from source

Only needed if you're changing the binding itself -- end users want `pip install nanosandbox` above, which installs a prebuilt wheel.

```bash
pip install maturin pytest
maturin develop
pytest tests/
```
