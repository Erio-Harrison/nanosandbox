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

## Building from source

Only needed if you're changing the binding itself -- end users want `pip install nanosandbox` above, which installs a prebuilt wheel.

```bash
pip install maturin pytest
maturin develop
pytest tests/
```
