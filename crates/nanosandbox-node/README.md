# nanosandbox (Node.js)

Node.js bindings for [nanosandbox](https://github.com/Erio-Harrison/nanosandbox), built with [napi-rs](https://napi.rs).

```bash
npm install nanosandbox
```

```javascript
const { Sandbox, MB } = require("nanosandbox");

const sandbox = Sandbox.builder()
    .workingDir("/tmp")
    .memoryLimit(128 * MB)
    .build();

const result = sandbox.run("echo", ["hello"]);
console.log(result.stdout);
```

`run()` blocks the JS thread until the command ends, so timers, I/O and any
other requests your process is serving stall meanwhile. In a server or an
agent loop, use the Promise versions, which run on libuv's thread pool and
leave the event loop free:

```javascript
const result = await sandbox.runAsync("echo", ["hello"]);
const piped = await sandbox.runWithInputAsync("cat", [], Buffer.from("hi"));
```

The thread pool has 4 threads by default (`UV_THREADPOOL_SIZE`), so more
concurrent runs than that queue behind each other.

See the [main README](https://github.com/Erio-Harrison/nanosandbox#readme) for the full API.

## Building from source

Only needed if you're changing the binding itself -- end users want `npm install nanosandbox` above, which installs a prebuilt binary.

```bash
npm install
npm run build
npm test
```
