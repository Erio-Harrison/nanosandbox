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

See the [main README](https://github.com/Erio-Harrison/nanosandbox#readme) for the full API.

## Building from source

```bash
npm install
npm run build
node --test tests/
```
