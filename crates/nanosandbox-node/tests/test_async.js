const test = require('node:test');
const assert = require('node:assert');
const { Sandbox } = require('../index.js');

const sandbox = () => Sandbox.builder().workingDir('/tmp').wallTimeLimit(20).build();

test('runAsync resolves with the result', async () => {
  const result = await sandbox().runAsync('echo', ['hello']);
  assert.ok(result.success());
  assert.strictEqual(result.stdout.trim(), 'hello');
  assert.strictEqual(result.exitCode, 0);
});

test('runWithInputAsync pipes stdin', async () => {
  const result = await sandbox().runWithInputAsync('cat', [], Buffer.from('piped'));
  assert.strictEqual(result.stdout.trim(), 'piped');
});

test('a failing command still resolves, with its exit code', async () => {
  const result = await sandbox().runAsync('false', []);
  assert.ok(!result.success());
  assert.strictEqual(result.exitCode, 1);
});

test('a run that cannot start rejects', async () => {
  await assert.rejects(sandbox().runAsync('echo', ['a\0b']));
});

// The point of runAsync: the event loop keeps turning while the command runs.
// A synchronous run() holds the JS thread, so no timer fires until it ends.
test('the event loop stays free during a run', async () => {
  let ticks = 0;
  const timer = setInterval(() => ticks++, 20);
  const result = await sandbox().runAsync('sleep', ['1']);
  clearInterval(timer);
  assert.ok(result.success());
  // ~50 ticks expected in a second; a blocked loop gets 0 or 1.
  assert.ok(ticks >= 20, `only ${ticks} ticks while the run was in flight`);
});

test('runs overlap instead of queueing behind one another', async () => {
  const s = sandbox();
  const start = Date.now();
  const results = await Promise.all([1, 2, 3].map(() => s.runAsync('sleep', ['1'])));
  const elapsed = Date.now() - start;
  assert.ok(results.every((r) => r.success()));
  assert.ok(elapsed < 2500, `3 x 1s took ${elapsed}ms; they ran one after another`);
});
