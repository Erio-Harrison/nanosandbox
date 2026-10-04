const test = require('node:test');
const assert = require('node:assert');
const { Sandbox } = require('../index.js');

test('basic run', () => {
  const sandbox = Sandbox.builder().workingDir('/tmp').memoryLimit(64 * 1024 * 1024).build();
  const result = sandbox.run('echo', ['hello']);
  assert.ok(result.success());
  assert.strictEqual(result.stdout.trim(), 'hello');
  assert.strictEqual(result.exitCode, 0);
});

test('run with input', () => {
  const sandbox = Sandbox.builder().workingDir('/tmp').build();
  const result = sandbox.runWithInput('cat', [], Buffer.from('piped'));
  assert.strictEqual(result.stdout.trim(), 'piped');
});

test('failure reason', () => {
  const sandbox = Sandbox.builder().workingDir('/tmp').build();
  const result = sandbox.run('false', []);
  assert.ok(!result.success());
  assert.strictEqual(result.failureReason(), 'Exit code 1');
});

test('presets build', () => {
  const sandbox = Sandbox.codeJudge('/tmp').cpuTimeLimit(2).build();
  assert.ok(sandbox);
});

test('builder reuse after consume throws', () => {
  const b = Sandbox.builder();
  b.memoryLimit(10 * 1024 * 1024);
  assert.throws(() => b.workingDir('/tmp'));
});
