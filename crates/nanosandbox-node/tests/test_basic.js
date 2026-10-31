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

// Duration::from_secs_f64 panics on these, and a panic in a napi call aborts the process.
test('bad time limits throw instead of aborting the process', () => {
  for (const bad of [-1, 0, NaN, Infinity, -Infinity, 1e300]) {
    assert.throws(() => Sandbox.builder().wallTimeLimit(bad), { code: 'InvalidArg', message: /wallTimeLimit/ }, `wallTimeLimit(${bad})`);
    assert.throws(() => Sandbox.builder().cpuTimeLimit(bad), { code: 'InvalidArg', message: /cpuTimeLimit/ }, `cpuTimeLimit(${bad})`);
  }
  assert.ok(Sandbox.builder().wallTimeLimit(0.5).cpuTimeLimit(1).build());
});

// `f64 as u64` saturates: maxOutput(-1) would silently become 0 and drop all output.
test('byte and count limits reject what is not a whole non-negative number', () => {
  const setters = ['memoryLimit', 'maxOutput', 'maxFileSize', 'privateTmp', 'maxPids', 'maxOpenFiles'];
  for (const name of setters) {
    for (const bad of [-1, 1.5, NaN, Infinity, 2 ** 53]) {
      assert.throws(() => Sandbox.builder()[name](bad), { code: 'InvalidArg' }, `${name}(${bad})`);
    }
  }
  for (const name of ['maxPids', 'maxOpenFiles']) {
    assert.throws(() => Sandbox.builder()[name](2 ** 32), { code: 'InvalidArg' }, `${name}(2^32)`);
  }
  const sandbox = Sandbox.builder().workingDir('/tmp').maxOutput(1024).maxOpenFiles(256).build();
  assert.ok(sandbox.run('echo', ['still works']).success());
});

test('builder reuse after consume throws', () => {
  const b = Sandbox.builder();
  b.memoryLimit(10 * 1024 * 1024);
  assert.throws(() => b.workingDir('/tmp'));
});

test('sharedTmp(false) makes the hosts /tmp read-only on macOS', { skip: process.platform !== 'darwin' }, () => {
  const fs = require('node:fs');
  const probe = `/tmp/nsb-node-strict-${process.pid}`;
  const sandbox = Sandbox.builder().workingDir('/tmp').sharedTmp(false).build();
  const result = sandbox.run('sh', ['-c', `echo hi > ${probe}; echo "tmp:$?"; echo hi > "$TMPDIR/p"; echo "private:$?"`]);
  const leaked = fs.existsSync(probe);
  if (leaked) fs.unlinkSync(probe);
  assert.ok(!leaked);
  assert.ok(result.stdout.includes('tmp:1') && result.stdout.includes('private:0'), result.stdout);
});
