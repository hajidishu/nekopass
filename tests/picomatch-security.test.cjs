const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const { createRequire } = require('node:module');
const { spawnSync } = require('node:child_process');

// Run from web or docs so this covers the build tool's installed dependency.
const projectRequire = createRequire(path.resolve('package.json'));
const modulePath = projectRequire.resolve('picomatch');
const pm = projectRequire('picomatch');

test('build glob patterns retain ordinary matching semantics', () => {
  const matches = [
    ['src/views/AdminView.vue', 'src/**/*.{ts,vue}'],
    ['guide/nodes.md', '**/*.md'],
    ['file2.js', 'file[0-9].js'],
    ['foo.js', '@(foo|bar).js'],
    ['file.ts', '!**/*.js'],
    ['src\\views\\AdminView.vue', '**/*.vue', { windows: true }],
  ];
  for (const [input, pattern, options] of matches) {
    assert.equal(pm.isMatch(input, pattern, options), true, pattern);
  }
  assert.equal(pm.isMatch('src/index.js', '**/*.vue'), false);
  assert.equal(pm.isMatch('.secret.md', '*.md'), false);
});

test('repeated extglobs are literal even when upstream recursion guard is disabled', () => {
  for (const pattern of ['+(*a)', '*(*)', '+(*)', '*(*a)', '+(a|aa)']) {
    for (const options of [{}, { maxExtglobRecursion: false }, { maxExtglobRecursion: 0 }]) {
      assert.equal(pm.isMatch(pattern, pattern, options), true, pattern);
      assert.equal(pm.isMatch('a'.repeat(100) + '!', pattern, options), false, pattern);
    }
  }
});

test('advisory backtracking inputs finish within a bounded child process', () => {
  const result = spawnSync(process.execPath, ['-e', `
    const assert = require('node:assert/strict');
    const pm = require(process.argv[1]);
    for (const pattern of ['+(*a)', '*(*a)', '+(*)a', '*(*)a']) {
      for (const length of [40, 100, 1000]) {
        assert.equal(pm.isMatch('a'.repeat(length) + '!', pattern), false);
      }
    }
  `, modulePath], { encoding: 'utf8', timeout: 4000 });
  assert.ifError(result.error);
  assert.equal(result.status, 0, result.stderr);
});
