const { test } = require('node:test');
const assert = require('node:assert/strict');
const { paths } = require('../src/components/interactive/request-model.cjs');

test('normal requests follow runtime middleware order', () => {
  assert.deepEqual(paths.oidc, ['client','requestid','info','lifecycle','headers','auth','guard','impersonate','audit','reverse','transport','upstream','response']);
});
test('authentication branches stop or fall back at the correct point', () => {
  assert(!paths.missing.includes('review'));
  assert(!paths.missing.includes('upstream'));
  assert(paths.passthrough.indexOf('review') > paths.passthrough.indexOf('auth'));
  assert(!paths.passthrough.includes('guard'));
  assert(!paths.denied.includes('transport'));
  assert(paths.failure.includes('transport'));
  assert(!paths.failure.includes('upstream'));
  assert(paths.reserved.includes('guard'));
  assert(!paths.reserved.includes('impersonate'));
});
