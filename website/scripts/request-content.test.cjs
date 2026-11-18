const { test } = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { resolve } = require('node:path');
const { nodes, scenarios } = require('../src/components/interactive/request-content.cjs');
const { paths } = require('../src/components/interactive/request-model.cjs');

test('every scenario and stage has teaching content and anchored source', async () => {
  const { requestMapData } = await import('./request-map-data.mjs');
  const publicData = requestMapData();
  assert.deepEqual(Object.keys(scenarios).sort(),Object.keys(paths).sort());
  assert.deepEqual([...new Set(Object.values(paths).flat())].sort(),Object.keys(nodes).sort());
  for (const node of Object.values(nodes)) {
    for (const field of ['title','tag','subtitle','summary','detail','input','output','change','tests']) assert(node[field],field);
    assert(node.refs.length);
    assert.equal(publicData.nodes[Object.keys(nodes).find(id => nodes[id] === node)].refs, undefined);
    for (const ref of node.refs) {
      const lines = readFileSync(resolve(__dirname,'../..',ref.file),'utf8').split('\n');
      assert.equal(lines.filter(line => line.includes(ref.anchor)).length, 1);
    }
  }
});
test('runtime middleware ordering still matches the mapped wrappers', () => {
  const handlers = readFileSync(resolve(__dirname,'../../pkg/proxy/handlers.go'),'utf8');
  const chain = handlers.slice(handlers.indexOf('func (p *Proxy) withFilterChain('));
  const body = chain.slice(0,chain.indexOf('\n}'));
  const wrappers = [...body.matchAll(/handler = (\S+)\(handler\)/g)].map(match=>match[1]).reverse();
  assert.deepEqual(wrappers,['p.withRequestID','p.auditor.WithRequestInfo','p.withRequestLifecycle','p.withSanitizedForwardHeaders','p.withAuthenticateRequest','p.withImpersonateRequest','p.auditor.WithRequest']);
});
