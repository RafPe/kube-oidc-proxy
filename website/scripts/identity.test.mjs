import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { evaluateIdentity, exampleDefaults, examples, bindingYaml } from '../src/components/interactive/identity-model.mjs';
const read = file => readFileSync(new URL(`../../${file}`,import.meta.url),'utf8');

test('Dex identities and bindings match the shipped demo manifests', () => {
  const config = read('demo/manifests/authentication-config.yaml.tpl');
  const bindings = read('demo/manifests/rbac.yaml');
  for(const id of ['alice','bob']) {
    const e = examples[id], result = evaluateIdentity({example:id});
    assert(bindings.includes(`name: "${e.username}"`));
    assert(bindings.includes(`name: ${e.binding}`));
    assert(config.includes(`prefix: "${e.username.split(':')[0]}:"`));
    assert(config.includes('claim: email'));
    assert.equal(result.allowed,true);
    assert.deepEqual(result.groups,['system:authenticated']);
    assert.equal(evaluateIdentity({example:id,resource:'secrets'}).allowed,false);
  }
});
test('GitHub identity and group binding match getting started', () => {
  const doc = read('docs/getting-started.md');
  const e = examples.github, result = evaluateIdentity({example:'github'});
  assert(doc.includes(e.username));
  for(const group of e.groups) assert(doc.includes(group));
  assert(doc.includes(`name: "${e.subject}"`));
  assert.equal(result.allowed,true);
  assert.equal(evaluateIdentity({example:'github',kind:'User'}).allowed,false);
  assert.equal(evaluateIdentity({example:'github',subject:'gha:repo:my-org/other'}).allowed,false);
});
test('ClusterRoleBinding spans namespaces while RoleBinding cannot grant an all-namespaces request', () => {
  for(const namespace of ['all','development','production']) assert.equal(evaluateIdentity({namespace}).allowed,true);
  assert.equal(evaluateIdentity({bindingScope:'namespace',namespace:'development'}).allowed,true);
  for(const namespace of ['all','production']) assert.equal(evaluateIdentity({bindingScope:'namespace',namespace}).allowed,false);
  assert.match(bindingYaml({bindingScope:'namespace'}),/kind: RoleBinding/);
  assert.match(bindingYaml({bindingScope:'namespace'}),/namespace: development/);
  assert.match(bindingYaml({bindingScope:'namespace'}),/kind: ClusterRole\n  name: view/);
});
test('default view permits pod reads, excludes Secrets and pod deletion', () => {
  for(const verb of ['get','list','watch']) assert.equal(evaluateIdentity({verb,namespace:'development'}).allowed,true);
  assert.equal(evaluateIdentity({verb:'delete',namespace:'development'}).allowed,false);
  assert.equal(evaluateIdentity({resource:'secrets'}).allowed,false);
});
test('caller grant, target grant and proxy grant are independent', () => {
  const doc = read('docs/authentication.md');
  assert(doc.includes('resourceNames: ["ci-viewer"]'));
  assert(doc.includes('name: "gha:repo:my-org/my-repo"'));
  const result = evaluateIdentity({example:'impersonation'});
  assert.equal(result.allowed,true);
  assert.equal(result.username,'ci-viewer');
  assert.deepEqual(result.groups,['system:authenticated']);
  for(const change of [{callerGrant:false},{target:'other-user'}]) {
    const denied = evaluateIdentity({example:'impersonation',...change});
    assert.equal(denied.forwarded,false);
    assert.match(denied.verdict,/Stopped at proxy/);
  }
  const proxyDenied = evaluateIdentity({example:'impersonation',proxyGrant:false});
  assert.equal(proxyDenied.forwarded,true);
  assert.equal(proxyDenied.allowed,false);
  assert.match(proxyDenied.verdict,/Rejected upstream/);
  assert.equal(evaluateIdentity({example:'impersonation',subject:'gha:repo:my-org/my-repo',kind:'Group'}).allowed,false);
  assert.equal(evaluateIdentity({callerGrant:false}).allowed,true);
});
test('preset reset restores the documented subject and scope', () => {
  for(const id of Object.keys(examples)) {
    const input = exampleDefaults(id);
    assert.equal(input.bindingScope,'cluster');
    assert.equal(evaluateIdentity(input).allowed,true);
    assert(bindingYaml(input).includes(examples[id].binding));
  }
});
