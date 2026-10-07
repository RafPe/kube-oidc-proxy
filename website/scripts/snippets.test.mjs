// The landing page's values.yaml example must render with the real chart, so
// a reader who copies it gets what the page promises: a NetworkPolicy on the
// metrics port and a cert-manager Certificate from their own issuer.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import path from 'node:path';

function snippet(id) {
  const src = readFileSync(new URL('../src/components/landing/FeatureTabs.astro', import.meta.url), 'utf8');
  const start = src.indexOf(`<CodeBlock id="${id}"`);
  const body = src.slice(src.indexOf('set:html={`', start) + 'set:html={`'.length, src.indexOf('`}', start));
  return body.replace(/<[^>]+>/g, '').replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&').replace(/\\\\/g, '\\');
}

const helm = (() => { try { execFileSync('helm', ['version'], { stdio: 'ignore' }); return true; } catch { return false; } })();

test('values.yaml example renders a metrics NetworkPolicy and a cert-manager Certificate', { skip: !helm && 'helm not installed' }, () => {
  const dir = mkdtempSync(path.join(tmpdir(), 'snippet-'));
  const values = path.join(dir, 'values.yaml');
  writeFileSync(values, snippet('kop-values'));
  const chart = new URL('../../chart/kube-oidc-proxy', import.meta.url).pathname;
  const out = execFileSync('helm', ['template', 'kop', chart, '-f', values], { stdio: ['ignore', 'pipe', 'pipe'] }).toString();
  assert.match(out, /kind: NetworkPolicy/);
  assert.match(out, /kubernetes\.io\/metadata\.name: monitoring/);
  assert.match(out, /kind: Certificate/);
  assert.match(out, /name: internal-ca/);
  assert.doesNotMatch(out, /^kind: Issuer$/m, 'selfSigned: false must not create an Issuer');
  assert.match(out, /kind: PodDisruptionBudget/);
  assert.match(out, /userextras\/gha\.example\.com\/run_id/);
});

test('authentication-config example is the documented AuthenticationConfiguration shape', () => {
  const src = readFileSync(new URL('../src/components/landing/HowItWorks.astro', import.meta.url), 'utf8');
  const start = src.indexOf('set:html={`');
  const text = src.slice(start + 'set:html={`'.length, src.indexOf('`}', start)).replace(/<[^>]+>/g, '');
  assert.match(text, /^apiVersion: apiserver\.config\.k8s\.io\/v1$/m);
  assert.match(text, /^kind: AuthenticationConfiguration$/m);
  assert.equal((text.match(/^  - issuer:$/gm) || []).length, 2);
});
