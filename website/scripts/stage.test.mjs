import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { stage } from './stage.mjs';
import { execFileSync as _execFileSync } from 'node:child_process';

let root, manifestPath, outDir, imgDir;

function write(rel, content) {
  const p = path.join(root, rel);
  mkdirSync(path.dirname(p), { recursive: true });
  writeFileSync(p, content);
}

function manifest(pages, exclude = ['docs/testing/']) {
  writeFileSync(manifestPath, JSON.stringify({ exclude, groups: ['Start', 'Guides'], pages }));
}

const basePages = [
  { source: 'docs/getting-started.md', route: 'start/getting-started', group: 'Start', label: 'Getting started', order: 1 },
  { source: 'docs/operations.md', route: 'guides/operations', group: 'Guides', label: 'Operations', order: 1 },
];

beforeEach(() => {
  root = mkdtempSync(path.join(tmpdir(), 'stage-'));
  manifestPath = path.join(root, 'site.manifest.json');
  outDir = path.join(root, 'out');
  imgDir = path.join(root, 'img');
  write('docs/getting-started.md', '# Getting started\n\nThe complete first [installation](./operations.md#first-checks) with `helm`.\n\n## Prerequisites\n\nSee [checks](#prerequisites) and [events](../pkg/logging/events.go).\n\n![ctx](./c4/diagrams/ctx.png)\n');
  write('docs/operations.md', '# Operations\n\n## First checks\n\nBack to [start](./getting-started.md).\n');
  write('docs/c4/diagrams/ctx.png', 'png');
  write('pkg/logging/events.go', 'package logging');
  manifest(basePages);
});

afterEach(() => rmSync(root, { recursive: true, force: true }));

function run(extra = {}) {
  return stage({ repoRoot: root, manifestPath, outDir, imgDir, ...extra });
}

function staged(route) {
  return readFileSync(path.join(outDir, `${route}.md`), 'utf8');
}

test('lifts the H1 into frontmatter title and removes it from the body', () => {
  run();
  const out = staged('start/getting-started');
  assert.match(out, /^---\ntitle: "Getting started"\n/);
  assert.doesNotMatch(out, /^# Getting started$/m);
});

test('description is the first paragraph, plain text, at most 160 characters', () => {
  write('docs/operations.md', '# Operations\n\n' + 'word '.repeat(60) + '\n');
  run();
  const out = staged('guides/operations');
  const m = out.match(/^description: "(.*)"$/m);
  assert.ok(m, 'description present');
  assert.ok(m[1].length <= 160, `too long: ${m[1].length}`);
  const gs = staged('start/getting-started');
  assert.match(gs, /^description: "The complete first installation with helm\."$/m);
});

test('frontmatter carries editUrl to the source on GitHub and the sidebar order', () => {
  run();
  const out = staged('start/getting-started');
  assert.match(out, /^editUrl: "https:\/\/github\.com\/RafPe\/kube-oidc-proxy\/edit\/main\/docs\/getting-started\.md"$/m);
  assert.match(out, /^sidebar:\n  order: 1$/m);
});

test('a link to an in-manifest file becomes a relative route link and keeps the fragment', () => {
  run();
  assert.match(staged('start/getting-started'), /\[installation\]\(\.\.\/\.\.\/guides\/operations\/#first-checks\)/);
  assert.match(staged('guides/operations'), /\[start\]\(\.\.\/\.\.\/start\/getting-started\/\)/);
});

test('a link to a repo file with no page becomes a GitHub blob URL', () => {
  run();
  assert.match(staged('start/getting-started'), /\[events\]\(https:\/\/github\.com\/RafPe\/kube-oidc-proxy\/blob\/main\/pkg\/logging\/events\.go\)/);
});

test('a same-page fragment link is left alone', () => {
  run();
  assert.match(staged('start/getting-started'), /\[checks\]\(#prerequisites\)/);
});

test('images are copied into imgDir and rewritten to a relative asset path', () => {
  run();
  assert.ok(existsSync(path.join(imgDir, 'docs/c4/diagrams/ctx.png')));
  assert.match(staged('start/getting-started'), /!\[ctx\]\(\.\.\/\.\.\/img\/docs\/c4\/diagrams\/ctx\.png\)/);
});

test('returns the staged pages in manifest order', () => {
  const { pages } = run();
  assert.deepEqual(pages.map((p) => p.route), ['start/getting-started', 'guides/operations']);
  assert.equal(pages[0].title, 'Getting started');
});

test('throws naming a missing source', () => {
  manifest([...basePages, { source: 'docs/missing.md', route: 'x', group: 'Start', label: 'x', order: 2 }]);
  assert.throws(() => run(), /docs\/missing\.md/);
});

test('throws when a source has no H1', () => {
  write('docs/operations.md', 'no heading here\n');
  assert.throws(() => run(), /docs\/operations\.md.*H1/);
});

test('throws naming file and link when a relative link cannot be resolved', () => {
  write('docs/operations.md', '# Operations\n\n[gone](./nope.md)\n');
  assert.throws(() => run(), /docs\/operations\.md.*\.\/nope\.md/);
});

test('throws naming a docs file that is neither in the manifest nor excluded', () => {
  write('docs/stray.md', '# Stray\n');
  assert.throws(() => run(), /docs\/stray\.md/);
  write('docs/testing/x.tdd.md', '# x\n');
  manifest(basePages, ['docs/testing/', 'docs/stray.md']);
  assert.doesNotThrow(() => run());
});

test('a first paragraph that starts with inline code is still the description', () => {
  write('docs/operations.md', '# Operations\n\n`kube-oidc-proxy` is a reverse proxy.\n\n```sh\nignored\n```\n');
  run();
  assert.match(staged('guides/operations'), /^description: "kube-oidc-proxy is a reverse proxy\."$/m);
});

test('a manifest title overrides the H1, which then stays in the body as a heading', () => {
  write('CHANGELOG.md', '# Unreleased\n\n- pending\n\n## [1.8.1] - 2026-09-13\n\n- fixed\n');
  manifest([...basePages, { source: 'CHANGELOG.md', route: 'project/changelog', group: 'Guides', label: 'Changelog', order: 9, title: 'Changelog' }]);
  run();
  const out = staged('project/changelog');
  assert.match(out, /^title: "Changelog"$/m);
  assert.match(out, /^## Unreleased$/m);
  assert.match(out, /^## \[1\.8\.1\]/m);
});

test('lastUpdated comes from the git commit date of the source when the repo has history', () => {
  const { execFileSync } = require_child();
  const git = (...a) => execFileSync('git', ['-C', root, ...a], { stdio: 'pipe', env: { ...process.env, GIT_AUTHOR_NAME: 't', GIT_AUTHOR_EMAIL: 't@t', GIT_COMMITTER_NAME: 't', GIT_COMMITTER_EMAIL: 't@t', GIT_AUTHOR_DATE: '2026-09-13T10:00:00Z', GIT_COMMITTER_DATE: '2026-09-13T10:00:00Z' } });
  git('init', '-q'); git('add', '.'); git('commit', '-q', '-m', 'docs');
  run();
  assert.match(staged('start/getting-started'), /^lastUpdated: 2026-09-13$/m);
});

test('without git history lastUpdated is omitted rather than invented', () => {
  run();
  assert.doesNotMatch(staged('start/getting-started'), /^lastUpdated:/m);
});

function require_child() { return { execFileSync: _execFileSync }; }
