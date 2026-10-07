// Stage repository markdown into Starlight's content folder.
//
// Reads site.manifest.json, copies every listed source into outDir with
// frontmatter derived from the file (title from the H1, description from the
// first paragraph, editUrl), rewrites relative links to site routes or GitHub
// URLs, and copies referenced images into imgDir. Fails loudly on anything it
// cannot resolve so a broken link never reaches the published site.
import { readFileSync, writeFileSync, mkdirSync, existsSync, copyFileSync, statSync, readdirSync, rmSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const GITHUB = 'https://github.com/RafPe/kube-oidc-proxy';
const IMAGE_EXT = new Set(['.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp']);

export function stage({ repoRoot, manifestPath, outDir, imgDir }) {
  const manifest = JSON.parse(readFileSync(manifestPath, 'utf8'));
  const bySource = new Map(manifest.pages.map((p) => [p.source, p]));

  checkCoverage(repoRoot, manifest, bySource);

  // Start from empty output so a removed or renamed page, or an image no
  // page references any more, cannot linger from a previous run.
  rmSync(outDir, { recursive: true, force: true });
  rmSync(imgDir, { recursive: true, force: true });

  const pages = manifest.pages.map((page) => {
    const abs = path.join(repoRoot, page.source);
    if (!existsSync(abs)) throw new Error(`stage: source ${page.source} does not exist`);
    const raw = readFileSync(abs, 'utf8');
    // A manifest `title` wins over the H1; the H1 then stays in the body as a
    // section heading (CHANGELOG.md starts with "# Unreleased").
    const { title, body } = page.title ? { title: page.title, body: demoteH1(raw) } : splitTitle(raw, page.source);
    const outFile = path.join(outDir, `${page.route}.md`);
    const rewritten = rewrite(body, { page, abs, repoRoot, bySource, outFile, imgDir });
    const fm = frontmatter({ title, description: describe(rewritten), editUrl: `${GITHUB}/edit/main/${page.source}`, order: page.order, lastUpdated: lastUpdated(repoRoot, page.source) });
    mkdirSync(path.dirname(outFile), { recursive: true });
    writeFileSync(outFile, `${fm}\n${rewritten}`);
    return { route: page.route, title, group: page.group, label: page.label, order: page.order, source: page.source };
  });
  return { pages };
}

function checkCoverage(repoRoot, manifest, bySource) {
  const docsDir = path.join(repoRoot, 'docs');
  if (!existsSync(docsDir)) return;
  const exclude = manifest.exclude ?? [];
  const excluded = (rel) => exclude.some((e) => (e.endsWith('/') ? rel.startsWith(e) : rel === e));
  for (const rel of walk(docsDir, repoRoot)) {
    if (!rel.endsWith('.md')) continue;
    if (bySource.has(rel) || excluded(rel)) continue;
    throw new Error(`stage: ${rel} is not in site.manifest.json and not excluded; add it to a sidebar group or to "exclude"`);
  }
}

function* walk(dir, repoRoot) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const abs = path.join(dir, entry.name);
    if (entry.isDirectory()) yield* walk(abs, repoRoot);
    else yield path.relative(repoRoot, abs).split(path.sep).join('/');
  }
}

function splitTitle(raw, source) {
  const m = raw.match(/^# (.+)$/m);
  if (!m) throw new Error(`stage: ${source} has no H1 to use as the page title`);
  const body = raw.slice(0, m.index) + raw.slice(m.index + m[0].length).replace(/^\n+/, '');
  return { title: m[1].trim(), body };
}

function demoteH1(raw) {
  return raw.replace(/^# /gm, '## ');
}

// The source's last commit date, so Starlight can show "Last updated" for
// staged files, which are not themselves tracked by git. Undefined when the
// repository has no history for the file.
function lastUpdated(repoRoot, source) {
  try {
    const iso = execFileSync('git', ['-C', repoRoot, 'log', '-1', '--format=%cI', '--', source], { stdio: ['ignore', 'pipe', 'ignore'] }).toString().trim();
    return iso ? iso.slice(0, 10) : undefined;
  } catch {
    return undefined;
  }
}

function describe(body) {
  const lines = body.split('\n');
  let para = [];
  for (const line of lines) {
    const t = line.trim();
    if (t === '') { if (para.length) break; continue; }
    if (/^(#|-|\*|\||>|!|```|<|\d+\.)/.test(t)) { if (para.length) break; continue; }
    para.push(t);
  }
  let text = para.join(' ')
    .replace(/!\[[^\]]*\]\([^)]*\)/g, '')
    .replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
    .replace(/[`*_]/g, '')
    .replace(/\s+/g, ' ')
    .trim();
  if (text.length > 160) text = text.slice(0, 157).replace(/\s+\S*$/, '') + '...';
  return text;
}

function frontmatter({ title, description, editUrl, order, lastUpdated }) {
  const q = (s) => JSON.stringify(s);
  const lines = ['---', `title: ${q(title)}`];
  if (description) lines.push(`description: ${q(description)}`);
  lines.push(`editUrl: ${q(editUrl)}`);
  if (lastUpdated) lines.push(`lastUpdated: ${lastUpdated}`);
  lines.push('sidebar:', `  order: ${order}`, '---');
  return lines.join('\n');
}

// Rewrites markdown link and image targets. Only the ](target) form is
// handled; the docs do not use raw HTML links.
function rewrite(body, ctx) {
  return body.replace(/(!?)\[([^\]]*)\]\(([^)\s]+)((?:\s+"[^"]*")?)\)/g, (whole, bang, text, target, titlePart) => {
    if (/^(https?:|mailto:|#)/i.test(target)) return whole;
    const [file, fragment = ''] = target.split('#');
    const resolvedAbs = path.resolve(path.dirname(ctx.abs), file);
    const rel = path.relative(ctx.repoRoot, resolvedAbs).split(path.sep).join('/');
    if (!existsSync(resolvedAbs)) {
      throw new Error(`stage: ${ctx.page.source} links to ${target}, which does not exist`);
    }
    const frag = fragment ? `#${fragment}` : '';
    if (bang === '!' || IMAGE_EXT.has(path.extname(file).toLowerCase())) {
      const dest = path.join(ctx.imgDir, rel);
      mkdirSync(path.dirname(dest), { recursive: true });
      copyFileSync(resolvedAbs, dest);
      const relPath = path.relative(path.dirname(ctx.outFile), dest).split(path.sep).join('/');
      return `${bang}[${text}](${relPath}${titlePart})`;
    }
    const page = ctx.bySource.get(rel);
    if (page) {
      const from = `/${ctx.page.route}`;
      const to = `/${page.route}`;
      const relRoute = path.posix.relative(from, to);
      return `[${text}](${relRoute}/${frag}${titlePart})`;
    }
    const kind = statSync(resolvedAbs).isDirectory() ? 'tree' : 'blob';
    return `[${text}](${GITHUB}/${kind}/main/${rel}${frag}${titlePart})`;
  });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const website = path.resolve(here, '..');
  const { pages } = stage({
    repoRoot: path.resolve(website, '..'),
    manifestPath: path.join(website, 'site.manifest.json'),
    outDir: path.join(website, 'src/content/docs'),
    imgDir: path.join(website, 'src/assets/img'),
  });
  console.log(`stage: wrote ${pages.length} pages`);
}
