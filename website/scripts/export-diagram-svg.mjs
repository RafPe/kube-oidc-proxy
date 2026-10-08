// Re-export an archify diagram as a standalone SVG by driving the viewer's
// own "Download SVG" action in headless Chrome. Usage, from website/:
//
//   node scripts/export-diagram-svg.mjs <diagram.html> <out.svg> [svg|svg-light|svg-dark]
//
// The <diagram.html> is produced by `archify finalize` from the
// *.archify.json next to each committed SVG (see docs/development.md).
import puppeteer from 'puppeteer-core';
import { mkdirSync, readdirSync, renameSync } from 'node:fs';
import path from 'node:path';
const [html, outFile, format = 'svg'] = process.argv.slice(2);
const dl = path.resolve(path.dirname(outFile), '.dl'); mkdirSync(dl, { recursive: true });
const b = await puppeteer.launch({ executablePath: process.env.CHROME_PATH ?? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', headless: true, args: ['--no-sandbox'] });
const p = await b.newPage(); await p.setViewport({ width: 1600, height: 1000 });
const client = await p.createCDPSession();
await client.send('Browser.setDownloadBehavior', { behavior: 'allow', downloadPath: dl, eventsEnabled: true });
await p.goto('file://' + path.resolve(html), { waitUntil: 'networkidle0' });
const done = new Promise((res) => client.on('Browser.downloadProgress', (e) => { if (e.state === 'completed') res(e); }));
await p.evaluate((f) => { const btn = document.querySelector(`.toolbar .export-menu button[data-format="${f}"]`); if (!btn) throw new Error('no export button ' + f); btn.click(); }, format);
await Promise.race([done, new Promise((_, rej) => setTimeout(() => rej(new Error('download timeout')), 15000))]);
const f = readdirSync(dl).find((n) => n.endsWith('.svg')); if (!f) throw new Error('no svg downloaded');
renameSync(path.join(dl, f), outFile); console.log('saved', outFile, f);
await b.close();
