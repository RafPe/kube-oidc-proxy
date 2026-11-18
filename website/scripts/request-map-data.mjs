import { readFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import content from '../src/components/interactive/request-content.cjs';

export function requestMapData() {
  const root = execFileSync('git', ['rev-parse', '--show-toplevel'], { encoding: 'utf8' }).trim();
  const data = structuredClone(content);
  for (const node of Object.values(data.nodes)) {
    for (const ref of node.refs) {
      const lines = readFileSync(resolve(root, ref.file), 'utf8').split('\n');
      const matches = lines.filter(line => line.includes(ref.anchor));
      if (matches.length !== 1) throw new Error(`Source anchor must match once: ${ref.file}: ${ref.anchor}`);
    }
    // Keep implementation references in the build checks, outside the public page data.
    delete node.refs;
    delete node.change;
    delete node.tests;
  }
  return data;
}
