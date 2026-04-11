#!/usr/bin/env node
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const out = join(dirname(fileURLToPath(import.meta.url)), '..', 'src/data/release-version.json');
const url = 'https://api.github.com/repos/biandratti/huginn-proxy/releases/latest';

const res = await fetch(url, {
	headers: { Accept: 'application/vnd.github+json', 'User-Agent': 'huginn-proxy-docs' },
});
if (!res.ok) {
	console.error(`fetch-release: ${res.status} ${res.statusText}`);
	process.exit(1);
}
const { tag_name: tag } = await res.json();
if (typeof tag !== 'string' || tag.length === 0) {
	console.error('fetch-release: empty tag_name');
	process.exit(1);
}
mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, JSON.stringify({ tag }, null, '\t') + '\n');
console.log('fetch-release:', tag);
