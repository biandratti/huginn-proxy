#!/usr/bin/env node
import { mkdirSync, writeFileSync, existsSync, readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const out = join(dirname(fileURLToPath(import.meta.url)), '..', 'src/data/release-version.json');
const url = 'https://api.github.com/repos/biandratti/huginn-proxy/releases/latest';

let tag;
try {
	const res = await fetch(url, {
		headers: { Accept: 'application/vnd.github+json', 'User-Agent': 'huginn-proxy-docs' },
		signal: AbortSignal.timeout(10_000),
	});
	if (!res.ok) {
		throw new Error(`${res.status} ${res.statusText}`);
	}
	const json = await res.json();
	if (typeof json.tag_name !== 'string' || json.tag_name.length === 0) {
		throw new Error('empty tag_name');
	}
	tag = json.tag_name;
} catch (err) {
	console.warn(`fetch-release: failed to fetch latest release (${err.message}), using fallback`);
	// Use the existing cached value if available, otherwise fall back to a placeholder.
	if (existsSync(out)) {
		const cached = JSON.parse(readFileSync(out, 'utf8'));
		tag = cached.tag ?? 'latest';
		console.warn(`fetch-release: using cached tag ${tag}`);
	} else {
		tag = 'latest';
		console.warn('fetch-release: no cache found, using "latest"');
	}
}

mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, JSON.stringify({ tag }, null, '\t') + '\n');
console.log('fetch-release:', tag);
