#!/usr/bin/env node
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const out = join(dirname(fileURLToPath(import.meta.url)), '..', 'src/data/release-version.json');
const endpoint = 'https://api.github.com/repos/biandratti/huginn-proxy/releases/latest';

/** @type {{ tag: string | null, url: string | null }} */
const release = { tag: null, url: null };

try {
	const res = await fetch(endpoint, {
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
	if (typeof json.html_url !== 'string' || json.html_url.length === 0) {
		throw new Error('empty html_url');
	}
	release.tag = json.tag_name;
	release.url = json.html_url;
} catch (err) {
	console.warn(`fetch-release: ${err instanceof Error ? err.message : err}`);
}

mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, JSON.stringify(release, null, '\t') + '\n');
console.log('fetch-release:', release.tag ?? 'latest');
