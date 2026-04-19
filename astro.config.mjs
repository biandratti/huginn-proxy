// @ts-check
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

const __dirname = dirname(fileURLToPath(import.meta.url));
const { tag: releaseTag } = JSON.parse(
	readFileSync(join(__dirname, 'src/data/release-version.json'), 'utf8'),
);

const site = 'https://biandratti.github.io';
const base = '/huginn-proxy';

export default defineConfig({
	site,
	base,
	trailingSlash: 'always',
	redirects: {
		'/docs/deployment/': '/docs/containers/',
	},
	integrations: [
		starlight({
			components: {
				Footer: './src/components/Footer.astro',
			},
			title: 'Huginn Proxy',
			description:
				'High-performance reverse proxy with passive fingerprints via Huginn Net (MIT/Apache). Beta.',
			titleDelimiter: '·',
			tagline: releaseTag,
			logo: {
				src: './src/assets/huginn-proxy.png',
				alt: 'Huginn Proxy',
				replacesTitle: false,
			},
			social: [
				{
					icon: 'github',
					label: 'GitHub',
					href: 'https://github.com/biandratti/huginn-proxy',
				},
			],
			customCss: ['./src/styles/custom.css'],
			head: [
				{
					tag: 'link',
					attrs: {
						rel: 'preconnect',
						href: 'https://fonts.googleapis.com',
					},
				},
				{
					tag: 'link',
					attrs: {
						rel: 'preconnect',
						href: 'https://fonts.gstatic.com',
						crossorigin: 'anonymous',
					},
				},
				{
					tag: 'link',
					attrs: {
						rel: 'stylesheet',
						href: 'https://fonts.googleapis.com/css2?family=JetBrains+Mono:ital,wght@0,400;0,600;1,400&display=swap',
					},
				},
			],
			favicon: '/favicon.ico',
			lastUpdated: true,
			tableOfContents: { minHeadingLevel: 2, maxHeadingLevel: 4 },
			sidebar: [
				{
					label: 'Getting started',
					items: [
						{ label: 'Documentation', slug: 'docs' },
						{ label: 'Getting started', slug: 'docs/getting-started' },
						{ label: 'Quick start', slug: 'docs/quick-example' },
					],
				},
				{
					label: 'Concepts',
					items: [{ label: 'How it works', slug: 'docs/how-it-works' }],
				},
				{
					label: 'Configuration',
					items: [
						{ label: 'Overview', slug: 'docs/configuration' },
						{
							label: 'Static',
							collapsed: false,
							items: [
								{ label: 'Listen', slug: 'docs/listen' },
								{ label: 'Timeout', slug: 'docs/timeout' },
								{ label: 'TLS', slug: 'docs/tls' },
								{ label: 'Fingerprinting', slug: 'docs/fingerprinting' },
								{ label: 'Logging', slug: 'docs/logging' },
								{ label: 'Telemetry', slug: 'docs/telemetry' },
							],
						},
						{
							label: 'Dynamic',
							collapsed: false,
							items: [
								{ label: 'Backends', slug: 'docs/backends' },
								{ label: 'Routes', slug: 'docs/routes' },
								{ label: 'Security', slug: 'docs/security' },
								{ label: 'IP filtering', slug: 'docs/ip-filtering' },
								{ label: 'Rate limiting', slug: 'docs/rate-limiting' },
								{ label: 'Headers', slug: 'docs/headers' },
							],
						},
					],
				},
				{
					label: 'Deployment',
					items: [
						{ label: 'Artifacts', slug: 'docs/artifacts' },
						{ label: 'Containers', slug: 'docs/containers' },
						{ label: 'Kubernetes', slug: 'docs/kubernetes' },
						{ label: 'eBPF TCP setup', slug: 'docs/ebpf-setup' },
					],
				},
				{
					label: 'Project',
					items: [{ label: 'Architecture', slug: 'docs/architecture' }],
				},
			],
		}),
	],
});
