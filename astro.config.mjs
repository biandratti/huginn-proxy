// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

const site = 'https://biandratti.github.io';
const base = '/huginn-proxy';

export default defineConfig({
	site,
	base,
	trailingSlash: 'always',
	integrations: [
		starlight({
			title: 'Huginn Proxy',
			description:
				'High-performance reverse proxy with passive fingerprints via Huginn Net (MIT/Apache). Beta.',
			titleDelimiter: '·',
			tagline: 'v0.0.3-beta',
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
			editLink: {
				baseUrl: 'https://github.com/biandratti/huginn-proxy/edit/gh-pages/',
			},
			lastUpdated: true,
			tableOfContents: { minHeadingLevel: 2, maxHeadingLevel: 4 },
			sidebar: [
				{
					label: 'Getting started',
					items: [
						{ label: 'Getting started', slug: 'docs/getting-started' },
						{ label: 'Quick example', slug: 'docs/quick-example' },
					],
				},
				{
					label: 'Core concepts',
					items: [
						{ label: 'How it works', slug: 'docs/how-it-works' },
						{ label: 'Fingerprinting', slug: 'docs/fingerprinting' },
						{ label: 'Routing', slug: 'docs/routing' },
					],
				},
				{
					label: 'Configuration',
					items: [
						{ label: 'Configuration reference', slug: 'docs/configuration' },
						{ label: 'Security', slug: 'docs/security' },
					],
				},
				{
					label: 'Observability',
					items: [{ label: 'Telemetry', slug: 'docs/telemetry' }],
				},
				{
					label: 'Deployment',
					items: [
						{ label: 'Deployment', slug: 'docs/deployment' },
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
