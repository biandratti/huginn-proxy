# Huginn Proxy documentation site (`gh-pages`)

This branch holds the **Astro** + [**Starlight**](https://starlight.astro.build/) static site published at:

**https://biandratti.github.io/huginn-proxy/**

The reverse proxy source code and crates live on the **`master`** branch.

## Local development

```bash
npm install
npm run dev
```

Build and preview the production bundle:

```bash
npm run build
npm run preview
```

The site uses `site` + `base` in [`astro.config.mjs`](astro.config.mjs) for GitHub Pages project URLs (`/huginn-proxy/`).

## Deployment

Workflow: [`.github/workflows/deploy.yml`](.github/workflows/deploy.yml). On push to `gh-pages`, the site is built with [`withastro/action`](https://github.com/withastro/action) and deployed with [`actions/deploy-pages`](https://github.com/actions/deploy-pages).

In the repository **Settings → Pages → Build and deployment**, set the source to **GitHub Actions** (not a legacy branch folder).
