// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import { unified } from '@astrojs/markdown-remark';
import starlightGithubAlerts from 'starlight-github-alerts';
import mermaid from 'astro-mermaid';
import { readFileSync } from 'node:fs';
import { sidebarFromManifest } from './scripts/sidebar.mjs';

const manifest = JSON.parse(readFileSync(new URL('./site.manifest.json', import.meta.url), 'utf8'));

// `site` and `base` are overridden in CI with --site/--base from
// actions/configure-pages, so a custom domain later needs no code change.
export default defineConfig({
  site: 'https://rafpe.github.io',
  base: '/kube-oidc-proxy',
  trailingSlash: 'always',
  markdown: {
    // Astro 7 defaults to Sätteri; the GitHub-alerts plugin needs remark.
    processor: unified(),
  },
  integrations: [
    mermaid({ theme: 'neutral', autoTheme: true }),
    starlight({
      title: 'kube-oidc-proxy',
      description: 'OIDC authentication for managed Kubernetes clusters, with multi-issuer support, via impersonation.',
      favicon: '/favicon.svg',
      logo: { src: './src/assets/logo.svg', alt: 'kube-oidc-proxy' },
      social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/RafPe/kube-oidc-proxy' }],
      editLink: { baseUrl: 'https://github.com/RafPe/kube-oidc-proxy/edit/main/' },
      lastUpdated: true,
      customCss: [
        '@fontsource-variable/bricolage-grotesque',
        '@fontsource/ibm-plex-sans/400.css',
        '@fontsource/ibm-plex-sans/500.css',
        '@fontsource/ibm-plex-sans/600.css',
        '@fontsource/ibm-plex-mono/400.css',
        '@fontsource/ibm-plex-mono/500.css',
        './src/styles/tokens.css',
        './src/styles/starlight.css',
        './src/styles/landing.css',
      ],
      components: {
        // Rendered only on pages that declare a hero, i.e. the landing page.
        Hero: './src/components/landing/Hero.astro',
        // Version line on every docs page.
        Banner: './src/components/overrides/Banner.astro',
        // Site title plus the Docs / Guides / Reference / Releases links.
        SiteTitle: './src/components/overrides/SiteTitle.astro',
      },
      // The docs use promql and logql fences, which Shiki does not ship; render
      // them as plain text instead of warning on every build.
      expressiveCode: { shiki: { langAlias: { promql: 'text', logql: 'text' } } },
      plugins: [starlightGithubAlerts()],
      sidebar: sidebarFromManifest(manifest),
      head: [
        { tag: 'meta', attrs: { property: 'og:image', content: 'https://rafpe.github.io/kube-oidc-proxy/social-card.png' } },
      ],
    }),
  ],
});
