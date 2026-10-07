import { defineConfig } from 'astro/config'
import starlight from '@astrojs/starlight'

export default defineConfig({
  site: 'https://edgewatch.offsec.nl',
  output: 'static',
  trailingSlash: 'always',
  devToolbar: { enabled: false },
  integrations: [
    starlight({
      title: 'EdgeWatch',
      description: 'Deploy, operate, and develop the EdgeWatch network-surface monitor.',
      logo: { src: './public/favicon.svg', replacesTitle: false },
      favicon: '/favicon.svg',
      social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/crypt0rr/EdgeWatch' }],
      editLink: { baseUrl: 'https://github.com/crypt0rr/EdgeWatch/edit/main/docs/' },
      customCss: [
        '@fontsource/inter/400.css',
        '@fontsource/inter/600.css',
        '@fontsource/inter/700.css',
        './src/styles/edgewatch.css',
      ],
      components: {
        Footer: './src/components/DocsFooter.astro',
        Header: './src/components/HomeHeader.astro',
        PageSidebar: './src/components/DocsPageSidebar.astro',
        ThemeProvider: './src/components/ThemeProvider.astro',
        ThemeSelect: './src/components/ThemeToggle.astro',
        Hero: './src/components/HomeHero.astro',
      },
      sidebar: [
        { label: 'Documentation', link: '/' },
        {
          label: 'Getting started',
          collapsed: true,
          items: [
            { label: 'Install with Docker', slug: 'getting-started/installation' },
            { label: 'Your first scan', slug: 'getting-started/first-scan' },
          ],
        },
        {
          label: 'Deployment',
          collapsed: true,
          items: [
            { label: 'Updates and rollback', slug: 'deployment/updates' },
            { label: 'Reverse proxies', slug: 'deployment/reverse-proxies' },
            { label: 'Container hardening', slug: 'deployment/container-hardening' },
          ],
        },
        {
          label: 'User guide',
          collapsed: true,
          items: [
            { label: 'Scanning and profiles', slug: 'user-guide/scanning' },
            { label: 'Jobs, baselines, and incidents', slug: 'user-guide/jobs-baselines-incidents' },
            { label: 'Notifications', slug: 'user-guide/notifications' },
          ],
        },
        {
          label: 'Administration',
          collapsed: true,
          items: [
            { label: 'Accounts and public status', slug: 'administration/accounts-public-status' },
            { label: 'Business units', slug: 'administration/business-units' },
            { label: 'Security', slug: 'administration/security' },
          ],
        },
        {
          label: 'Operations',
          collapsed: true,
          items: [
            { label: 'Backup and recovery', slug: 'operations/backup-recovery' },
            { label: 'Troubleshooting', slug: 'operations/troubleshooting' },
          ],
        },
        {
          label: 'Reference',
          collapsed: true,
          items: [
            { label: 'Deployment configuration', slug: 'reference/configuration' },
            { label: 'Host commands', slug: 'reference/cli' },
            { label: 'Database compatibility', slug: 'reference/database-compatibility' },
            { label: 'API compatibility', slug: 'reference/api-compatibility' },
            { label: 'License and source code', slug: 'reference/license' },
          ],
        },
        {
          label: 'Maintainers',
          collapsed: true,
          items: [
            { label: 'Local development', slug: 'maintainers/development' },
            { label: 'Architecture and contributing', slug: 'maintainers/contributing' },
            { label: 'Documentation and hosting', slug: 'maintainers/documentation' },
          ],
        },
      ],
      expressiveCode: {
        themes: ['github-dark', 'github-light'],
        styleOverrides: { borderRadius: '0.65rem' },
      },
    }),
  ],
})
