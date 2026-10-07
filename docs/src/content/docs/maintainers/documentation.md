---
title: Documentation and hosting
description: Write and validate the Starlight documentation and deploy it to Cloudflare Pages at edgewatch.offsec.nl.
---

The documentation website is an independent Astro Starlight project in the
repository's `docs/` directory. Its production URL is
`https://edgewatch.offsec.nl`.

## Run locally

Use the Node.js version in the repository's `.node-version`. From the repository root:

```sh
npm --prefix docs ci
npm --prefix docs run dev
```

Open **http://127.0.0.1:4321**. The documentation does not need a running Go
backend or a console build.

To validate and inspect the production output:

```sh
npm --prefix docs run build
npm --prefix docs run preview
```

The build type-checks Astro components, generates static HTML and the Pagefind
search index, and checks local links and fragment targets. Search is available
in the built preview; use that preview for acceptance testing.

## Add or edit a page

Write Markdown or MDX in `docs/src/content/docs/`. Each page needs `title` and
`description` frontmatter:

```md
---
title: Page title
description: A short description of what this page helps readers do.
---

## First section

Write the guide here.
```

Add the page to the sidebar in `docs/astro.config.mjs`. Use relative links or
site-root paths such as `/getting-started/installation/` for website pages.
Link to repository files on GitHub when they are not published website pages.

Place images in `docs/public/` or alongside content as supported by Astro.
Change the site theme in `docs/src/styles/edgewatch.css`. The theme starts dark,
and the header toggle saves the visitor's light or dark preference locally.
Fonts and search assets are served with the site.
The bundled Inter fonts retain their [Open Font License](/inter-license.txt).

Generated `docs/dist/`, `docs/.astro/`, and `node_modules/` are ignored and
must not be committed. Commit the documentation package and lockfile together.

## Required documentation updates

Update the affected guides in the same pull request whenever new features or
changes affect documented behavior. Build the documentation, review the branch
preview, and verify the website deployment after merging. This is mandatory;
see [contribution requirements](/maintainers/contributing/#required-documentation-updates).

## Cloudflare Pages settings

The `edgewatch-cpd` Pages project connects to `crypt0rr/EdgeWatch` through Git
integration and deploys the public website from `main`.

| Setting | Value |
| --- | --- |
| Production branch | `main` |
| Framework preset | Astro |
| Root directory | `docs` |
| Build command | `npm run build` |
| Build output directory | `dist` |
| `NODE_VERSION` | The exact version in the repository's `.node-version` |

Configure the same Node version for production and preview environments.
Restrict build watch paths to `docs/*` and `.node-version` to avoid rebuilding
for unrelated application changes. Preserve branch deployments for reviewing
pull requests. The documentation workflow checks clean installation, dependency
advisories, types, generated pages, and local links before merging.

This is a fully static website. It requires no runtime adapter, Pages Functions,
database, or EdgeWatch credentials. Fonts, video, and search assets are served
with the site. The production site is indexable; Cloudflare marks branch
previews with an `X-Robots-Tag: noindex` response header.

See Cloudflare's [Astro guide](https://developers.cloudflare.com/pages/framework-guides/deploy-an-astro-site/),
[build image configuration](https://developers.cloudflare.com/pages/configuration/build-image/),
[build watch paths](https://developers.cloudflare.com/pages/configuration/build-watch-paths/),
and [preview deployments](https://developers.cloudflare.com/pages/configuration/preview-deployments/).

## Custom domain

Register `edgewatch.offsec.nl` in the project's **Custom domains** before
configuring DNS. If `offsec.nl` is managed in the same Cloudflare account,
complete the suggested DNS setup. Otherwise, create a CNAME for `edgewatch`
pointing to `edgewatch-cpd.pages.dev`. Use the project's stable address rather
than a deployment hash URL.

Wait for the domain and certificate to become active, then verify HTTPS,
deep page URLs, search, and the 404 page. DNS alone does not register the domain
with Pages. A subdomain can use DNS hosted outside Cloudflare.
See the [custom domain instructions](https://developers.cloudflare.com/pages/configuration/custom-domains/).

The documentation hostname serves public static guides. Application listener
and reverse-proxy settings belong to each EdgeWatch deployment.

## Review and deploy documentation changes

1. Update the guides alongside the implementation. Confirm they describe the
   intended EdgeWatch release; identify features requiring a newer release.
2. Use `.node-version`, install dependencies, and run the checks below from the
   repository root.
3. Review the built website and branch deployment, including changed pages,
   search results, links, keyboard navigation, and mobile layouts.
4. Require the documentation workflow and applicable repository CI checks to
   pass on the final pull request before merging into `main`.
5. Confirm Pages deploys the merged commit, then verify the production website.

```sh
npm --prefix docs ci
npm --prefix docs run build
npm --prefix docs audit --audit-level=high
./scripts/check-schema-docs.sh
git diff --check
git diff --cached --check
```

Review the diff for generated assets, unrelated changes, and credentials.
Investigate failed checks and new warnings. The known moderate build-tool
advisory and duplicate 404 route warning are described in `docs/README.md`.
A successful earlier preview does not replace validation of the final commit.

Production is built from `main`, so merge a documentation change only after
its preview passes; there is no separate launch step. Keep README links on
live `https://edgewatch.offsec.nl/` URLs, and edit links on `main`.

## Verify production

Run these checks against `https://edgewatch.offsec.nl`, rather than only a
hashed preview URL:

- Homepage and every guide return `200`; unknown URLs return the custom page
  with HTTP status `404`.
- Search results and section links work on desktop and mobile.
- Dark is the default, theme preferences persist, and video play/pause and
  reduced-motion behavior work.
- The preview notice is absent. Production has neither a `noindex` robots meta
  tag nor an `X-Robots-Tag: noindex` header; branch previews remain excluded.
- Canonical URLs and sitemap entries use `https://edgewatch.offsec.nl`.
- README guide links and **Edit page** links point to their intended destinations.
- HTTPS and the configured security headers work on the custom domain.

Record the deployed commit and URL that passed these checks. Announce a public
launch only after production verification passes. Confirm the next change
produces a branch preview and that merging updates the production website.

## Rollback

Record a working production deployment before changing production. If essential
navigation, search, or installation guidance breaks, restore that deployment
through Pages and correct the source in Git before deploying again. Keep the
custom-domain DNS in place.

Cloudflare can roll back to successful production deployments; preview
deployments are not rollback targets. See the [rollback instructions](https://developers.cloudflare.com/pages/configuration/rollbacks/).

Update guides with related code changes and publish release-specific
compatibility notes. Add documentation versioning when multiple supported
releases need separate manuals.
