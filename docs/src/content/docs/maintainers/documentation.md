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

## Configure the trial Pages project

Create a **Cloudflare Pages** project and connect `crypt0rr/EdgeWatch` using
Git integration. Choose Pages explicitly in the Cloudflare dashboard.

For the initial trial, use these settings:

| Setting | Value |
| --- | --- |
| Production branch | `docs/website-preview` during the trial |
| Root directory | `docs` |
| Build command | `npm run build` |
| Build output directory | `dist` |
| `NODE_VERSION` | The exact version in the repository's `.node-version` |

The trial branch needs to be pushed before Cloudflare can build it. The
current `main` branch does not yet contain the website, so select the trial
branch for the initial deployment. Configure the same Node version for
production and preview environments, and restrict build watch paths to
`docs/*` and `.node-version` to avoid rebuilding for unrelated application changes.

This project generates a fully static site. It does not need a Cloudflare
runtime adapter, Pages Functions, a database, or EdgeWatch credentials.

Cloudflare provides a `*.pages.dev` address for the trial. The prototype emits
a `noindex, nofollow` meta tag even when the trial branch is treated as
production. Branch previews also receive Cloudflare's `X-Robots-Tag: noindex`
response header.

See Cloudflare's [Astro Pages guide](https://developers.cloudflare.com/pages/framework-guides/deploy-an-astro-site/),
[monorepo configuration](https://developers.cloudflare.com/pages/configuration/monorepos/),
and [preview deployment guide](https://developers.cloudflare.com/pages/configuration/preview-deployments/).

## Connect edgewatch.offsec.nl

After the preview has passed review:

1. In the Pages project, open **Custom domains** and add `edgewatch.offsec.nl`.
2. If `offsec.nl` is managed in the same Cloudflare account, complete the
   suggested DNS setup. Otherwise, create a CNAME at your DNS provider for
   `edgewatch`, pointing to the project's `<project>.pages.dev` address.
3. Wait for Cloudflare to activate the domain and certificate, then verify
   HTTPS, deep page URLs, search, theme switching, and the 404 page.

Register the hostname in Pages before creating the CNAME; DNS alone does not
associate the domain with the project. A subdomain can use DNS hosted outside
Cloudflare. See the [custom domain documentation](https://developers.cloudflare.com/pages/configuration/custom-domains/).

The documentation hostname serves public static guides. Application listener
and reverse-proxy settings belong to each EdgeWatch deployment.

## Promote the documentation

Before merging the trial:

- Review the migrated guides against the release and verify commands and links.
- Keep the root README as the overview and quick start. Detailed guidance belongs
  in `docs/src/content/docs/`; retain the root security policy and license files.
- Change the edit-link branch in `astro.config.mjs` and repository source links
  in content from `docs/website-preview` to `main`.
- Replace the root README’s temporary source links with the live guide URLs.
- Remove the preview banner and prototype `noindex` meta tag.

Once the website is merged, change the Pages production branch to `main` and
use other branches for previews. Publish release-specific compatibility notes
with the related code changes. Full documentation versioning can be added
later if multiple supported releases need separate manuals.
