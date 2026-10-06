# EdgeWatch documentation website

An Astro Starlight prototype for `https://edgewatch.offsec.nl`, developed on
`docs/website-preview`. Dark mode is the default, with a persistent light/dark
toggle. The site uses the console's palette, brand mark, and Inter typography.

From the repository root, using the Node version in `.node-version`:

```sh
npm --prefix docs ci
npm --prefix docs run dev
```

The site is served at `http://127.0.0.1:4321`. For the built preview, including
search:

```sh
npm --prefix docs run build
npm --prefix docs run preview
```

The website has its own package and lockfile; the application's npm commands
and embedded assets remain independent. The build runs `astro check`, generates
the static site and Pagefind search index, and verifies local links and anchors.

## Source layout

- `src/content/docs/`: published Markdown and MDX guides.
- `src/components/`: homepage, preview notice, and dark-default theme controls.
- `src/styles/edgewatch.css`: documentation theme.
- `public/`: favicon and Cloudflare Pages response headers.
- `scripts/check-links.mjs`: validation of generated local links and anchors.
- `astro.config.mjs`: site URL, sidebar, branding, and edit links.

`dist/`, `.astro/`, and `node_modules/` are generated and ignored.

## Landing page

The Product Showcase landing page places the headline and video side by side
on desktop and stacks them on smaller screens. It uses the
[repository's original 30-second video](https://github.com/user-attachments/assets/ddff32e8-617a-477f-b9b7-8681dbc25b82),
served locally from `public/media/`. The derived MP4 is about 2 MB, using H.264
at 1280 × 720 and AAC audio; `faststart` lets playback begin before the entire
file downloads. The poster is extracted at 12 seconds from the source.

The video starts muted and inline, with native controls hidden and a compact
play/pause button in its frame. Reduced-motion visitors get the poster and can start playback themselves. Leaving the video
or hiding the tab pauses it; returning resumes automatic playback unless the
visitor explicitly paused it. If autoplay is blocked, the play button remains
available. A failed media load exposes a link to the original video.

Regenerate the assets with FFmpeg from a downloaded original:

```sh
ffmpeg -i original.mp4 -vf scale=1280:-2 -c:v libx264 -preset slow \
  -crf 24 -pix_fmt yuv420p -c:a aac -b:a 96k -movflags +faststart \
  public/media/edgewatch-demo.mp4
ffmpeg -ss 12 -i original.mp4 -frames:v 1 -vf scale=1280:-2 \
  -q:v 3 public/media/edgewatch-demo-poster.jpg
```

Run those commands inside `docs/`.

## Dependency audit

`npm audit --audit-level=high` passes. The current lockfile reports ten moderate
entries from one [PostCSS selector-parser advisory](https://github.com/advisories/GHSA-rj75-hqrm-r3gf)
in Starlight's Expressive Code dependency chain. This dependency processes
trusted styles during the build; it is not an HTTP service in the generated
static site. The advisory excludes ordinary build-time use on trusted sources.
Track an upstream compatible fix rather than applying npm's suggested forced
downgrade of Starlight.

Astro currently reports a duplicate `/404` route warning for Starlight's custom
404 content. The higher-priority route generates `dist/404.html`, and the
built preview serves the verified custom page for unknown URLs.

## Cloudflare Pages

Use root directory `docs`, build command `npm run build`, output directory
`dist`, and `NODE_VERSION` matching the root `.node-version`.
Use `docs/website-preview` as the initial trial project's production branch;
`main` does not contain the site until this branch is merged.

The full local preview, Pages, DNS, and promotion instructions are in
[Documentation and hosting](src/content/docs/maintainers/documentation.md).
No deployment or DNS changes are performed by building this project.

## Documentation ownership

The user, operator, and maintainer guides now live in `src/content/docs/`.
The root README is the repository overview and quick start. `SECURITY.md`
remains the canonical security policy; license, notice, and agent-guide files
retain their repository roles.

The former `docs/container-hardening.md` and `docs/api-compatibility.md` are now
published under `deployment/container-hardening` and `reference/api-compatibility`.
The schema check reads `reference/database-compatibility.md` and the root
security policy. Update those sources together when migrations change.

The site remains marked as a preview and emits `noindex, nofollow`. Before
production, switch edit links and repository source links from
`docs/website-preview` to `main`, remove the preview banner and `noindex` meta
tag, and change the Pages production branch to `main` after merging.
