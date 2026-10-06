import { readdir, readFile, stat } from 'node:fs/promises'
import { extname, join, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { parse } from 'parse5'

const output = fileURLToPath(new URL('../dist/', import.meta.url))
const origin = 'https://edgewatch.offsec.nl'
const pages = new Map()

async function collect(directory) {
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name)
    if (entry.isDirectory()) await collect(path)
    else if (extname(path) === '.html') {
      const ids = new Set()
      const links = []
      const visit = (node) => {
        const attrs = Object.fromEntries((node.attrs ?? []).map(({ name, value }) => [name, value]))
        if (attrs.id) ids.add(attrs.id)
        if (attrs.href) links.push(attrs.href)
        if (attrs.src) links.push(attrs.src)
        if (attrs.poster) links.push(attrs.poster)
        for (const child of node.childNodes ?? []) visit(child)
      }
      visit(parse(await readFile(path, 'utf8')))
      pages.set(path, { ids, links })
    }
  }
}

await collect(output)
if (!pages.size) throw new Error('No generated documentation pages found. Run astro build first.')

const failures = []
let checked = 0
for (const [page, { links }] of pages) {
  const pagePath = '/' + relative(output, page).split(sep).join('/')
  const pageUrl = new URL(pagePath.endsWith('/index.html') ? pagePath.slice(0, -10) : pagePath, origin)
  for (const link of links) {
    const url = new URL(link, pageUrl)
    // External websites, mailto:, and data: assets are outside this build.
    if (url.origin !== origin) continue
    checked++
    let error
    try {
      let target = resolve(output, '.' + decodeURIComponent(url.pathname))
      if (target !== resolve(output) && !target.startsWith(resolve(output) + sep)) {
        throw new Error('path escapes the output directory')
      }
      try {
        const info = await stat(target)
        if (info.isDirectory()) target = join(target, 'index.html')
      } catch (cause) {
        // Cloudflare Pages serves /404 and /404/ from 404.html, as well as
        // directory routes from index.html. Mirror its clean-URL lookup.
        if (cause.code !== 'ENOENT' || extname(target)) throw cause
        target = target.replace(/\/$/, '') + '.html'
      }
      await stat(target)
      if (url.hash && pages.has(target) && !pages.get(target).ids.has(decodeURIComponent(url.hash.slice(1)))) {
        error = 'missing anchor'
      }
    } catch (cause) {
      error = cause.code === 'ENOENT' ? 'missing file or page' : cause.message
    }
    if (error) failures.push(`${relative(output, page)}: ${link} (${error})`)
  }
}

if (failures.length) {
  console.error(failures.join('\n'))
  process.exitCode = 1
} else {
  console.log(`Verified ${checked} local links and assets across ${pages.size} documentation pages.`)
}
