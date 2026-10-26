import { readdirSync, readFileSync } from 'node:fs'
import { join, relative } from 'node:path'
import { fileURLToPath } from 'node:url'
import { matchRoutes, type RouteObject } from 'react-router-dom'
import { parseSync } from 'vite'
import { describe, expect, it } from 'vitest'
import {
  allConsoleRoutes,
  consoleScopeRouters,
  entrySurfaces,
  routesWithoutInventoryEntry,
  type ConsoleRouteCase,
  type EntrySurfaceCase,
  type RouteExclusion,
} from '../e2e/console-routes'

// The browser audits (e2e/route-accessibility.spec.ts and
// e2e/role-matrix.spec.ts) visit only the pages that e2e/console-routes.ts
// lists. This check compares that inventory with the routers themselves, so
// a new page cannot skip the audit unnoticed and a removed page cannot leave
// an entry behind. It parses the JSX with the TypeScript parser that Vite
// ships instead of matching text, so formatting, attribute order, and
// conditional routes do not change what it reads.

const repositoryRoot = fileURLToPath(new URL('..', import.meta.url))
const sourceRoot = join(repositoryRoot, 'src')

/** The router APIs that this check reads as JSX. */
const routerModules = new Set(['react-router-dom', 'react-router'])
/** Router APIs that build routes outside JSX, which this check cannot read. */
const unreadRouterAPIs = new Set(['useRoutes', 'createBrowserRouter', 'createHashRouter', 'createMemoryRouter', 'createStaticRouter', 'createRoutesFromElements', 'createRoutesFromChildren', 'RouterProvider'])

/**
 * AppContent serves the public status pages from the address alone, before
 * any router or session read, so they have no `<Route>`. These patterns
 * stand for them.
 */
const publicStatusRoutes = ['/public', '/public/:slug']

/** The UnitDetail tabs, which /platform/units/:id/:tab selects. */
const unitDetailFile = 'src/pages/platform/UnitDetail.tsx'
const unitDetailTabsVariable = 'tabs'
const unitDetailTabParam = 'tab'

type Node = { type: string; [key: string]: unknown }

type SourceRoute = {
  /** As written; undefined for an index route. */
  path?: string
  index: boolean
  /** The components that its element renders, such as a descendant router. */
  renders: string[]
  children: SourceRoute[]
}

type SourceRouter = {
  /** The component that renders the `<Routes>`. */
  name: string
  routes: SourceRoute[]
}

type SourceFile = { file: string; code: string }

function isNode(value: unknown): value is Node {
  return typeof value === 'object' && value !== null && typeof (value as Node).type === 'string'
}

function childNodes(node: Node): Node[] {
  const result: Node[] = []
  for (const [key, value] of Object.entries(node)) {
    if (key === 'parent') continue
    if (Array.isArray(value)) result.push(...value.filter(isNode))
    else if (isNode(value)) result.push(value)
  }
  return result
}

function jsxName(node: Node): string | undefined {
  if (node.type !== 'JSXElement') return undefined
  const name = (node.openingElement as Node).name as Node
  return name.type === 'JSXIdentifier' ? String(name.name) : undefined
}

function jsxRouterMemberName(node: Node): string | undefined {
  if (node.type !== 'JSXElement') return undefined
  const name = (node.openingElement as Node).name as Node
  if (name.type !== 'JSXMemberExpression') return undefined
  const property = name.property as Node
  const member = property.type === 'JSXIdentifier' ? String(property.name) : undefined
  return member === 'Route' || member === 'Routes' ? member : undefined
}

function jsxAttribute(element: Node, name: string): Node | undefined {
  const attributes = (element.openingElement as Node).attributes as Node[]
  return attributes.find(attribute => attribute.type === 'JSXAttribute' && ((attribute.name as Node).name === name))
}

/** The components that a JSX expression renders, by name. */
function renderedComponents(node: Node | undefined): string[] {
  if (!node) return []
  const names: string[] = []
  const visit = (current: Node) => {
    const name = jsxName(current)
    if (name && /^[A-Z]/.test(name)) names.push(name)
    childNodes(current).forEach(visit)
  }
  visit(node)
  return names
}

function stringValue(node: Node | undefined, where: string): string {
  if (node?.type === 'Literal' && typeof node.value === 'string') return node.value
  if (node?.type === 'JSXExpressionContainer') return stringValue(node.expression as Node, where)
  if (node?.type === 'TemplateLiteral' && (node.expressions as Node[]).length === 0) return String(((node.quasis as Node[])[0].value as { cooked: string }).cooked)
  throw new Error(`${where} must be a string literal so the inventory check can read it`)
}

/**
 * Reads every `<Routes>` of the given sources, named by the component that
 * renders it, with its `<Route>` tree.
 */
function extractRouters(sources: SourceFile[]): SourceRouter[] {
  const routers: SourceRouter[] = []
  for (const { file, code } of sources) {
    const parsed = parseSync(file, code, { lang: file.endsWith('.tsx') ? 'tsx' : 'ts' })
    if (parsed.errors.length) throw new Error(`${file}: ${parsed.errors.map(error => error.message).join('; ')}`)
    const program = parsed.program as unknown as Node

    const local = { Route: new Set<string>(), Routes: new Set<string>() }
    for (const statement of program.body as Node[]) {
      if (statement.type !== 'ImportDeclaration' || !routerModules.has(String((statement.source as Node).value))) continue
      for (const specifier of statement.specifiers as Node[]) {
        if (specifier.type !== 'ImportSpecifier') throw new Error(`${file} uses ${specifier.type} from a router module; the console route inventory check requires named router imports so it can read every route`)
        const imported = String((specifier.imported as Node).name)
        const localName = String((specifier.local as Node).name)
        if (imported === 'Route' || imported === 'Routes') local[imported].add(localName)
        if (unreadRouterAPIs.has(imported)) throw new Error(`${file} imports ${imported}; the console route inventory check reads only <Routes> and <Route> elements, so declare routes as JSX or teach src/console-route-inventory.test.ts the new API`)
      }
    }

    const importedRouterAPI = (name: string) => local.Route.has(name) ? 'Route' : local.Routes.has(name) ? 'Routes' : undefined
    for (const statement of program.body as Node[]) {
      if (statement.type !== 'ExportNamedDeclaration' && statement.type !== 'ExportAllDeclaration') continue
      const source = statement.source as Node | null | undefined
      if (source && routerModules.has(String(source.value))) throw new Error(`${file} re-exports router APIs from ${String(source.value)}; the console route inventory check requires routes to be declared through named JSX imports`)
      if (source || statement.type !== 'ExportNamedDeclaration') continue
      for (const specifier of (statement.specifiers as Node[] | undefined) ?? []) {
        const localName = String((specifier.local as Node).name)
        const api = importedRouterAPI(localName)
        if (api) throw new Error(`${file} re-exports local ${localName}, imported as ${api}; the console route inventory check cannot follow router API re-exports`)
      }
    }

    const rejectRouterMemberElements = (node: Node) => {
      const api = jsxRouterMemberName(node)
      if (api) throw new Error(`${file} uses a JSX member expression ending in ${api}; the console route inventory check requires directly named <Route> and <Routes> elements`)
      childNodes(node).forEach(rejectRouterMemberElements)
    }
    rejectRouterMemberElements(program)
    if (!local.Route.size && !local.Routes.size) continue

    let routeElements = 0
    let collectedRoutes = 0
    const collect = (nodes: Node[], where: string): SourceRoute[] => {
      const routes: SourceRoute[] = []
      const visit = (node: Node) => {
        const name = jsxName(node)
        if (name && local.Route.has(name)) {
          collectedRoutes += 1
          const index = !!jsxAttribute(node, 'index')
          const pathAttribute = jsxAttribute(node, 'path')
          routes.push({
            path: pathAttribute ? stringValue(pathAttribute.value as Node, `A <Route> path in ${where} in ${file}`) : undefined,
            index,
            renders: renderedComponents(jsxAttribute(node, 'element')?.value as Node | undefined),
            children: collect(node.children as Node[], where),
          })
          return
        }
        // A nested <Routes> is its own router.
        if (name && local.Routes.has(name)) return
        childNodes(node).forEach(visit)
      }
      nodes.forEach(visit)
      return routes
    }

    const walk = (node: Node, component: string) => {
      let current = component
      if (node.type === 'FunctionDeclaration' && node.id) current = String((node.id as Node).name)
      if (node.type === 'VariableDeclarator' && (node.id as Node).type === 'Identifier' && /^[A-Z]/.test(String((node.id as Node).name))) current = String((node.id as Node).name)
      const name = jsxName(node)
      if (name && local.Route.has(name)) routeElements += 1
      if (name && local.Routes.has(name)) {
        if (!current) throw new Error(`${file}: a <Routes> outside a named component`)
        const count = routers.filter(router => router.name === current || router.name.startsWith(`${current}#`)).length
        routers.push({ name: count ? `${current}#${count + 1}` : current, routes: collect(node.children as Node[], current) })
      }
      childNodes(node).forEach(child => walk(child, current))
    }
    walk(program, '')
    if (routeElements !== collectedRoutes) throw new Error(`${file}: a <Route> is outside every <Routes>, which the console route inventory check cannot place`)
  }
  return routers
}

/** The values of the `key` properties in the array that `variable` names. */
function extractTabKeys(file: string, code: string, variable: string): string[] {
  const program = parseSync(file, code, { lang: 'tsx' }).program as unknown as Node
  let keys: string[] | undefined
  const visit = (node: Node) => {
    if (node.type === 'VariableDeclarator' && (node.id as Node).type === 'Identifier' && (node.id as Node).name === variable && (node.init as Node | null)?.type === 'ArrayExpression') {
      keys = ((node.init as Node).elements as Node[]).map(element => {
        const property = (element.properties as Node[] | undefined)?.find(item => item.type === 'Property' && ((item.key as Node).name === 'key' || (item.key as Node).value === 'key'))
        return stringValue(property?.value as Node | undefined, `Each tab key in ${variable} in ${file}`)
      })
      return
    }
    childNodes(node).forEach(visit)
  }
  visit(program)
  if (!keys) throw new Error(`${file}: no array named ${variable}; update the tab check in src/console-route-inventory.test.ts`)
  return keys
}

type RouteHandle = {
  /** The router that declares the route; a descendant router keeps its own name. */
  router: string
  /** The full path pattern; an index route adds "(index)" to its parent's. */
  pattern: string
  splat: boolean
}
type ResolvedRouter = { name: string; objects: RouteObject[]; handles: RouteHandle[] }

const label = (handle: RouteHandle) => `${handle.router} ${handle.pattern}`

function joinPattern(parent: string, path: string | undefined) {
  if (path === undefined) return parent || '/'
  if (path.startsWith('/') || !parent) return path
  return `${parent.replace(/\/$/, '')}/${path}`
}

/**
 * Builds a React Router route table for each router that no other router
 * mounts. A route whose element renders another router, such as
 * /jobs/new/* rendering JobCreationJourney, gets that router's routes as
 * its children, as React Router resolves descendant routes.
 */
function resolveRouters(routers: SourceRouter[]): ResolvedRouter[] {
  const byName = new Map(routers.map(router => [router.name, router]))
  const mounted = new Set<string>()

  const build = (declaring: string, routes: SourceRoute[], parent: string, handles: RouteHandle[], seen: Set<string>): RouteObject[] => routes.map(route => {
    const pattern = joinPattern(parent, route.path)
    const base = pattern.replace(/\/\*$/, '') || '/'
    const descendants = route.renders.filter(name => byName.has(name))
    const handle: RouteHandle = { router: declaring, pattern: route.index ? `${pattern} (index)` : pattern, splat: false }
    handles.push(handle)
    const children: RouteObject[] = build(declaring, route.children, base, handles, seen)
    for (const name of descendants) {
      if (seen.has(name)) throw new Error(`${name} renders itself through its routes`)
      mounted.add(name)
      children.push(...build(name, byName.get(name)!.routes, base, handles, new Set([...seen, name])))
    }
    handle.splat = !children.length && (route.path === '*' || !!route.path?.endsWith('/*'))
    if (route.index) return { index: true, handle }
    const path = descendants.length && route.path?.endsWith('/*') ? route.path.slice(0, -2) || '/' : route.path
    return { path, handle, children: children.length ? children : undefined }
  })

  const all = routers.map(router => {
    const handles: RouteHandle[] = []
    return { name: router.name, objects: build(router.name, router.routes, '', handles, new Set([router.name])), handles }
  })
  return all.filter(router => !mounted.has(router.name))
}

type InventoryEntry = { path: string; routers: string[]; redirectToHome: boolean; redirects: boolean; label: string }

function inventoryEntries(consoleRoutes: ConsoleRouteCase[], surfaces: EntrySurfaceCase[], scopeRouters: Record<ConsoleRouteCase['scope'], string[]>): InventoryEntry[] {
  return [
    ...consoleRoutes.map(route => ({ path: route.path, routers: scopeRouters[route.scope], redirectToHome: !!route.redirectToHome, redirects: !!route.redirectToHome || !!route.allowedPath, label: `${route.scope} ${route.path}` })),
    ...surfaces.map(surface => ({ path: new URL(surface.path, 'http://inventory.invalid').pathname, routers: [surface.router], redirectToHome: false, redirects: false, label: `${surface.router} ${surface.path}` })),
  ]
}

type Inventory = {
  consoleRoutes: ConsoleRouteCase[]
  surfaces: EntrySurfaceCase[]
  scopeRouters: Record<ConsoleRouteCase['scope'], string[]>
  exclusions: RouteExclusion[]
  tabKeys: string[]
}

/**
 * Every disagreement between the routers and the inventory, as messages
 * that say what to change. An empty list means they agree.
 */
function inventoryProblems(routers: ResolvedRouter[], inventory: Inventory): string[] {
  const problems: string[] = []
  const publicRouter: ResolvedRouter = { name: 'public', objects: [], handles: [] }
  for (const pattern of publicStatusRoutes) {
    const handle: RouteHandle = { router: 'public', pattern, splat: false }
    publicRouter.handles.push(handle)
    publicRouter.objects.push({ path: pattern, handle })
  }
  const all = [...routers, publicRouter]
  const byName = new Map(all.map(router => [router.name, router]))
  const handles = all.flatMap(router => router.handles)
  const covered = new Set<RouteHandle>()
  const tabs = new Set<string>()

  for (const entry of inventoryEntries(inventory.consoleRoutes, inventory.surfaces, inventory.scopeRouters)) {
    for (const name of entry.routers) {
      const router = byName.get(name)
      if (!router) { problems.push(`inventory entry ${entry.label} names router ${name}, which no <Routes> in src renders`); continue }
      const matches = matchRoutes(router.objects, entry.path)
      if (!matches) { problems.push(`inventory entry ${entry.label} matches no route of ${name}; remove it or restore its route`); continue }
      const leaf = matches.at(-1)!.route.handle as RouteHandle
      // Only a redirectToHome entry may stand for a shell's own catch-all; an
      // alias that a nested catch-all redirects, such as an unmatched
      // job-creation step, names where it lands in allowedPath.
      if (leaf.splat && !(leaf.pattern === '*' ? entry.redirectToHome : entry.redirects)) problems.push(`inventory entry ${entry.label} reaches only the catch-all ${label(leaf)}; remove it, restore its route, or mark the redirect`)
      if (!leaf.splat && entry.redirectToHome) problems.push(`inventory entry ${entry.label} is marked redirectToHome but reaches ${label(leaf)}`)
      for (const match of matches) covered.add(match.route.handle as RouteHandle)
      const tab = matches.at(-1)!.params[unitDetailTabParam]
      if (tab !== undefined && name === 'PlatformShell') tabs.add(tab)
    }
  }

  const excluded = new Set<RouteHandle>()
  for (const exclusion of inventory.exclusions) {
    if (!exclusion.reason.trim()) problems.push(`exclusion ${exclusion.router} ${exclusion.path} gives no reason`)
    const handle = handles.find(item => item.router === exclusion.router && item.pattern === exclusion.path)
    if (!handle) { problems.push(`exclusion ${exclusion.router} ${exclusion.path} names no route; remove it from routesWithoutInventoryEntry`); continue }
    if (covered.has(handle)) problems.push(`exclusion ${exclusion.router} ${exclusion.path} also has an inventory entry; remove one of them`)
    excluded.add(handle)
  }

  for (const handle of handles) {
    if (!covered.has(handle) && !excluded.has(handle)) problems.push(`route ${label(handle)} has no entry in e2e/console-routes.ts; add one so the axe audit and role matrix visit it, or exclude it with a reason in routesWithoutInventoryEntry`)
  }

  const tabRoute = byName.get('PlatformShell')?.handles.some(handle => handle.pattern.includes(`:${unitDetailTabParam}`))
  if (!tabRoute && inventory.tabKeys.length) problems.push(`PlatformShell has no route with :${unitDetailTabParam} for the UnitDetail tabs`)
  for (const key of inventory.tabKeys) {
    if (!tabs.has(key)) problems.push(`UnitDetail tab ${key} has no /platform/units/:id/${key} entry in e2e/console-routes.ts`)
  }
  for (const tab of tabs) {
    if (!inventory.tabKeys.includes(tab)) problems.push(`inventory entry /platform/units/:id/${tab} names no UnitDetail tab; remove it or restore the tab`)
  }
  return problems
}

function sourceFiles(directory = sourceRoot): SourceFile[] {
  const files: SourceFile[] = []
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name)
    const file = relative(repositoryRoot, path).split('\\').join('/')
    if (entry.isDirectory()) {
      if (file !== 'src/test' && file !== 'src/generated') files.push(...sourceFiles(path))
    } else if (/\.tsx?$/.test(entry.name) && !/\.test\.tsx?$/.test(entry.name) && !entry.name.endsWith('.d.ts')) {
      files.push({ file, code: readFileSync(path, 'utf8') })
    }
  }
  return files
}

const repositoryInventory: Inventory = {
  consoleRoutes: allConsoleRoutes,
  surfaces: entrySurfaces,
  scopeRouters: consoleScopeRouters,
  exclusions: routesWithoutInventoryEntry,
  tabKeys: extractTabKeys(unitDetailFile, readFileSync(join(repositoryRoot, unitDetailFile), 'utf8'), unitDetailTabsVariable),
}

describe('console route inventory', () => {
  const sources = sourceFiles()
  const routers = extractRouters(sources)
  const resolved = resolveRouters(routers)

  it('reads the routers that the console renders', () => {
    expect(resolved.map(router => router.name)).toEqual(expect.arrayContaining(['AuthRoutes', 'PlatformShell', 'Shell', 'TotpEnrollmentShell']))
    const shell = resolved.find(router => router.name === 'Shell')!
    // JobCreationJourney's routes are resolved under /jobs/new/*.
    expect(shell.handles.filter(handle => handle.router === 'JobCreationJourney').map(label)).toEqual(['JobCreationJourney /jobs/new (index)', 'JobCreationJourney /jobs/new/advanced', 'JobCreationJourney /jobs/new/*'])
    expect(repositoryInventory.tabKeys).toEqual(expect.arrayContaining(['overview', 'accounts', 'capacity', 'danger']))
  })

  it('lists every route and UnitDetail tab, and every entry still reaches its route', () => {
    expect(inventoryProblems(resolved, repositoryInventory)).toEqual([])
  })

  describe('the check itself', () => {
    const shell = (routes: string) => ({
      file: 'src/fixture.tsx',
      code: `import { Navigate, Route, Routes } from 'react-router-dom'
function Wizard() { return <Routes><Route index element={<p />} /><Route path="step" element={<p />} /><Route path="*" element={<Navigate to="/wizard" />} /></Routes> }
export function Shell({ admin }: { admin: boolean }) {
  return <Routes>${routes}<Route path="*" element={<Navigate to="/" />} /></Routes>
}`,
    })
    const baseRoutes = `<Route path="/" element={<p />} /><Route path="/items/:id" element={<p />} /><Route path="/wizard/*" element={admin ? <Wizard /> : <Navigate to="/" />} />`
    const baseInventory: Inventory = {
      consoleRoutes: [
        { path: '/', scope: 'unit' },
        { path: '/items/item-1', scope: 'unit' },
        { path: '/wizard', scope: 'unit' },
        { path: '/wizard/step', scope: 'unit' },
        { path: '/wizard/elsewhere', scope: 'unit', allowedPath: '/wizard' },
        { path: '/unknown', scope: 'unit', redirectToHome: true },
      ],
      surfaces: [
        { path: '/public', router: 'public', state: 'public', heading: '' },
        { path: '/public/unit', router: 'public', state: 'public', heading: '' },
      ],
      scopeRouters: { unit: ['Shell'], platform: [], shared: ['Shell'] },
      exclusions: [],
      tabKeys: [],
    }
    const problems = (routes: string, inventory: Partial<Inventory> = {}) => inventoryProblems(resolveRouters(extractRouters([shell(routes)])), { ...baseInventory, ...inventory })

    it('accepts an inventory that matches, whatever the JSX formatting', () => {
      expect(problems(baseRoutes)).toEqual([])
      const reformatted = `
        <Route
          element={<p />}
          path={'/'}
        />
        {admin && <Route element={<p />} path={\`/items/:id\`} />}
        <Route path="/wizard/*"
          element={admin ? <Wizard /> : <Navigate to="/" />} />`
      expect(problems(reformatted)).toEqual([])
    })

    it('fails when a route has no inventory entry', () => {
      expect(problems(`${baseRoutes}<Route path="/reports" element={<p />} />`)).toEqual([
        'route Shell /reports has no entry in e2e/console-routes.ts; add one so the axe audit and role matrix visit it, or exclude it with a reason in routesWithoutInventoryEntry',
      ])
      // A route nested inside another <Route> counts too.
      expect(problems(`${baseRoutes}<Route path="/reports"><Route path="weekly" element={<p />} /></Route>`)).toEqual([
        'route Shell /reports has no entry in e2e/console-routes.ts; add one so the axe audit and role matrix visit it, or exclude it with a reason in routesWithoutInventoryEntry',
        'route Shell /reports/weekly has no entry in e2e/console-routes.ts; add one so the axe audit and role matrix visit it, or exclude it with a reason in routesWithoutInventoryEntry',
      ])
    })

    it('fails when a route loses its inventory entry', () => {
      expect(problems(baseRoutes, { consoleRoutes: baseInventory.consoleRoutes.filter(route => route.path !== '/wizard/step') })).toEqual([
        'route Wizard /wizard/step has no entry in e2e/console-routes.ts; add one so the axe audit and role matrix visit it, or exclude it with a reason in routesWithoutInventoryEntry',
      ])
    })

    it('fails when an entry outlives its route', () => {
      expect(problems(`<Route path="/" element={<p />} /><Route path="/wizard/*" element={<Wizard />} />`)).toEqual([
        'inventory entry unit /items/item-1 reaches only the catch-all Shell *; remove it, restore its route, or mark the redirect',
      ])
    })

    it('requires each exclusion to name a route and give a reason', () => {
      expect(problems(`${baseRoutes}<Route path="/reports" element={<Navigate to="/" />} />`, {
        exclusions: [
          { router: 'Shell', path: '/reports', reason: 'Redirects to the overview.' },
          { router: 'Shell', path: '/gone', reason: 'Removed.' },
          { router: 'Shell', path: '/', reason: ' ' },
        ],
      })).toEqual([
        'exclusion Shell /gone names no route; remove it from routesWithoutInventoryEntry',
        'exclusion Shell / gives no reason',
        'exclusion Shell / also has an inventory entry; remove one of them',
      ])
    })

    it('checks the UnitDetail tabs against the tab entries', () => {
      const platform = {
        file: 'src/platform.tsx',
        code: `import { Route, Routes } from 'react-router-dom'
export function PlatformShell() { return <Routes><Route path="/units/:id/:tab" element={<p />} /></Routes> }`,
      }
      const routers = resolveRouters(extractRouters([shell(baseRoutes), platform]))
      const inventory = { ...baseInventory, scopeRouters: { unit: ['Shell'], platform: ['PlatformShell'], shared: ['Shell', 'PlatformShell'] } }
      expect(inventoryProblems(routers, { ...inventory, consoleRoutes: [...baseInventory.consoleRoutes, { path: '/units/u/overview', scope: 'platform' }, { path: '/units/u/legacy', scope: 'platform' }], tabKeys: ['overview', 'danger'] })).toEqual([
        'UnitDetail tab danger has no /platform/units/:id/danger entry in e2e/console-routes.ts',
        'inventory entry /platform/units/:id/legacy names no UnitDetail tab; remove it or restore the tab',
      ])
      expect(extractTabKeys('tabs.tsx', `const tabs = [{ key: 'overview', label: 'Overview' }, { label: 'Danger', 'key': "danger" }]`, 'tabs')).toEqual(['overview', 'danger'])
    })

    it('refuses routes it cannot read', () => {
      expect(() => extractRouters([{ file: 'src/a.tsx', code: `import { Route, Routes } from 'react-router-dom'\nconst base = '/x'\nexport function A() { return <Routes><Route path={base} element={<p />} /></Routes> }` }])).toThrow(/must be a string literal/)
      expect(() => extractRouters([{ file: 'src/b.tsx', code: `import { useRoutes } from 'react-router-dom'\nexport function B() { return useRoutes([{ path: '/b' }]) }` }])).toThrow(/imports useRoutes/)
      expect(() => extractRouters([{ file: 'src/c.tsx', code: `import { Route } from 'react-router-dom'\nexport const routes = <Route path="/c" element={<p />} />` }])).toThrow(/outside every <Routes>/)
      // An aliased import is still read.
      expect(extractRouters([{ file: 'src/d.tsx', code: `import { Route as Page, Routes as Pages } from 'react-router'\nexport function D() { return <Pages><Page path="/d" element={<p />} /></Pages> }` }]).map(router => [router.name, router.routes.map(route => route.path)])).toEqual([['D', ['/d']]])
      expect(() => extractRouters([{ file: 'src/e.tsx', code: `import * as RR from 'react-router-dom'\nexport function E() { return <RR.Routes><RR.Route path="/e" /></RR.Routes> }` }])).toThrow(/ImportNamespaceSpecifier/)
      expect(() => extractRouters([{ file: 'src/f.ts', code: `export { Route, Routes } from 'react-router-dom'` }])).toThrow(/re-exports router APIs/)
      expect(() => extractRouters([{ file: 'src/g.ts', code: `import { Route as Page, Routes as Pages } from 'react-router-dom'\nexport { Page as Route, Pages as Routes }` }])).toThrow(/re-exports local Page, imported as Route/)
      // A namespace-style element is refused even when the file also has
      // readable named imports, so its route cannot hide beside them.
      expect(() => extractRouters([{ file: 'src/h.tsx', code: `import { Route, Routes } from 'react-router-dom'\nexport function H() { return <Routes><Route path="/visible" /><RR.Route path="/hidden" /></Routes> }` }])).toThrow(/JSX member expression ending in Route/)
    })
  })
})
