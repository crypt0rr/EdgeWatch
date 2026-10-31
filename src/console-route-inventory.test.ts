import { mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, posix, relative, sep } from 'node:path'
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
// lists. This check keeps that list complete in two steps.
//
// A policy that fails closed by construction keeps every way to choose a page
// where the check can see it: only the router files may import Route and
// Routes, non-test src imports values only from its own modules and the known
// packages, it loads no module and creates no element at runtime without a
// listed reason, and every read of the address path is classified.
//
// The JSX route reader then reads the <Routes> of the router files with the
// TypeScript parser that Vite ships, so formatting, attribute order, and
// conditional routes do not change what it reads, and the inventory is
// compared with the routes it found: a new page cannot skip the audit
// unnoticed, and a removed page cannot leave an entry behind.

const repositoryRoot = fileURLToPath(new URL('..', import.meta.url))

/** The modules that may import Route and Routes. The JSX route reader reads their <Routes>. */
const routerFiles = ['src/main.tsx', 'src/pages/TotpEnrollment.tsx', 'src/pages/platform/PlatformShell.tsx']

/**
 * The packages that non-test src may import values from, by exact
 * specifier, and why none of them renders a page that the inventory misses.
 */
const knownPackages: Record<string, string> = {
  react: 'Hooks and primitives; its element factories and lazy are refused below.',
  'react-dom': 'createPortal, which renders the children that src passes it.',
  'react-dom/client': 'createRoot, which mounts App.',
  'react-router-dom': 'The router; routerExports lists what src may import from it.',
  '@tanstack/react-query': 'Server-state queries and their provider; it renders no page.',
  'react-hook-form': 'Form state; it renders no page.',
  '@hookform/resolvers/zod': 'Connects zod schemas to react-hook-form.',
  zod: 'Schema validation.',
  'lucide-react': 'SVG icons.',
}

/**
 * The names that src may import from react-router-dom. Route and Routes only
 * in the router files. The path matchers read the address, so each use
 * counts as a path read in pathReaders. Route-table APIs such as useRoutes,
 * createBrowserRouter, and RouterProvider are left out on purpose: they build
 * routes that the JSX route reader cannot read.
 */
const routerExports = {
  routes: new Set(['Route', 'Routes']),
  pathMatchers: new Set(['matchPath', 'matchRoutes', 'useMatch', 'useMatches']),
  other: new Set(['BrowserRouter', 'Link', 'Navigate', 'useLocation', 'useNavigate', 'useNavigationType', 'useParams', 'useSearchParams']),
}

/** Module loads and element factories that run at runtime, which the JSX route reader cannot follow. */
type RuntimeConstruct = 'import()' | 'import.meta.glob' | 'require' | 'lazy' | 'createElement' | 'cloneElement'
type RuntimeAllowance = { file: string; construct: RuntimeConstruct; reason: string }

/** The runtime constructs that a module may use, each with why it cannot hide a page. src uses none. */
const runtimeAllowances: RuntimeAllowance[] = []

/**
 * The standard JavaScript and browser globals that src may read besides its
 * own bindings and imports, and the members it may read from window. A
 * global that something outside the bundle sets, such as a component
 * registry on window, could hold a page that the inventory cannot see. Add a
 * standard global when src starts to use it.
 */
const knownGlobals = new Set([
  'AbortController', 'Array', 'Boolean', 'CustomEvent', 'Date', 'Element', 'Error', 'Event', 'EventSource', 'HTMLElement', 'Headers',
  'Intl', 'JSON', 'Map', 'Math', 'NaN', 'Number', 'Object', 'Promise', 'Set', 'String', 'TextEncoder', 'TypeError', 'URL', 'URLSearchParams',
  'clearTimeout', 'crypto', 'decodeURIComponent', 'document', 'encodeURIComponent', 'fetch', 'navigator', 'performance', 'setTimeout', 'undefined',
])
const knownWindowMembers = new Set([
  'addEventListener', 'cancelAnimationFrame', 'clearInterval', 'clearTimeout', 'dispatchEvent', 'getSelection', 'history', 'location',
  'matchMedia', 'removeEventListener', 'requestAnimationFrame', 'setInterval', 'setTimeout',
])
/** The names of the global object, whose members are globals too. */
const globalObjects = new Set(['window', 'globalThis', 'self'])

type PathReader = {
  file: string
  /** The top-level declaration that holds the reads. */
  declaration: string
  /** Its reads of a path: each `.pathname` read or destructure and each use of a path matcher. */
  reads: number
  /**
   * The route patterns of the pages that these reads choose outside every
   * <Route>. The comparison treats them as a router named after the
   * declaration, so each needs an entry surface that names it.
   */
  serves?: string[]
  /** How the reads choose those pages, or why they choose none. */
  reason: string
}

/**
 * Every declaration in non-test src that reads a path. A page chosen from the
 * path outside every <Route> would escape the JSX route reader, so the check
 * fails when a declaration gains or loses a read until its entry here says
 * which inventoried pages the reads serve or why they serve none.
 */
const pathReaders: PathReader[] = [
  {
    file: 'src/main.tsx',
    declaration: 'AppContent',
    reads: 2,
    serves: ['/public', '/public/:slug', '/activate'],
    reason: 'Serves the public status pages before any session read, and the account-link notice when a signed-in browser opens an activation or password-reset link.',
  },
  {
    file: 'src/main.tsx',
    declaration: 'Shell',
    reads: 9,
    reason: 'Names the breadcrumb and document title, moves focus to the main region when the path changes, and marks the active navigation link.',
  },
  {
    file: 'src/main.tsx',
    declaration: 'ProtectedApp',
    reads: 1,
    reason: 'Redirects a console that sign-in mounted on /login to the page that sent the visitor to sign in; it renders a redirect, not a page.',
  },
  {
    file: 'src/main.tsx',
    declaration: 'AuthRoutes',
    reads: 1,
    reason: 'Records the requested page as the return path of the catch-all redirect to /login.',
  },
  {
    file: 'src/pages/platform/PlatformShell.tsx',
    declaration: 'PlatformShell',
    reads: 6,
    reason: 'Marks the active navigation link and moves focus to the main region when the path changes.',
  },
  {
    file: 'src/pages/JobEditor.tsx',
    declaration: 'JobEditor',
    reads: 7,
    reason: 'Tells /jobs/new/advanced, which has its own route, from the guided creation, and keeps the unsaved-changes guard on the current history entry.',
  },
  {
    file: 'src/pages/MonitorSetup.tsx',
    declaration: 'MonitorSetup',
    reads: 8,
    reason: 'Clears consumed navigation state in place and keeps the unsaved-changes guard on the current history entry.',
  },
  {
    file: 'src/pages/JobDetail.tsx',
    declaration: 'JobDetail',
    reads: 2,
    reason: 'Clears the first-scan token from the navigation state in place.',
  },
  {
    file: 'src/pages/Auth.tsx',
    declaration: 'signInReturnPath',
    reads: 4,
    reason: 'Checks that the stored return path is a local path before the console opens it.',
  },
  {
    file: 'src/pages/Auth.tsx',
    declaration: 'Activate',
    reads: 2,
    reason: 'Removes the token from the address bar in place.',
  },
  {
    file: 'src/host-list-state.ts',
    declaration: 'useHostListState',
    reads: 2,
    reason: 'Builds the returnTo path of the host list and restores its search when the list address changes.',
  },
  {
    file: 'src/job-list-state.ts',
    declaration: 'useJobListState',
    reads: 2,
    reason: 'Builds the returnTo path of the job list and restores its search when the list address changes.',
  },
]

/** The UnitDetail tabs, which /platform/units/:id/:tab selects. */
const unitDetailFile = 'src/pages/platform/UnitDetail.tsx'
const unitDetailTabsVariable = 'tabs'
const unitDetailTabParam = 'tab'

type Node = { type: string; start?: number; [key: string]: unknown }

function isNode(value: unknown): value is Node {
  return typeof value === 'object' && value !== null && typeof (value as Node).type === 'string'
}

const field = (node: Node | undefined, key: string): Node | undefined => node && isNode(node[key]) ? node[key] as Node : undefined
const list = (node: Node | undefined, key: string): Node[] => node && Array.isArray(node[key]) ? (node[key] as unknown[]).filter(isNode) : []
const nameOf = (node: Node | undefined): string | undefined => node && (node.type === 'Identifier' || node.type === 'JSXIdentifier') ? String(node.name) : undefined

function childNodes(node: Node): Node[] {
  return Object.values(node).flatMap(value => Array.isArray(value) ? value.filter(isNode) : isNode(value) ? [value] : [])
}

/** Parentheses and TypeScript wrappers that leave the value they wrap unchanged. */
const transparentExpressions = new Set(['ParenthesizedExpression', 'ChainExpression', 'TSAsExpression', 'TSSatisfiesExpression', 'TSNonNullExpression', 'TSTypeAssertion', 'TSInstantiationExpression'])

function unwrap(node: Node | undefined): Node | undefined {
  while (node && transparentExpressions.has(node.type)) node = field(node, 'expression')
  return node
}

function staticString(node: Node | undefined): string | undefined {
  node = unwrap(node)
  if (node?.type === 'Literal') return typeof node.value === 'string' ? node.value : undefined
  if (node?.type === 'TemplateLiteral' && !list(node, 'expressions').length) {
    const value = list(node, 'quasis')[0]?.value as { cooked?: string | null; raw: string } | undefined
    return value ? value.cooked ?? value.raw : undefined
  }
  if (node?.type === 'BinaryExpression' && node.operator === '+') {
    const left = staticString(field(node, 'left'))
    const right = staticString(field(node, 'right'))
    return left !== undefined && right !== undefined ? left + right : undefined
  }
  return undefined
}

/** The name that a member expression reads or a property key names, when it is static. */
function staticKey(node: Node): string | undefined {
  const key = field(node, node.type === 'MemberExpression' ? 'property' : 'key')
  if (node.computed) return staticString(key)
  return key?.type === 'Identifier' ? String(key.name) : staticString(key)
}

/** Whether an Identifier names a variable, rather than a property, a key, or a label. */
function namesVariable(parent: Node | undefined, key: string): boolean {
  switch (parent?.type) {
    case 'MemberExpression': return key !== 'property' || parent.computed === true
    case 'Property': case 'PropertyDefinition': case 'MethodDefinition': case 'AccessorProperty': return key !== 'key' || parent.computed === true
    case 'ImportSpecifier': case 'ImportDefaultSpecifier': case 'ImportNamespaceSpecifier': return false
    case 'ExportSpecifier': return key === 'local'
    case 'LabeledStatement': case 'BreakStatement': case 'ContinueStatement': case 'MetaProperty': return false
    case 'TSEnumMember': return key !== 'id'
    default: return true
  }
}

/** TypeScript nodes that hold runtime values; every other TypeScript node holds only types. */
const valueTypeScriptNodes = new Set([
  ...transparentExpressions,
  'TSEnumDeclaration', 'TSEnumBody', 'TSEnumMember', 'TSModuleDeclaration', 'TSModuleBlock', 'TSParameterProperty',
  'TSExportAssignment', 'TSImportEqualsDeclaration', 'TSExternalModuleReference',
])
/** Keys whose subtrees hold only types. */
const typeKeys = new Set(['typeAnnotation', 'typeParameters', 'typeArguments', 'returnType', 'superTypeArguments', 'implements'])

type Visitor = (node: Node, parent: Node | undefined, key: string) => boolean | void

/** Visits every node that can hold a runtime value, parents first; a visitor that returns false skips the children. */
function visitValues(node: Node, visit: Visitor, parent?: Node, key = ''): void {
  if (node.type.startsWith('TS') && !valueTypeScriptNodes.has(node.type)) return
  if (visit(node, parent, key) === false) return
  for (const childKey in node) {
    if (typeKeys.has(childKey)) continue
    const value = node[childKey]
    if (Array.isArray(value)) {
      for (const child of value) if (isNode(child)) visitValues(child, visit, node, childKey)
    } else if (isNode(value)) visitValues(value, visit, node, childKey)
  }
}

/** The names that a binding pattern declares. */
function patternNames(pattern: Node | undefined): string[] {
  if (!pattern) return []
  switch (pattern.type) {
    case 'Identifier': return [String(pattern.name)]
    case 'ObjectPattern': return list(pattern, 'properties').flatMap(property => patternNames(property.type === 'RestElement' ? field(property, 'argument') : field(property, 'value')))
    case 'ArrayPattern': return list(pattern, 'elements').flatMap(patternNames)
    case 'AssignmentPattern': return patternNames(field(pattern, 'left'))
    case 'RestElement': return patternNames(field(pattern, 'argument'))
    case 'TSParameterProperty': return patternNames(field(pattern, 'parameter'))
    default: return []
  }
}

/** How often each name is bound anywhere in a module: declarations, parameters, imports, and catch clauses. */
function bindingCounts(program: Node): Map<string, number> {
  const counts = new Map<string, number>()
  const count = (name: string | undefined) => { if (name) counts.set(name, (counts.get(name) ?? 0) + 1) }
  visitValues(program, node => {
    if (node.type === 'VariableDeclarator') patternNames(field(node, 'id')).forEach(count)
    if (['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression'].includes(node.type)) {
      count(nameOf(field(node, 'id')))
      list(node, 'params').flatMap(patternNames).forEach(count)
    }
    if (['ClassDeclaration', 'ClassExpression', 'TSEnumDeclaration', 'TSImportEqualsDeclaration', 'TSModuleDeclaration'].includes(node.type)) count(nameOf(field(node, 'id')))
    if (node.type === 'CatchClause') patternNames(field(node, 'param')).forEach(count)
    if (['ImportSpecifier', 'ImportDefaultSpecifier', 'ImportNamespaceSpecifier'].includes(node.type)) count(nameOf(field(node, 'local')))
  })
  return counts
}

type SourceFile = { file: string; code: string }
type Module = SourceFile & { program: Node }

const lineOf = (module: SourceFile, node: Node) => module.code.slice(0, node.start ?? 0).split('\n').length

const parsedPrograms = new Map<string, Node>()

function parseModule(source: SourceFile): Module {
  const key = `${source.file}\0${source.code}`
  let program = parsedPrograms.get(key)
  if (!program) {
    const parsed = parseSync(source.file, source.code, { lang: source.file.endsWith('.tsx') ? 'tsx' : 'ts' })
    if (parsed.errors.length) throw new Error(`${source.file}: ${parsed.errors.map(error => error.message).join('; ')}`)
    program = parsed.program as unknown as Node
    parsedPrograms.set(key, program)
  }
  return { ...source, program }
}

const byFile = (left: SourceFile, right: SourceFile) => left.file < right.file ? -1 : left.file > right.file ? 1 : 0

/** Whether the policy checks a file under src: non-test TypeScript modules, including the generated API types. */
function isCheckedModule(file: string) {
  return /\.tsx?$/.test(file) && !file.endsWith('.d.ts') && !/\.test\.tsx?$/.test(file) && !file.startsWith('src/test/')
}

type SourceTree = { sources: SourceFile[]; files: Set<string> }

/** Every file under src, and the modules among them that the policy checks. Nothing under src may resolve outside it. */
function readSourceTree(root = repositoryRoot): SourceTree {
  const sourceRoot = realpathSync(join(root, 'src'))
  const files = new Set<string>()
  const sources: SourceFile[] = []
  const scanned = new Set([sourceRoot])
  const scan = (directory: string) => {
    for (const name of readdirSync(directory).sort()) {
      const path = join(directory, name)
      const file = relative(root, path).split(sep).join('/')
      const canonical = realpathSync(path)
      if (!canonical.startsWith(`${sourceRoot}${sep}`)) throw new Error(`${file} resolves to ${canonical}, outside src; the route inventory reads only the modules in src`)
      if (statSync(canonical).isDirectory()) {
        if (!scanned.has(canonical)) { scanned.add(canonical); scan(path) }
        continue
      }
      files.add(file)
      if (isCheckedModule(file)) sources.push({ file, code: readFileSync(path, 'utf8') })
    }
  }
  scan(join(root, 'src'))
  return { sources, files }
}

const isLocalSpecifier = (specifier: string) => specifier.startsWith('.') || specifier.startsWith('/')
const viteExtensions = ['.mjs', '.js', '.mts', '.ts', '.jsx', '.tsx', '.json']

/** The file that Vite resolves a local specifier to: the path as written, then Vite's default extension order. */
function resolveLocalModule(importer: string, specifier: string, files: Set<string>): string | undefined {
  const base = specifier.startsWith('/') ? posix.normalize(specifier.slice(1)) : posix.join(posix.dirname(importer), specifier)
  return [base, ...viteExtensions.map(extension => `${base}${extension}`), ...viteExtensions.map(extension => `${base}/index${extension}`)]
    .find(candidate => files.has(candidate))
}

type PolicyOptions = {
  routerFiles: string[]
  /** Every file under src, for resolving local imports; the given modules by default. Its checked modules count as read. */
  files?: Set<string>
  allowances?: RuntimeAllowance[]
}

const elementConstructs = new Set<string>(['createElement', 'cloneElement', 'lazy'])

/** The runtime construct that a node uses, if any. */
function runtimeConstruct(node: Node, parent: Node | undefined, key: string): RuntimeConstruct | undefined {
  if (node.type === 'ImportExpression') return 'import()'
  if (node.type === 'TSImportEqualsDeclaration' && field(node, 'moduleReference')?.type === 'TSExternalModuleReference') return 'require'
  if (node.type === 'Identifier' && node.name === 'require' && namesVariable(parent, key)) return 'require'
  if (node.type === 'MemberExpression') {
    const name = staticKey(node)
    if (name === 'require' || (name !== undefined && elementConstructs.has(name))) return name as RuntimeConstruct
    if ((name === 'glob' || name === 'globEager') && field(node, 'object')?.type === 'MetaProperty') return 'import.meta.glob'
  }
  if (node.type === 'Property' && parent?.type === 'ObjectPattern') {
    const name = staticKey(node)
    if (name === 'require' || (name !== undefined && elementConstructs.has(name))) return name as RuntimeConstruct
  }
  return undefined
}

/**
 * Every way that non-test src could choose a page where the JSX route reader
 * cannot see it, as messages that say what to change. An empty list means
 * that src keeps the policy.
 */
function policyProblems(sources: SourceFile[], options: PolicyOptions): string[] {
  const modules = sources.map(parseModule)
  const checked = new Set([...modules.map(module => module.file), ...[...options.files ?? []].filter(isCheckedModule)])
  const files = options.files ?? checked
  const allowances = options.allowances ?? runtimeAllowances
  const usedAllowances = new Set<RuntimeAllowance>()
  const problems: string[] = []

  const checkSpecifier = (file: string, where: string, specifier: string, sideEffectOnly: boolean, verb = 'imports') => {
    if (!isLocalSpecifier(specifier)) {
      if (!Object.hasOwn(knownPackages, specifier)) problems.push(`${where} ${verb} ${specifier}, which knownPackages does not list; render the page from src, or add the package with the reason it cannot render a page that the inventory misses`)
      return
    }
    const target = resolveLocalModule(file, specifier, files)
    if (target && (checked.has(target) || (sideEffectOnly && target.endsWith('.css')))) return
    problems.push(`${where} ${verb} ${specifier}, which resolves to ${target ?? 'no file in src'}; src may load values only from its non-test TypeScript modules, which this check reads`)
  }

  for (const file of options.routerFiles) {
    if (!checked.has(file)) problems.push(`routerFiles lists ${file}, which is not a checked module in src; remove it`)
  }

  for (const module of modules) {
    const { file, program } = module
    const isRouterFile = options.routerFiles.includes(file)
    for (const statement of list(program, 'body')) {
      if (statement.type === 'ImportDeclaration') {
        const specifier = String(field(statement, 'source')?.value)
        const specifiers = list(statement, 'specifiers')
        const values = statement.importKind === 'type' ? [] : specifiers.filter(item => item.importKind !== 'type')
        if (specifiers.length && !values.length) continue
        checkSpecifier(file, file, specifier, !specifiers.length)
        if (isLocalSpecifier(specifier)) continue
        for (const item of values) {
          if (item.type !== 'ImportSpecifier') {
            problems.push(`${file} imports ${specifier} with a ${item.type === 'ImportDefaultSpecifier' ? 'default' : 'namespace'} import; import package values by name, so this check sees each name`)
            continue
          }
          const name = nameOf(field(item, 'imported')) ?? staticString(field(item, 'imported')) ?? ''
          if (specifier === 'react' && elementConstructs.has(name)) {
            if (!allowedConstruct(file, name as RuntimeConstruct)) problems.push(constructProblem(`${file}:${lineOf(module, item)}`, name))
          }
          if (specifier !== 'react-router-dom') continue
          if (routerExports.routes.has(name)) {
            if (!isRouterFile) problems.push(`${file} imports ${name} from react-router-dom but is not in routerFiles; declare routes in a router file, whose <Routes> the JSX route reader reads`)
          } else if (!routerExports.pathMatchers.has(name) && !routerExports.other.has(name)) {
            problems.push(`${file} imports ${name} from react-router-dom, which routerExports does not list; the JSX route reader reads only <Routes> and <Route>, so add the name only if it neither builds routes nor reads the path`)
          }
        }
        continue
      }
      const reexport = statement.type === 'ExportAllDeclaration' || (statement.type === 'ExportNamedDeclaration' && field(statement, 'source'))
      if (reexport && statement.exportKind !== 'type' && (statement.type === 'ExportAllDeclaration' || list(statement, 'specifiers').some(item => item.exportKind !== 'type'))) {
        const specifier = String(field(statement, 'source')?.value)
        if (isLocalSpecifier(specifier)) checkSpecifier(file, file, specifier, false, 're-exports')
        else problems.push(`${file} re-exports ${specifier}; src may re-export only its own modules, so a package value cannot reach a router file under another name`)
      }
    }

    const bound = bindingCounts(program)
    visitValues(program, (node, parent, key) => {
      if (node.type === 'ImportDeclaration' || node.type === 'ExportAllDeclaration' || (node.type === 'ExportNamedDeclaration' && field(node, 'source'))) return false
      const global = globalRead(node, parent, key, bound)
      if (global) problems.push(`${file}:${lineOf(module, node)} reads ${global}, which is neither declared or imported in the module nor in knownGlobals; a global that code outside the bundle sets could hold a page that the inventory cannot see`)
      const construct = runtimeConstruct(node, parent, key)
      if (!construct) return
      const where = `${file}:${lineOf(module, node)}`
      if (!allowedConstruct(file, construct)) { problems.push(constructProblem(where, construct)); return }
      const loaded = construct === 'import()' ? field(node, 'source')
        : construct === 'require' && parent?.type === 'CallExpression' && key === 'callee' ? list(parent, 'arguments')[0]
          : undefined
      if (construct !== 'import()' && !loaded) return
      const specifier = staticString(loaded)
      if (specifier === undefined) problems.push(`${where} loads a module whose name is computed at runtime; the policy cannot check what it loads`)
      else checkSpecifier(file, where, specifier, false, 'loads')
    })
  }

  for (const allowance of allowances) {
    if (!allowance.reason.trim()) problems.push(`runtimeAllowances entry for ${allowance.construct} in ${allowance.file} gives no reason`)
    if (!usedAllowances.has(allowance)) problems.push(`runtimeAllowances allows ${allowance.construct} in ${allowance.file}, which does not use it; remove the entry`)
  }
  return [...new Set(problems)]

  function allowedConstruct(file: string, construct: RuntimeConstruct) {
    const allowance = allowances.find(item => item.file === file && item.construct === construct)
    if (allowance) usedAllowances.add(allowance)
    return !!allowance
  }
}

/** The global that a node reads, when the module neither declares nor imports it and knownGlobals does not list it. */
function globalRead(node: Node, parent: Node | undefined, key: string, bound: Map<string, number>): string | undefined {
  let name: string | undefined
  if (node.type === 'Identifier' && namesVariable(parent, key)) name = String(node.name)
  // A capitalized JSX tag, or the root of a member tag, names a component variable.
  if (node.type === 'JSXOpeningElement') {
    let tag = field(node, 'name')
    while (tag?.type === 'JSXMemberExpression') tag = field(tag, 'object')
    const tagName = nameOf(tag)
    if (tagName && (/^[A-Z_$]/.test(tagName) || field(node, 'name')?.type === 'JSXMemberExpression') && tagName !== 'this') name = tagName
  }
  // A runtime construct, which the policy reports on its own.
  if (!name || name === 'require' || bound.has(name)) return undefined
  if (globalObjects.has(name)) {
    if (parent?.type === 'UnaryExpression' && parent.operator === 'typeof') return undefined
    if (parent?.type !== 'MemberExpression' || key !== 'object') return name
    const member = staticKey(parent)
    return member !== undefined && (knownGlobals.has(member) || knownWindowMembers.has(member)) ? undefined : `${name}.${member ?? '[computed]'}`
  }
  return knownGlobals.has(name) ? undefined : name
}

function constructProblem(where: string, construct: string) {
  return `${where} uses ${construct}; the JSX route reader cannot follow a module loaded or an element created at runtime, so declare the page in JSX, or add a runtimeAllowances entry with the reason it cannot hide a page`
}

type PathReadCount = { file: string; declaration: string; reads: number; lines: number[] }

/** The top-level declarations of a module, each with the name that pathReaders uses for it. */
function topLevelDeclarations(program: Node): { name: string; node: Node }[] {
  return list(program, 'body').flatMap(statement => {
    if (statement.type === 'ExportDefaultDeclaration') {
      const declaration = field(statement, 'declaration')
      return declaration ? [{ name: nameOf(field(declaration, 'id')) ?? 'default', node: declaration }] : []
    }
    const declaration = statement.type === 'ExportNamedDeclaration' ? field(statement, 'declaration') ?? statement : statement
    if (declaration.type === 'VariableDeclaration') {
      return list(declaration, 'declarations').map(declarator => ({ name: patternNames(field(declarator, 'id')).join(', ') || '(module)', node: declarator }))
    }
    const id = ['FunctionDeclaration', 'ClassDeclaration', 'TSEnumDeclaration'].includes(declaration.type) ? nameOf(field(declaration, 'id')) : undefined
    return [{ name: id ?? '(module)', node: declaration }]
  })
}

/** Every read of a path in non-test src, by top-level declaration. */
function pathReadCounts(sources: SourceFile[]): PathReadCount[] {
  const counts = new Map<string, PathReadCount>()
  for (const module of sources.map(parseModule)) {
    const matchers = new Set<string>()
    for (const statement of list(module.program, 'body')) {
      if (statement.type !== 'ImportDeclaration' || field(statement, 'source')?.value !== 'react-router-dom') continue
      for (const item of list(statement, 'specifiers')) {
        if (item.type === 'ImportSpecifier' && routerExports.pathMatchers.has(nameOf(field(item, 'imported')) ?? '')) matchers.add(nameOf(field(item, 'local'))!)
      }
    }
    for (const { name, node } of topLevelDeclarations(module.program)) {
      if (node.type === 'ImportDeclaration') continue
      const lines: number[] = []
      visitValues(node, (child, parent, key) => {
        const read = (child.type === 'MemberExpression' && staticKey(child) === 'pathname')
          || (child.type === 'Property' && parent?.type === 'ObjectPattern' && staticKey(child) === 'pathname')
          || (child.type === 'Identifier' && matchers.has(String(child.name)) && namesVariable(parent, key))
        if (read) lines.push(lineOf(module, child))
      })
      if (!lines.length) continue
      const id = `${module.file}\0${name}`
      const count = counts.get(id) ?? { file: module.file, declaration: name, reads: 0, lines: [] }
      count.reads += lines.length
      count.lines.push(...lines)
      counts.set(id, count)
    }
  }
  return [...counts.values()]
}

/** Every disagreement between the path reads in src and pathReaders. */
function pathReaderProblems(counts: PathReadCount[], readers: PathReader[]): string[] {
  const problems: string[] = []
  const matches = (reader: PathReader, count: PathReadCount) => reader.file === count.file && reader.declaration === count.declaration
  for (const count of counts) {
    const reader = readers.find(item => matches(item, count))
    const where = `${count.declaration} in ${count.file} reads the path ${count.reads} time${count.reads === 1 ? '' : 's'} (line ${count.lines.join(', ')})`
    if (!reader) problems.push(`${where} and has no pathReaders entry; list the routes of the pages that the reads choose outside every <Route> so the inventory audits them, or say why they choose none`)
    else if (reader.reads !== count.reads) problems.push(`${where}, but its pathReaders entry allows ${reader.reads}; update the entry with the routes of any page that a new read chooses, or with why it chooses none`)
  }
  for (const reader of readers) {
    if (!counts.some(count => matches(reader, count))) problems.push(`pathReaders lists ${reader.declaration} in ${reader.file}, which reads no path; remove the entry`)
    if (!reader.reason.trim()) problems.push(`pathReaders entry for ${reader.declaration} in ${reader.file} gives no reason`)
  }
  return problems
}

type SourceRoute = {
  /** As written; undefined for an index route. */
  path?: string
  index: boolean
  /** Explicit React Router path case handling. */
  caseSensitive?: boolean
  /** The router components that its element renders, as `file:component`. */
  renders: string[]
  children: SourceRoute[]
}

type SourceRouter = {
  /** The component that renders the `<Routes>`, with a suffix when another router has its name. */
  name: string
  file: string
  component: string
  routes: SourceRoute[]
}

type Binding = { kind: 'declaration' } | { kind: 'import'; source: string; imported: string }

type RouterModule = Module & {
  route: Set<string>
  routes: Set<string>
  fragments: Set<string>
  /** Module-scope bindings. */
  bindings: Map<string, Binding>
  /** How often each name is bound anywhere in the module; a name bound twice is shadowed somewhere. */
  bindingCounts: Map<string, number>
  /** Exported name to the name of its declaration. */
  exports: Map<string, string>
  /** The components that render a <Routes>. */
  routerComponents: Set<string>
}

/** Calls onRoutes for each <Routes> element with the component that renders it. */
function walkComponents(program: Node, routes: Set<string>, onRoutes: (node: Node, component: string) => void) {
  const walk = (node: Node, component: string) => {
    let current = component
    if (node.type === 'FunctionDeclaration' && field(node, 'id')) current = nameOf(field(node, 'id'))!
    if (node.type === 'VariableDeclarator' && /^[A-Z]/.test(nameOf(field(node, 'id')) ?? '')) current = nameOf(field(node, 'id'))!
    if (node.type === 'JSXElement' && routes.has(jsxTagName(node) ?? '')) onRoutes(node, current)
    childNodes(node).forEach(child => walk(child, current))
  }
  walk(program, '')
}

function jsxTagName(node: Node): string | undefined {
  return node.type === 'JSXElement' ? nameOf(field(field(node, 'openingElement'), 'name')) : undefined
}

function jsxTagText(tag: Node | undefined): string {
  if (tag?.type === 'JSXMemberExpression') return `${jsxTagText(field(tag, 'object'))}.${jsxTagText(field(tag, 'property'))}`
  if (tag?.type === 'JSXNamespacedName') return `${jsxTagText(field(tag, 'namespace'))}:${jsxTagText(field(tag, 'name'))}`
  return nameOf(tag) ?? '?'
}

function jsxAttribute(element: Node, name: string): Node | undefined {
  return list(field(element, 'openingElement'), 'attributes').find(attribute => attribute.type === 'JSXAttribute' && nameOf(field(attribute, 'name')) === name)
}

/** The expression that an attribute passes: `{value}`, a string, or JSX written without braces. */
function attributeValue(attribute: Node | undefined): Node | undefined {
  const value = field(attribute, 'value')
  return value?.type === 'JSXExpressionContainer' ? unwrap(field(value, 'expression')) : value
}

function readRouterModule(source: SourceFile): RouterModule {
  const module = parseModule(source)
  const routerModule: RouterModule = {
    ...module,
    route: new Set(),
    routes: new Set(),
    fragments: new Set(),
    bindings: new Map(),
    bindingCounts: new Map(),
    exports: new Map(),
    routerComponents: new Set(),
  }
  const declare = (name: string | undefined, binding: Binding = { kind: 'declaration' }) => { if (name) routerModule.bindings.set(name, binding) }
  for (const statement of list(module.program, 'body')) {
    if (statement.type === 'ImportDeclaration') {
      if (statement.importKind === 'type') continue
      const source = String(field(statement, 'source')?.value)
      for (const item of list(statement, 'specifiers')) {
        if (item.importKind === 'type') continue
        const local = nameOf(field(item, 'local'))!
        const imported = item.type === 'ImportSpecifier' ? nameOf(field(item, 'imported')) ?? staticString(field(item, 'imported')) ?? '' : item.type === 'ImportDefaultSpecifier' ? 'default' : '*'
        declare(local, { kind: 'import', source, imported })
        if (source === 'react-router-dom' && imported === 'Route') routerModule.route.add(local)
        if (source === 'react-router-dom' && imported === 'Routes') routerModule.routes.add(local)
        if (source === 'react' && imported === 'Fragment') routerModule.fragments.add(local)
      }
      continue
    }
    const exported = statement.type === 'ExportNamedDeclaration' || statement.type === 'ExportDefaultDeclaration'
    const declaration = exported ? field(statement, 'declaration') : statement
    if (statement.type === 'ExportNamedDeclaration' && !field(statement, 'source')) {
      for (const item of list(statement, 'specifiers')) {
        const local = nameOf(field(item, 'local'))
        const name = nameOf(field(item, 'exported')) ?? staticString(field(item, 'exported'))
        if (local && name) routerModule.exports.set(name, local)
      }
    }
    if (!declaration) continue
    const names = declaration.type === 'VariableDeclaration'
      ? list(declaration, 'declarations').flatMap(declarator => patternNames(field(declarator, 'id')))
      : ['FunctionDeclaration', 'ClassDeclaration', 'TSEnumDeclaration'].includes(declaration.type) ? [nameOf(field(declaration, 'id'))].filter((name): name is string => !!name) : []
    names.forEach(name => declare(name))
    if (statement.type === 'ExportNamedDeclaration') names.forEach(name => routerModule.exports.set(name, name))
    if (statement.type === 'ExportDefaultDeclaration') {
      const name = names[0] ?? nameOf(declaration)
      if (name) routerModule.exports.set('default', name)
    }
  }
  routerModule.bindingCounts = bindingCounts(module.program)
  walkComponents(module.program, routerModule.routes, (_node, component) => { if (component) routerModule.routerComponents.add(component) })
  return routerModule
}

type ReaderOptions = {
  /** The modules whose <Routes> to read; every given module by default, as in the fixtures. */
  routerFiles?: string[]
  /** Every file under src, for resolving local imports; the given modules by default. */
  files?: Set<string>
}

/** What a component name in a router file stands for. */
type ComponentTarget = { kind: 'router'; key: string } | { kind: 'package' } | { kind: 'local' } | { kind: 'unlisted'; source: string } | { kind: 'unknown' }

/**
 * Reads the <Routes> of the router files. It throws on every form whose
 * routes it cannot read, so a route cannot hide in one.
 */
function extractRouters(sources: SourceFile[], options: ReaderOptions = {}): SourceRouter[] {
  const selected = options.routerFiles ?? sources.map(source => source.file)
  const files = options.files ?? new Set(sources.map(source => source.file))
  const modules = sources.filter(source => selected.includes(source.file)).sort(byFile).map(readRouterModule)
  const byPath = new Map(modules.map(module => [module.file, module]))
  const routers: SourceRouter[] = []

  const componentTarget = (module: RouterModule, name: string): ComponentTarget => {
    const binding = module.bindings.get(name)
    if (!binding || module.bindingCounts.get(name) !== 1) return { kind: 'unknown' }
    if (binding.kind === 'declaration') return module.routerComponents.has(name) ? { kind: 'router', key: `${module.file}:${name}` } : { kind: 'local' }
    if (!isLocalSpecifier(binding.source)) {
      if (!Object.hasOwn(knownPackages, binding.source)) return { kind: 'unlisted', source: binding.source }
      return binding.imported === '*' || binding.imported === 'default' ? { kind: 'unknown' } : { kind: 'package' }
    }
    const target = byPath.get(resolveLocalModule(module.file, binding.source, files) ?? '')
    const declared = target?.exports.get(binding.imported)
    return target && declared && target.routerComponents.has(declared) ? { kind: 'router', key: `${target.file}:${declared}` } : { kind: 'local' }
  }

  for (const module of modules) {
    const { file, program, route: routeNames, routes: routesNames } = module
    if (!routeNames.size && !routesNames.size) continue
    const fail = (message: string): never => { throw new Error(`${file}: ${message}`) }

    visitValues(program, (node, parent, key) => {
      if (node.type === 'ImportDeclaration') return false
      const name = node.type === 'Identifier' ? String(node.name) : ''
      if ((routeNames.has(name) || routesNames.has(name)) && namesVariable(parent, key)) {
        fail(`line ${lineOf(module, node)} uses ${routeNames.has(name) ? 'Route' : 'Routes'} as a value; use Route and Routes only as JSX tag names, so the reader sees every route`)
      }
    })

    const isFragment = (node: Node) => node.type === 'JSXFragment' || (node.type === 'JSXElement' && module.fragments.has(jsxTagName(node) ?? ''))
    const rejectChild = (node: Node, where: string): never => fail(`<Routes> in ${where} contains an unsupported child (${node.type === 'JSXElement' ? `<${jsxTagText(field(field(node, 'openingElement'), 'name'))}>` : node.type}); the reader reads only <Route> elements, fragments, and conditional JSX`)
    const assertRouteExpression = (node: Node | undefined, where: string): void => {
      const expression = unwrap(node)
      if (!expression) return rejectChild(node!, where)
      if (expression.type === 'JSXEmptyExpression' || (expression.type === 'Literal' && (expression.value === null || typeof expression.value === 'boolean'))) return
      if (expression.type === 'JSXElement' || expression.type === 'JSXFragment') return assertRouteChild(expression, where)
      if (expression.type === 'LogicalExpression' && expression.operator === '&&') return assertRouteExpression(field(expression, 'right'), where)
      if (expression.type === 'ConditionalExpression') { assertRouteExpression(field(expression, 'consequent'), where); return assertRouteExpression(field(expression, 'alternate'), where) }
      if (expression.type === 'ArrayExpression') { list(expression, 'elements').forEach(element => assertRouteExpression(element, where)); return }
      rejectChild(expression, where)
    }
    const assertRouteChild = (node: Node, where: string): void => {
      if (node.type === 'JSXText') { if (String(node.value).trim()) rejectChild(node, where); return }
      if (node.type === 'JSXExpressionContainer') return assertRouteExpression(field(node, 'expression'), where)
      if (isFragment(node)) { list(node, 'children').forEach(child => assertRouteChild(child, where)); return }
      const name = jsxTagName(node) ?? ''
      if (routeNames.has(name) || routesNames.has(name)) return
      rejectChild(node, where)
    }

    const wildcardFailure = (path: string, where: string, detail: string): never => fail(`<Route path="${path}"> in ${where} ${detail}; a wildcard route hands the rest of the address to what it renders, so it may render only a nested router, a redirect or another component from a known package, and markup`)
    const assertWildcardElement = (value: Node | undefined, path: string, where: string, prop: string): void => {
      const expression = unwrap(value)
      if (!expression) return
      if (expression.type === 'JSXElement' || expression.type === 'JSXFragment') return assertWildcardTree(expression, path, where)
      if (expression.type === 'JSXEmptyExpression' || (expression.type === 'Literal' && typeof expression.value !== 'object') || (expression.type === 'Literal' && expression.value === null)) return
      if (expression.type === 'ConditionalExpression') { assertWildcardElement(field(expression, 'consequent'), path, where, prop); return assertWildcardElement(field(expression, 'alternate'), path, where, prop) }
      if (expression.type === 'LogicalExpression') {
        if (expression.operator !== '&&') assertWildcardElement(field(expression, 'left'), path, where, prop)
        return assertWildcardElement(field(expression, 'right'), path, where, prop)
      }
      wildcardFailure(path, where, `has an unreadable ${prop} (${expression.type})`)
    }
    const assertWildcardTree = (node: Node, path: string, where: string): void => {
      if (node.type === 'JSXElement') {
        const opening = field(node, 'openingElement')
        const tag = field(opening, 'name')
        const tagName = nameOf(tag)
        if (tag?.type === 'JSXMemberExpression') wildcardFailure(path, where, `renders <${jsxTagText(tag)}>; import the component by name`)
        if (tagName && /^[A-Z_$]/.test(tagName) && !module.fragments.has(tagName)) {
          const target = componentTarget(module, tagName)
          if (target.kind === 'local') wildcardFailure(path, where, `renders <${tagName}>, a local component that renders no <Routes> of its own; import a nested router from the module that declares it`)
          if (target.kind === 'unlisted') wildcardFailure(path, where, `renders <${tagName}> from ${target.source}, which knownPackages does not list`)
          if (target.kind === 'unknown') wildcardFailure(path, where, `renders <${tagName}>, which is not a module-level component that this check can resolve`)
        }
        for (const attribute of list(opening, 'attributes')) {
          if (attribute.type === 'JSXSpreadAttribute') wildcardFailure(path, where, `spreads props into <${jsxTagText(tag)}>`)
          else if (nameOf(field(attribute, 'name')) === 'children') assertWildcardElement(attributeValue(attribute), path, where, 'children prop')
          else if (field(attribute, 'value')) visitValues(field(attribute, 'value')!, child => {
            if (child.type !== 'JSXElement' && child.type !== 'JSXFragment') return
            assertWildcardTree(child, path, where)
            return false
          })
        }
      }
      for (const child of list(node, 'children')) {
        if (child.type === 'JSXText') continue
        if (child.type === 'JSXExpressionContainer') assertWildcardElement(field(child, 'expression'), path, where, 'child')
        else if (child.type === 'JSXSpreadChild') wildcardFailure(path, where, 'spreads children')
        else assertWildcardTree(child, path, where)
      }
    }

    let routeElements = 0
    let collectedRoutes = 0
    visitValues(program, node => { if (node.type === 'JSXElement' && routeNames.has(jsxTagName(node) ?? '')) routeElements += 1 })

    const readRoute = (node: Node, where: string): SourceRoute => {
      collectedRoutes += 1
      const attributes = list(field(node, 'openingElement'), 'attributes')
      if (attributes.some(attribute => attribute.type === 'JSXSpreadAttribute')) fail(`<Route> in ${where} uses a JSX prop spread; the reader requires explicit props so it can determine the effective path`)
      if (jsxAttribute(node, 'children')) fail(`<Route> in ${where} uses a children attribute; declare nested routes as direct JSX children so the reader can read them`)
      if (jsxAttribute(node, 'lazy')) fail(`<Route> in ${where} uses a lazy prop; the reader cannot read a route that loads at runtime`)
      const literal = (name: string, purpose: string): boolean | undefined => {
        const attribute = jsxAttribute(node, name)
        if (!attribute) return undefined
        if (!field(attribute, 'value')) return true
        const value = attributeValue(attribute)
        if (value?.type === 'Literal' && typeof value.value === 'boolean') return value.value
        return fail(`<Route> in ${where} has a non-literal ${name} prop; use shorthand or a boolean literal so the reader can ${purpose}`)
      }
      const index = literal('index', 'tell whether it is an index route') ?? false
      const caseSensitive = literal('caseSensitive', 'preserve route matching')
      const pathAttribute = jsxAttribute(node, 'path')
      const path = pathAttribute ? staticString(attributeValue(pathAttribute)) ?? fail(`a <Route> path in ${where} must be a string literal so the reader can read it`) : undefined
      if (path?.includes('*') && !((path === '*' || path.endsWith('/*')) && path.indexOf('*') === path.length - 1)) {
        fail(`<Route> in ${where} uses non-canonical wildcard path ${path}; put the splat '*' in its own final path segment so the inventory can audit it`)
      }
      const wildcard = path === '*' || !!path?.endsWith('/*')
      const renders = new Set<string>()
      for (const prop of ['element', 'errorElement', 'hydrateFallbackElement']) {
        const value = attributeValue(jsxAttribute(node, prop))
        if (!value) continue
        if (wildcard) assertWildcardElement(value, path!, where, `${prop} prop`)
        visitValues(value, child => {
          const name = jsxTagName(child)
          const target = name ? componentTarget(module, name) : undefined
          if (target?.kind === 'router') renders.add(target.key)
        })
      }
      for (const prop of ['Component', 'ErrorBoundary', 'HydrateFallback']) {
        const attribute = jsxAttribute(node, prop)
        if (!attribute) continue
        const value = attributeValue(attribute)
        const target = value?.type === 'Identifier' ? componentTarget(module, String(value.name)) : { kind: 'unknown' as const }
        if (target.kind === 'router') renders.add(target.key)
        else if (wildcard && target.kind !== 'package') wildcardFailure(path!, where, `passes ${prop} a value that is neither a nested router nor a component from a known package`)
      }
      return { path, index, caseSensitive, renders: [...renders], children: collect(list(node, 'children'), where) }
    }

    const collect = (nodes: Node[], where: string): SourceRoute[] => {
      nodes.forEach(node => assertRouteChild(node, where))
      const routes: SourceRoute[] = []
      const visit = (node: Node) => {
        const name = jsxTagName(node) ?? ''
        if (routeNames.has(name)) { routes.push(readRoute(node, where)); return }
        // A nested <Routes> is its own router.
        if (routesNames.has(name)) return
        childNodes(node).forEach(visit)
      }
      nodes.forEach(visit)
      return routes
    }

    walkComponents(program, routesNames, (node, component) => {
      if (!component) fail('a <Routes> outside a named component; render it from a named component so the inventory can name its router')
      const attributes = list(field(node, 'openingElement'), 'attributes')
      if (attributes.some(attribute => attribute.type === 'JSXSpreadAttribute') || jsxAttribute(node, 'children')) {
        fail(`<Routes> in ${component} must declare route children as direct JSX children, not a children prop or prop spread`)
      }
      if (jsxAttribute(node, 'location')) fail(`<Routes> in ${component} uses a location prop; the route inventory must audit the browser location that the accessibility checks visit`)
      const count = routers.filter(router => router.name === component || router.name.startsWith(`${component}#`)).length
      routers.push({ name: count ? `${component}#${count + 1}` : component, file, component, routes: collect(list(node, 'children'), component) })
    })
    if (routeElements !== collectedRoutes) fail('a <Route> is outside every <Routes>, which the reader cannot place')
  }
  return routers
}

/** The values of the `key` properties in the array that `variable` names. */
function extractTabKeys(file: string, code: string, variable: string): string[] {
  let keys: string[] | undefined
  visitValues(parseModule({ file, code }).program, node => {
    if (node.type !== 'VariableDeclarator' || nameOf(field(node, 'id')) !== variable || field(node, 'init')?.type !== 'ArrayExpression') return
    keys = list(field(node, 'init'), 'elements').map(element => {
      const property = list(element, 'properties').find(item => item.type === 'Property' && staticKey(item) === 'key')
      return staticString(field(property, 'value')) ?? (() => { throw new Error(`Each tab key in ${variable} in ${file} must be a string literal so the inventory check can read it`) })()
    })
    return false
  })
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
  const byName = new Map<string, SourceRouter>()
  const byComponent = new Map<string, string[]>()
  for (const router of routers) {
    if (byName.has(router.name)) throw new Error(`multiple <Routes> components are named ${router.name}; the console route inventory requires unique router component names`)
    byName.set(router.name, router)
    const key = `${router.file}:${router.component}`
    byComponent.set(key, [...byComponent.get(key) ?? [], router.name])
  }
  const mounted = new Set<string>()

  const build = (declaring: string, routes: SourceRoute[], parent: string, handles: RouteHandle[], seen: Set<string>): RouteObject[] => routes.map(route => {
    const pattern = joinPattern(parent, route.path)
    const base = pattern.replace(/\/\*$/, '') || '/'
    const descendants = [...new Set(route.renders.flatMap(key => byComponent.get(key) ?? []))]
    const handle: RouteHandle = { router: declaring, pattern: route.index ? `${pattern} (index)` : pattern, splat: false }
    handles.push(handle)
    const children: RouteObject[] = build(declaring, route.children, base, handles, seen)
    for (const name of descendants) {
      if (seen.has(name)) throw new Error(`${name} renders itself through its routes`)
      mounted.add(name)
      children.push(...build(name, byName.get(name)!.routes, base, handles, new Set([...seen, name])))
    }
    handle.splat = !children.length && (route.path === '*' || !!route.path?.endsWith('/*'))
    if (route.index) return { index: true, caseSensitive: route.caseSensitive, handle }
    const path = descendants.length && route.path?.endsWith('/*') ? route.path.slice(0, -2) || '/' : route.path
    return { path, caseSensitive: route.caseSensitive, handle, children: children.length ? children : undefined }
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
    ...consoleRoutes.map(route => ({ path: route.path, routers: scopeRouters[route.scope], redirectToHome: !!route.redirectToHome, redirects: !!route.redirectToHome || (!!route.allowedPath && route.allowedPath !== route.path), label: `${route.scope} ${route.path}` })),
    ...surfaces.map(surface => ({ path: new URL(surface.path, 'http://inventory.invalid').pathname, routers: [surface.router], redirectToHome: false, redirects: false, label: `${surface.router} ${surface.path}` })),
  ]
}

type Inventory = {
  consoleRoutes: ConsoleRouteCase[]
  surfaces: EntrySurfaceCase[]
  scopeRouters: Record<ConsoleRouteCase['scope'], string[]>
  exclusions: RouteExclusion[]
  tabKeys: string[]
  /** The routes that pathReaders entries serve outside every <Route>, each under the name of its declaration. */
  servedRoutes: Record<string, string[]>
}

/**
 * Every disagreement between the routers and the inventory, as messages
 * that say what to change. An empty list means they agree.
 */
function inventoryProblems(routers: ResolvedRouter[], inventory: Inventory): string[] {
  const problems: string[] = []
  const servedRouters = Object.entries(inventory.servedRoutes).map(([name, patterns]): ResolvedRouter => {
    const handles = patterns.map(pattern => ({ router: name, pattern, splat: false }))
    return { name, objects: handles.map(handle => ({ path: handle.pattern, handle })), handles }
  })
  const all = [...routers, ...servedRouters]
  const byName = new Map(all.map(router => [router.name, router]))
  const handles = all.flatMap(router => router.handles)
  const covered = new Set<RouteHandle>()
  const tabs = new Set<string>()

  const named = new Set([...Object.values(inventory.scopeRouters).flat(), ...inventory.surfaces.map(surface => surface.router)])
  for (const router of routers) {
    if (!named.has(router.name)) problems.push(`router ${router.name} is mounted by no route element, and no scope or entry surface in e2e/console-routes.ts names it; render it directly in the element of the route it serves, or name it there`)
  }

  for (const entry of inventoryEntries(inventory.consoleRoutes, inventory.surfaces, inventory.scopeRouters)) {
    for (const name of entry.routers) {
      const router = byName.get(name)
      if (!router) { problems.push(`inventory entry ${entry.label} names router ${name}, which no <Routes> in src renders and no pathReaders entry serves`); continue }
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

function servedRoutesOf(readers: PathReader[]): Record<string, string[]> {
  const routes: Record<string, string[]> = {}
  for (const reader of readers) {
    if (!reader.serves) continue
    if (routes[reader.declaration]) throw new Error(`pathReaders has two entries named ${reader.declaration} that serve routes; the comparison names the router of their routes after the declaration, so rename one`)
    routes[reader.declaration] = reader.serves
  }
  return routes
}

const repositoryTree = readSourceTree()
const repositoryInventory: Inventory = {
  consoleRoutes: allConsoleRoutes,
  surfaces: entrySurfaces,
  scopeRouters: consoleScopeRouters,
  exclusions: routesWithoutInventoryEntry,
  tabKeys: extractTabKeys(unitDetailFile, readFileSync(join(repositoryRoot, unitDetailFile), 'utf8'), unitDetailTabsVariable),
  servedRoutes: servedRoutesOf(pathReaders),
}

describe('console route inventory', () => {
  const { sources, files } = repositoryTree
  const resolved = resolveRouters(extractRouters(sources, { routerFiles, files }))
  const pathCounts = pathReadCounts(sources)

  it('keeps non-test src inside the policy that lets the reader see every page', () => {
    expect(sources.map(source => source.file)).toEqual(expect.arrayContaining([...routerFiles, 'src/generated/api-types.ts']))
    expect(policyProblems(sources, { routerFiles, files })).toEqual([])
  })

  it('reads the routers that the console renders', () => {
    expect(resolved.map(router => router.name).sort()).toEqual(['AuthRoutes', 'PlatformShell', 'Shell', 'TotpEnrollmentShell'])
    const shell = resolved.find(router => router.name === 'Shell')!
    // JobCreationJourney's routes are resolved under /jobs/new/*.
    expect(shell.handles.filter(handle => handle.router === 'JobCreationJourney').map(label)).toEqual(['JobCreationJourney /jobs/new (index)', 'JobCreationJourney /jobs/new/advanced', 'JobCreationJourney /jobs/new/*'])
    expect(repositoryInventory.tabKeys).toEqual(expect.arrayContaining(['overview', 'accounts', 'capacity', 'danger']))
  })

  it('classifies every read of the path', () => {
    expect(pathReaderProblems(pathCounts, pathReaders)).toEqual([])
  })

  it('lists every route, page chosen from the path, and UnitDetail tab, and every entry still reaches its route', () => {
    expect(inventoryProblems(resolved, repositoryInventory)).toEqual([])
  })

  describe('the policy', () => {
    const policy = (sources: SourceFile[], options: Partial<PolicyOptions> = {}) => policyProblems(sources, { routerFiles: [], ...options })
    const unlisted = (where: string, specifier: string, verb = 'imports') => `${where} ${verb} ${specifier}, which knownPackages does not list; render the page from src, or add the package with the reason it cannot render a page that the inventory misses`

    it('refuses a component from an unlisted package rendered beside the router', () => {
      // The JSX route reader alone sees only Shell's route; ExtraRoutes could
      // render routes of its own beside it.
      const app = {
        file: 'src/main.tsx',
        code: `import { Route, Routes } from 'react-router-dom'
import { ExtraRoutes } from 'third-party-router'
export function Shell() { return <Routes><Route path="/" element={<p />} /></Routes> }
export function App() { return <><Shell /><ExtraRoutes /></> }`,
      }
      expect(resolveRouters(extractRouters([app])).map(router => [router.name, router.handles.map(label)])).toEqual([['Shell', ['Shell /']]])
      expect(policy([app], { routerFiles: ['src/main.tsx'] })).toEqual([unlisted('src/main.tsx', 'third-party-router')])
    })

    it('lets src import values only from the known packages, by name', () => {
      const refused: [string, string][] = [
        ['react-router', `import { Route, Routes } from 'react-router'`],
        ['react/jsx-runtime', `import { jsx } from 'react/jsx-runtime'`],
        ['node:module', `import { createRequire } from 'node:module'`],
        ['#route-tree', `import { NestedRoutes } from '#route-tree'`],
        ['@edgewatch/router-bindings', `import { Page, Pages } from '@edgewatch/router-bindings'`],
        ['https://routes.example/router.js', `import 'https://routes.example/router.js'`],
      ]
      for (const [specifier, code] of refused) {
        expect(policy([{ file: 'src/fixture.tsx', code }], { routerFiles: ['src/fixture.tsx'] }), specifier).toEqual([unlisted('src/fixture.tsx', specifier)])
      }
      expect(policy([{ file: 'src/fixture.ts', code: `import * as RR from 'react-router-dom'\nimport React, { useState } from 'react'` }])).toEqual([
        'src/fixture.ts imports react-router-dom with a namespace import; import package values by name, so this check sees each name',
        'src/fixture.ts imports react with a default import; import package values by name, so this check sees each name',
      ])
      // Types cannot render a page.
      expect(policy([{ file: 'src/fixture.ts', code: `import type { RouteObject } from 'react-router'\nimport { type Page } from 'third-party-router'\nexport type { RouteObject }` }])).toEqual([])
    })

    it('refuses package re-exports, so a package value cannot reach a router file under another name', () => {
      const cases = [
        ['third-party-router', `export { NestedRoutes } from 'third-party-router'`],
        ['third-party-router', `export * from 'third-party-router'`],
        ['react-router-dom', `export { Route as Page, Routes as Pages } from 'react-router-dom'`],
      ]
      for (const [specifier, code] of cases) {
        expect(policy([{ file: 'src/barrel.ts', code }]), code).toEqual([`src/barrel.ts re-exports ${specifier}; src may re-export only its own modules, so a package value cannot reach a router file under another name`])
      }
      expect(policy([{ file: 'src/barrel.ts', code: `export type { RouteObject } from 'react-router-dom'` }])).toEqual([])
    })

    it('lets src import local values only from the modules that it checks', () => {
      const shell = (imports: string) => ({ file: 'src/Shell.tsx', code: `${imports}\nexport function Shell() { return null }` })
      const page = { file: 'src/Page.tsx', code: 'export function Page() { return null }' }
      const index = { file: 'src/pages/index.tsx', code: 'export function Pages() { return null }' }
      const resolves = (imports: string, files: string[] = []) => policy([shell(imports), page, index], { files: new Set(['src/Shell.tsx', 'src/Page.tsx', 'src/pages/index.tsx', ...files]) })
      const refusal = (specifier: string, target: string, verb = 'imports') => `src/Shell.tsx ${verb} ${specifier}, which resolves to ${target}; src may load values only from its non-test TypeScript modules, which this check reads`

      expect(resolves(`import { Page } from './Page'\nimport { Pages } from './pages'\nimport { Page as Root } from '/src/Page.tsx'\nimport './styles.css'\nexport * from './Page'`, ['src/styles.css'])).toEqual([])
      expect(resolves(`import HiddenRoutes from './unreadable-router.js'`)).toEqual([refusal('./unreadable-router.js', 'no file in src')])
      expect(resolves(`import { Page, Pages } from '../router-bindings'`)).toEqual([refusal('../router-bindings', 'no file in src')])
      // Vite tries .js before .tsx, and an explicit .jsx names that file.
      expect(resolves(`import { Page } from './Page'`, ['src/Page.js'])).toEqual([refusal('./Page', 'src/Page.js')])
      expect(resolves(`import { Page } from './Page.jsx'`, ['src/Page.jsx'])).toEqual([refusal('./Page.jsx', 'src/Page.jsx')])
      expect(resolves(`import { renderPage } from './Page.test'`, ['src/Page.test.tsx'])).toEqual([refusal('./Page.test', 'src/Page.test.tsx')])
      expect(resolves(`import styles from './styles.css'`, ['src/styles.css'])).toEqual([refusal('./styles.css', 'src/styles.css')])
      expect(resolves(`export * from './missing'`)).toEqual([refusal('./missing', 'no file in src', 're-exports')])
    })

    it('reads only files that resolve inside src', () => {
      const root = mkdtempSync(join(tmpdir(), 'edgewatch-route-inventory-'))
      const outside = mkdtempSync(join(tmpdir(), 'edgewatch-route-inventory-outside-'))
      try {
        mkdirSync(join(root, 'src', 'test'), { recursive: true })
        for (const file of ['src/Shell.tsx', 'src/Shell.test.tsx', 'src/test/setup.ts', 'src/vite-env.d.ts', 'src/styles.css']) writeFileSync(join(root, file), 'export {}\n')
        expect(readSourceTree(root)).toEqual({
          sources: [{ file: 'src/Shell.tsx', code: 'export {}\n' }],
          files: new Set(['src/Shell.test.tsx', 'src/Shell.tsx', 'src/styles.css', 'src/test/setup.ts', 'src/vite-env.d.ts']),
        })
        writeFileSync(join(outside, 'Router.tsx'), 'export {}\n')
        symlinkSync(join(outside, 'Router.tsx'), join(root, 'src', 'Router.tsx'))
        expect(() => readSourceTree(root)).toThrow(/^src\/Router\.tsx resolves to .*Router\.tsx, outside src/)
        rmSync(join(root, 'src', 'Router.tsx'))
        symlinkSync(outside, join(root, 'src', 'linked'), 'dir')
        expect(() => readSourceTree(root)).toThrow(/^src\/linked resolves to .*, outside src/)
      } finally {
        rmSync(root, { recursive: true, force: true })
        rmSync(outside, { recursive: true, force: true })
      }
    })

    it('lets only the router files import Route and Routes, and refuses router APIs it cannot read', () => {
      const main = { file: 'src/main.tsx', code: `import { Route, Routes } from 'react-router-dom'` }
      const other = { file: 'src/Other.tsx', code: `import { Route as Page, Routes } from 'react-router-dom'\nimport { useRoutes, createBrowserRouter, RouterProvider, Link } from 'react-router-dom'` }
      const unread = (name: string) => `src/Other.tsx imports ${name} from react-router-dom, which routerExports does not list; the JSX route reader reads only <Routes> and <Route>, so add the name only if it neither builds routes nor reads the path`
      expect(policy([main, other], { routerFiles: ['src/main.tsx', 'src/gone.tsx'] })).toEqual([
        'routerFiles lists src/gone.tsx, which is not a checked module in src; remove it',
        'src/Other.tsx imports Route from react-router-dom but is not in routerFiles; declare routes in a router file, whose <Routes> the JSX route reader reads',
        'src/Other.tsx imports Routes from react-router-dom but is not in routerFiles; declare routes in a router file, whose <Routes> the JSX route reader reads',
        unread('useRoutes'),
        unread('createBrowserRouter'),
        unread('RouterProvider'),
      ])
    })

    it('refuses runtime module loads and element factories without an allowance', () => {
      const cases: [RuntimeConstruct, string, string][] = [
        ['import()', 'src/a.tsx', `export async function HiddenRouter() { const { Route, Routes } = await import('react-router-dom'); return <Routes><Route path="/hidden" /></Routes> }`],
        ['import()', 'src/b.ts', 'export const router = import(`react-router`)'],
        ['import()', 'src/c.ts', `const routerModule = 'react-router-dom'\nexport const load = () => import(routerModule)`],
        ['import()', 'src/d.ts', `export const routes = import('#route-tree')`],
        ['import.meta.glob', 'src/e.ts', `export const pages = import.meta.glob('./pages/*.tsx')`],
        ['require', 'src/f.tsx', `export function HiddenRouter() { const { Route, Routes } = require('react-router-dom'); return <Routes><Route path="/hidden" /></Routes> }`],
        ['require', 'src/g.ts', 'const loadModule = require\nexport const router = loadModule(\'react-router-dom\')'],
        ['require', 'src/h.ts', `export const router = module.require('react-router-dom')`],
        ['require', 'src/i.ts', `export const loadModule = module['require']`],
        ['require', 'src/j.ts', `const { require: loadRouter } = module\nexport const router = loadRouter('react-router-dom')`],
        ['require', 'src/k.ts', `export const router = Reflect.apply(module.require, module, ['react-router-dom'])`],
        ['require', 'src/l.ts', `export const router = (<typeof require>module.require)('react-router-dom')`],
        ['require', 'src/m.ts', `export const router = module?.require?.('react-router-dom')`],
        ['require', 'src/n.ts', `import router = require('react-router-dom')\nexport { router }`],
        ['lazy', 'src/o.tsx', `export const NestedRoutes = React.lazy(() => Promise.resolve({ default: window.routeRegistry.current }))`],
        ['lazy', 'src/p.tsx', `import { lazy as defer } from 'react'\nexport const NestedRoutes = defer(loadRoutes)`],
        ['createElement', 'src/q.tsx', `import { createElement as make } from 'react'\nexport const page = make(window.routeRegistry.current)`],
        ['createElement', 'src/r.tsx', `export const page = React.createElement(window.routeRegistry.current)`],
        ['createElement', 'src/s.tsx', `const { createElement: make } = React\nexport const page = make('main')`],
        ['cloneElement', 'src/t.tsx', `import { cloneElement } from 'react'\nexport const page = (element: React.ReactElement) => cloneElement(element, { path: '/hidden' })`],
      ]
      for (const [construct, file, code] of cases) {
        expect(policy([{ file, code }]), file).toContainEqual(expect.stringMatching(new RegExp(`^${file.replace('.', '\\.')}:\\d+ uses ${construct.replace(/[().]/g, '\\$&')}; the JSX route reader cannot follow a module loaded or an element created at runtime`)))
      }
    })

    it('refuses components read from globals that code outside the bundle could set', () => {
      const global = (where: string, name: string) => `${where} reads ${name}, which is neither declared or imported in the module nor in knownGlobals; a global that code outside the bundle sets could hold a page that the inventory cannot see`
      const routes = {
        file: 'src/Fallback.tsx',
        code: `import { Route, Routes } from 'react-router-dom'
const Page = window.routeRegistry.current
export function Fallback() { return <><Routes><Route path="child" element={<p>Child</p>} /></Routes><Page /></> }
export function Registry() { const Hidden = globalThis['route' + 'Registry']; return <><Hidden /><Pages.Hidden /><Extra /></> }
export function Leak() { return lookUp(self) ?? window[routeName] }`,
      }
      expect(policy([routes], { routerFiles: ['src/Fallback.tsx'] })).toEqual([
        global('src/Fallback.tsx:2', 'window.routeRegistry'),
        global('src/Fallback.tsx:4', 'globalThis.routeRegistry'),
        global('src/Fallback.tsx:4', 'Pages'),
        global('src/Fallback.tsx:4', 'Extra'),
        global('src/Fallback.tsx:5', 'lookUp'),
        global('src/Fallback.tsx:5', 'self'),
        global('src/Fallback.tsx:5', 'window.[computed]'),
        global('src/Fallback.tsx:5', 'routeName'),
      ])
      // Standard globals, a typeof probe, and a local binding named window are fine.
      expect(policy([{ file: 'src/ok.ts', code: `export const wide = typeof window !== 'undefined' && window.matchMedia('(min-width: 1px)').matches
export const path = window.location.pathname + JSON.stringify(new URL(document.baseURI))
export function label(window: { name: string }) { return window.name }` }])).toEqual([])
    })

    it('accepts a runtime construct that an allowance with a reason names, and still checks what it loads', () => {
      const page = { file: 'src/page.tsx', code: `import { createElement } from 'react'\nexport const element = createElement('main')` }
      const allowance: RuntimeAllowance = { file: 'src/page.tsx', construct: 'createElement', reason: 'Builds a DOM element that renders no page.' }
      expect(policy([page], { allowances: [allowance] })).toEqual([])
      expect(policy([page], { allowances: [{ ...allowance, reason: ' ' }] })).toEqual(['runtimeAllowances entry for createElement in src/page.tsx gives no reason'])
      expect(policy([{ file: 'src/other.ts', code: 'export {}' }], { allowances: [allowance] })).toEqual(['runtimeAllowances allows createElement in src/page.tsx, which does not use it; remove the entry'])

      const loads = {
        file: 'src/loads.ts',
        code: `export const local = () => import('./page')
export const external = () => import('third-party-router')
export const computed = (name: string) => import(name)
export const required = require('./legacy.jsx')`,
      }
      expect(policy([loads, page], {
        files: new Set(['src/loads.ts', 'src/page.tsx', 'src/legacy.jsx']),
        allowances: [allowance, { file: 'src/loads.ts', construct: 'import()', reason: 'Splits the bundle.' }, { file: 'src/loads.ts', construct: 'require', reason: 'Fixture.' }],
      })).toEqual([
        unlisted('src/loads.ts:2', 'third-party-router', 'loads'),
        'src/loads.ts:3 loads a module whose name is computed at runtime; the policy cannot check what it loads',
        'src/loads.ts:4 loads ./legacy.jsx, which resolves to src/legacy.jsx; src may load values only from its non-test TypeScript modules, which this check reads',
      ])
    })
  })

  describe('the path check', () => {
    const reader = {
      file: 'src/reader.tsx',
      code: `import { matchPath, useLocation, useMatch } from 'react-router-dom'
export function Kiosk() {
  const location = useLocation()
  const { pathname } = location
  if (location.pathname === '/kiosk' || window.location['pathname'].startsWith('/kiosk/')) return <main />
  const match = useMatch('/kiosk/:id')
  return matchPath('/kiosk', pathname) || match ? <main /> : null
}
const initial = window.location.pathname
export default function () { return <a href="/" title="pathname">{initial}</a> }`,
    }

    it('counts every path read and path matcher by top-level declaration', () => {
      expect(pathReadCounts([reader])).toEqual([
        { file: 'src/reader.tsx', declaration: 'Kiosk', reads: 5, lines: [4, 5, 5, 6, 7] },
        { file: 'src/reader.tsx', declaration: 'initial', reads: 1, lines: [9] },
      ])
    })

    it('fails on a read that no entry classifies, on a changed count, and on a stale or unexplained entry', () => {
      expect(pathReaderProblems(pathReadCounts([reader]), [
        { file: 'src/reader.tsx', declaration: 'Kiosk', reads: 4, reason: 'Fixture.' },
        { file: 'src/reader.tsx', declaration: 'Gone', reads: 1, reason: ' ' },
      ])).toEqual([
        'Kiosk in src/reader.tsx reads the path 5 times (line 4, 5, 5, 6, 7), but its pathReaders entry allows 4; update the entry with the routes of any page that a new read chooses, or with why it chooses none',
        'initial in src/reader.tsx reads the path 1 time (line 9) and has no pathReaders entry; list the routes of the pages that the reads choose outside every <Route> so the inventory audits them, or say why they choose none',
        'pathReaders lists Gone in src/reader.tsx, which reads no path; remove the entry',
        'pathReaders entry for Gone in src/reader.tsx gives no reason',
      ])
    })

    it('fails when AppContent chooses another page from the path', () => {
      const main = repositoryTree.sources.find(source => source.file === 'src/main.tsx')!
      const anchor = '  if (isPublic) return <PublicDashboard slug={publicSlug} />\n'
      expect(main.code).toContain(anchor)
      const probe = { ...main, code: main.code.replace(anchor, `  if (location.pathname === '/kiosk') return <PublicDashboard slug="kiosk" />\n${anchor}`) }
      const counts = [...pathCounts.filter(count => count.file !== main.file), ...pathReadCounts([probe])]
      // The policy and the JSX route reader accept the probe; the path check
      // refuses it until its entry lists the page, which then needs an
      // inventory entry.
      expect(policyProblems([probe], { routerFiles, files })).toEqual([])
      expect(resolveRouters(extractRouters([probe], { files }))).toEqual(resolveRouters(extractRouters([main], { files })))
      expect(pathReaderProblems(counts, pathReaders)).toEqual([
        expect.stringMatching(/^AppContent in src\/main\.tsx reads the path 3 times \(line \d+, \d+, \d+\), but its pathReaders entry allows 2;/),
      ])
      const served = pathReaders.map(entry => entry.declaration === 'AppContent' ? { ...entry, reads: 3, serves: [...entry.serves!, '/kiosk'] } : entry)
      expect(pathReaderProblems(counts, served)).toEqual([])
      expect(inventoryProblems(resolved, { ...repositoryInventory, servedRoutes: servedRoutesOf(served) })).toEqual([
        'route AppContent /kiosk has no entry in e2e/console-routes.ts; add one so the axe audit and role matrix visit it, or exclude it with a reason in routesWithoutInventoryEntry',
      ])
    })
  })

  describe('the JSX route reader', () => {
    const read = (code: string, file = 'src/fixture.tsx') => extractRouters([{ file, code }])
    const paths = (routers: SourceRouter[]) => routers.map(router => [router.name, router.routes.map(route => route.path)])

    it('refuses routes it cannot read', () => {
      expect(() => read(`import { Route, Routes } from 'react-router-dom'\nconst base = '/x'\nexport function A() { return <Routes><Route path={base} element={<p />} /></Routes> }`)).toThrow(/must be a string literal/)
      expect(() => read(`import { Route } from 'react-router-dom'\nexport function C() { return <main><Route path="/c" element={<p />} /></main> }`)).toThrow(/a <Route> is outside every <Routes>/)
      expect(() => read(`import { Route, Routes } from 'react-router-dom'\nexport default () => <Routes><Route path="/x" /></Routes>`)).toThrow(/a <Routes> outside a named component/)
      // A namespace-style element is refused even beside readable routes, so
      // its route cannot hide among them.
      expect(() => read(`import { Route, Routes } from 'react-router-dom'\nexport function H() { return <Routes><Route path="/visible" /><RR.Route path="/hidden" /></Routes> }`)).toThrow(/<Routes> in H contains an unsupported child \(<RR\.Route>\)/)
      // An aliased import is still read.
      expect(paths(read(`import { Route as Page, Routes as Pages } from 'react-router-dom'\nexport function D() { return <Pages><Page path="/d" element={<p />} /></Pages> }`))).toEqual([['D', ['/d']]])
    })

    it('refuses Route and Routes used as values outside a JSX tag', () => {
      const imports = `import { Route, Routes } from 'react-router-dom'`
      const cases = [
        `${imports}\nconst HiddenRoute = Route\nexport function I() { return <Routes><Route path="/visible" /><HiddenRoute path="/hidden" /></Routes> }`,
        `${imports}\nconst HiddenRoutes = Routes\nexport function J() { return <HiddenRoutes><Route path="/visible" /></HiddenRoutes> }`,
        `${imports}\nfunction HiddenRouter({ Route: RouteComponent }) { return <RouteComponent path="/hidden" /> }\nexport function App() { return <HiddenRouter Route={Route} /> }`,
        `${imports}\nexport function App() { return <HiddenRouter {...{ Route, Routes }} /> }`,
        `${imports}\nexport function App() { return makeRouter(Route, Routes) }`,
        `${imports}\nexport { Route as Page }`,
        `${imports}\nexport function K() { return <Routes><Route path="/visible" />{createElement(Route, { path: '/hidden' })}</Routes> }`,
        `${imports}\nexport function L({ Route }: { Route: React.ComponentType }) { return <Routes><Route path="/shadowed" /></Routes> }`,
      ]
      for (const code of cases) expect(() => read(code), code).toThrow(/uses (Route|Routes) as a value; use Route and Routes only as JSX tag names/)
    })

    it('refuses Route props and children that could hide the effective path or nested routes', () => {
      const route = (attribute: string, declarations = '') => `import { Route, Routes } from 'react-router-dom'
${declarations}
export function K() { return <Routes><Route path="/visible" element={<Visible />} /><Route ${attribute} /></Routes> }`
      for (const attribute of [
        `path="/known" {...{ path: "/hidden", element: <HiddenPage /> }}`,
        `{...{ path: "/hidden", element: <HiddenPage /> }} path="/known"`,
        `path="/known" {...hiddenProps}`,
        `{...(showHidden ? hiddenProps : {})} path="/known"`,
      ]) expect(() => read(route(attribute)), attribute).toThrow(/<Route> in K uses a JSX prop spread; the reader requires explicit props/)
      for (const attribute of [
        `path="/parent" children={<Route path="hidden" element={<HiddenPage />} />}`,
        `path="/parent" children={hiddenRoutes}`,
        `path="/parent" children={showHidden ? getHiddenRoutes() : null}`,
      ]) expect(() => read(route(attribute)), attribute).toThrow(/<Route> in K uses a children attribute; declare nested routes as direct JSX children/)
      expect(() => read(route(`path="/known" lazy={loadRoute}`))).toThrow(/<Route> in K uses a lazy prop; the reader cannot read a route that loads at runtime/)
      expect(() => read(route(`path="/known*" element={<p />}`))).toThrow(/uses non-canonical wildcard path \/known\*; put the splat '\*' in its own final path segment/)
    })

    it('refuses non-JSX <Routes> children, children props, spreads, and location overrides', () => {
      const routes = (children: string) => `import { Route, Routes } from 'react-router-dom'\nexport function K() { return <Routes><Route path="/visible" />${children}</Routes> }`
      expect(() => read(routes('{hiddenRoutes}'))).toThrow(/<Routes> in K contains an unsupported child \(Identifier\)/)
      expect(() => read(routes('{paths.map(path => <Route path={path} />)}'))).toThrow(/<Routes> in K contains an unsupported child \(CallExpression\)/)
      expect(() => read(routes('<HiddenRoutes />'))).toThrow(/<Routes> in K contains an unsupported child \(<HiddenRoutes>\)/)
      const attributes = (attribute: string) => `import { Route, Routes } from 'react-router-dom'\nexport function HiddenRouter() { return <Routes ${attribute} /> }`
      for (const attribute of ['children={<Route path="/hidden" />}', '{...routerProps}']) {
        expect(() => read(attributes(attribute)), attribute).toThrow(/<Routes> in HiddenRouter must declare route children as direct JSX children/)
      }
      expect(() => read(`import { Route, Routes } from 'react-router-dom'\nexport function Shell() { return <Routes location="/other"><Route path="/known" /></Routes> }`)).toThrow(/uses a location prop; the route inventory must audit the browser location/)
    })

    it('reads routes in fragments, conditions, and arrays', () => {
      const code = `import { Fragment as Group } from 'react'
import { Route, Routes } from 'react-router-dom'
export function O({ admin }: { admin: boolean }) {
  return <Routes>
    <><Route path="/short" /></>
    <Group><Route path="/named" /></Group>
    {admin && <Route path="/admin" />}
    {admin ? <Route path="/yes" /> : null}
    {[<Route key="a" path="/listed" />]}
  </Routes>
}`
      expect(paths(read(code))).toEqual([['O', ['/short', '/named', '/admin', '/yes', '/listed']]])
    })

    it('treats only shorthand and literal true index props as index routes', () => {
      const source = {
        file: 'src/index-props.tsx',
        code: `import { Route, Routes } from 'react-router-dom'
export function IndexProps() {
  return <Routes>
    <Route path="/short"><Route index element={<p />} /></Route>
    <Route path="/literal"><Route index={true} element={<p />} /></Route>
    <Route path="/parent"><Route index={false} path="child"><Route path="deep" element={<p />} /></Route></Route>
  </Routes>
}`,
      }
      const router = resolveRouters(extractRouters([source]))[0]
      expect(router.handles.map(label)).toEqual([
        'IndexProps /short',
        'IndexProps /short (index)',
        'IndexProps /literal',
        'IndexProps /literal (index)',
        'IndexProps /parent',
        'IndexProps /parent/child',
        'IndexProps /parent/child/deep',
      ])
      expect(matchRoutes(router.objects, '/short')?.at(-1)?.route.handle).toEqual(router.handles[1])
      expect(matchRoutes(router.objects, '/literal')?.at(-1)?.route.handle).toEqual(router.handles[3])
      expect(matchRoutes(router.objects, '/parent/child/deep')?.at(-1)?.route.handle).toEqual(router.handles[6])
      expect(() => read(`import { Route, Routes } from 'react-router-dom'\nexport function DynamicIndex({ isIndex }: { isIndex: boolean }) { return <Routes><Route index={isIndex} path="/dynamic" /></Routes> }`)).toThrow(/non-literal index prop/)
    })

    it('preserves case-sensitive route matching', () => {
      const router = resolveRouters(read(`import { Route, Routes } from 'react-router-dom'\nexport function Shell() { return <Routes><Route path="/Admin/*" caseSensitive element={<p />} /><Route path="/Reports/*" caseSensitive={false} element={<p />} /></Routes> }`))[0]
      expect(matchRoutes(router.objects, '/Admin/users')).not.toBeNull()
      expect(matchRoutes(router.objects, '/admin/users')).toBeNull()
      expect(router.objects[1].caseSensitive).toBe(false)
      expect(() => read(`import { Route, Routes } from 'react-router-dom'\nexport function Shell({ strict }: { strict: boolean }) { return <Routes><Route path="/Admin" caseSensitive={strict} /></Routes> }`)).toThrow(/non-literal caseSensitive prop/)
    })

    it('lets a wildcard route render only a nested router, a component from a known package, and markup', () => {
      const shell = (route: string, declarations = '') => `import { Navigate, Route, Routes } from 'react-router-dom'
import { NestedRoutes as PackageRoutes } from 'third-party-router'
import * as Local from './local'
${declarations}
function NestedRoutes() { return <Routes><Route path="child" element={<p />} /></Routes> }
function Fallback() { return <main /> }
export function Shell({ page, Page }: { page: React.ReactNode; Page: React.ComponentType }) {
  return <Routes><Route path="/known/*" ${route} /></Routes>
}`
      const refused: [string, RegExp, string?][] = [
        ['element={<Fallback />}', /renders <Fallback>, a local component that renders no <Routes> of its own/],
        ['element={<Registry />}', /renders <Registry>, a local component that renders no <Routes> of its own/, 'const Registry = window.routeRegistry.current'],
        ['element={<Navigate to="/" state={{ page: <Fallback /> }} />}', /renders <Fallback>, a local component/],
        ['element={<Page />}', /renders <Page>, which is not a module-level component that this check can resolve/],
        ['element={<PackageRoutes />}', /renders <PackageRoutes> from third-party-router, which knownPackages does not list/],
        ['element={<Local.Fallback />}', /renders <Local\.Fallback>; import the component by name/],
        ['element={page}', /has an unreadable element prop \(Identifier\)/],
        ['element={renderPage()}', /has an unreadable element prop \(CallExpression\)/],
        ['element={React.createElement(NestedRoutes)}', /has an unreadable element prop \(CallExpression\)/],
        ['element={page ?? <main />}', /has an unreadable element prop \(Identifier\)/],
        ['element={<main>{page}</main>}', /has an unreadable child \(Identifier\)/],
        ['element={<main children={page} />}', /has an unreadable children prop \(Identifier\)/],
        ['element={<Navigate {...redirect} />}', /spreads props into <Navigate>/],
        ['errorElement={<Fallback />}', /renders <Fallback>, a local component/],
        ['hydrateFallbackElement={<Fallback />}', /renders <Fallback>, a local component/],
        ['Component={Fallback}', /passes Component a value that is neither a nested router nor a component from a known package/],
        ['Component={Page}', /passes Component a value that is neither a nested router nor a component from a known package/],
        ['Component={resolveComponent()}', /passes Component a value that is neither a nested router nor a component from a known package/],
        ['ErrorBoundary={Fallback}', /passes ErrorBoundary a value that/],
        ['HydrateFallback={Fallback}', /passes HydrateFallback a value that/],
      ]
      for (const [route, error, declarations] of refused) {
        expect(() => read(shell(route, declarations)), route).toThrow(new RegExp(`<Route path="/known/\\*"> in Shell ${error.source}`))
      }
      // A name bound twice is shadowed somewhere, so the check cannot tell
      // which one the route renders.
      expect(() => read(shell('element={<NestedRoutes />}').replace('function Fallback() { return <main /> }', 'function Fallback({ NestedRoutes }: { NestedRoutes: React.ComponentType }) { return <NestedRoutes /> }'))).toThrow(/renders <NestedRoutes>, which is not a module-level component/)

      for (const route of [
        'element={<main><h1>Moved</h1>{null}<Navigate to="/" /></main>}',
        'element={<><Wifi aria-hidden /></>}',
      ]) expect(() => read(shell(route, `import { Wifi } from 'lucide-react'`)), route).not.toThrow()
      for (const route of [
        'element={<NestedRoutes />}',
        'Component={NestedRoutes}',
        'element={page ? <NestedRoutes /> : <Navigate to="/" replace state={{ from: { pathname: "/known" } }} />}',
      ]) {
        const routers = resolveRouters(read(shell(route)))
        expect(routers.map(router => [router.name, router.handles.map(label)]), route).toEqual([['Shell', ['Shell /known/*', 'NestedRoutes /known/child']]])
      }
      // Routes without a splat may render any page.
      expect(read(shell('element={page}').replace('/known/*', '/known')).find(router => router.name === 'Shell')!.routes).toEqual([{ path: '/known', index: false, caseSensitive: undefined, renders: [], children: [] }])
    })

    it('mounts a nested router imported from the module that declares it, under any export or import name', () => {
      const shell = (imports: string, tag: string) => ({ file: 'src/Shell.tsx', code: `import { Route, Routes } from 'react-router-dom'\n${imports}\nexport function Shell() { return <Routes><Route path="/known/*" element={<${tag} />} /></Routes> }` })
      const renamed = { file: 'src/Fallback.tsx', code: `import { Route, Routes } from 'react-router-dom'\nfunction RuntimeFallback() { return <Routes><Route path="child" element={<p>Child</p>} /></Routes> }\nexport { RuntimeFallback as Fallback }` }
      const defaulted = { file: 'src/Router.tsx', code: `import { Route, Routes } from 'react-router-dom'\nexport default function Router() { return <Routes><Route path="child" element={<p />} /></Routes> }` }
      for (const sources of [
        [shell(`import { Fallback as ImportedFallback } from './Fallback'`, 'ImportedFallback'), renamed],
        [shell(`import Nested from './Router'`, 'Nested'), defaulted],
      ]) {
        const shellRouter = resolveRouters(extractRouters(sources)).find(router => router.name === 'Shell')!
        expect(matchRoutes(shellRouter.objects, '/known/child')?.at(-1)?.route.handle).toMatchObject({ pattern: '/known/child' })
      }
      // A barrel is not the module that declares the router, and a module
      // without <Routes> declares none.
      const barrel = { file: 'src/barrel.ts', code: `export { Fallback } from './Fallback'` }
      const plain = { file: 'src/Plain.tsx', code: `export function Plain() { return <main /> }` }
      expect(() => extractRouters([shell(`import { Fallback } from './barrel'`, 'Fallback'), barrel, renamed])).toThrow(/renders <Fallback>, a local component that renders no <Routes> of its own; import a nested router from the module that declares it/)
      expect(() => extractRouters([shell(`import { Plain } from './Plain'`, 'Plain'), plain])).toThrow(/renders <Plain>, a local component that renders no <Routes> of its own/)
    })
  })

  describe('the inventory comparison', () => {
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
      surfaces: [],
      scopeRouters: { unit: ['Shell'], platform: [], shared: ['Shell'] },
      exclusions: [],
      tabKeys: [],
      servedRoutes: {},
    }
    const problems = (routes: string, inventory: Partial<Inventory> = {}) => inventoryProblems(resolveRouters(extractRouters([shell(routes)])), { ...baseInventory, ...inventory })
    const missing = (route: string) => `route ${route} has no entry in e2e/console-routes.ts; add one so the axe audit and role matrix visit it, or exclude it with a reason in routesWithoutInventoryEntry`

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
      expect(problems(`${baseRoutes}<Route path="/reports" element={<p />} />`)).toEqual([missing('Shell /reports')])
      // A route nested inside another <Route> counts too.
      expect(problems(`${baseRoutes}<Route path="/reports"><Route path="weekly" element={<p />} /></Route>`)).toEqual([missing('Shell /reports'), missing('Shell /reports/weekly')])
    })

    it('fails when a route loses its inventory entry', () => {
      expect(problems(baseRoutes, { consoleRoutes: baseInventory.consoleRoutes.filter(route => route.path !== '/wizard/step') })).toEqual([missing('Wizard /wizard/step')])
    })

    it('fails when an entry outlives its route', () => {
      expect(problems(`<Route path="/" element={<p />} /><Route path="/wizard/*" element={<Wizard />} />`)).toEqual([
        'inventory entry unit /items/item-1 reaches only the catch-all Shell *; remove it, restore its route, or mark the redirect',
      ])
    })

    it('does not treat a self-mapped allowedPath as a redirect', () => {
      expect(problems(`${baseRoutes}<Route path="/known/*" element={<Navigate to="/" />} />`, {
        consoleRoutes: [...baseInventory.consoleRoutes, { path: '/known', scope: 'unit', allowedPath: '/known' }],
      })).toEqual(['inventory entry unit /known reaches only the catch-all Shell /known/*; remove it, restore its route, or mark the redirect'])
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

    it('fails on a router that no route mounts and the inventory does not name', () => {
      const extra = { file: 'src/extra.tsx', code: `import { Route, Routes } from 'react-router-dom'\nexport function ExtraRoutes() { return <Routes><Route path="/extra" element={<p />} /></Routes> }` }
      expect(inventoryProblems(resolveRouters(extractRouters([shell(baseRoutes), extra])), baseInventory)).toEqual([
        'router ExtraRoutes is mounted by no route element, and no scope or entry surface in e2e/console-routes.ts names it; render it directly in the element of the route it serves, or name it there',
        missing('ExtraRoutes /extra'),
      ])
    })

    it('requires an entry surface for every route that a path reader serves', () => {
      const surface = (path: string): EntrySurfaceCase => ({ path, router: 'AppContent', state: 'public', heading: '' })
      const servedRoutes = { AppContent: ['/public', '/public/:slug', '/activate'] }
      expect(problems(baseRoutes, { servedRoutes, surfaces: [surface('/public'), surface('/public/unit'), { ...surface('/activate#token=T'), state: 'signed-in' }] })).toEqual([])
      expect(problems(baseRoutes, { servedRoutes, surfaces: [surface('/public'), surface('/public/unit'), surface('/kiosk')] })).toEqual([
        'inventory entry AppContent /kiosk matches no route of AppContent; remove it or restore its route',
        missing('AppContent /activate'),
      ])
      expect(() => servedRoutesOf([
        { file: 'src/a.tsx', declaration: 'Dispatch', reads: 1, serves: ['/a'], reason: 'Fixture.' },
        { file: 'src/b.tsx', declaration: 'Dispatch', reads: 1, serves: ['/b'], reason: 'Fixture.' },
      ])).toThrow(/pathReaders has two entries named Dispatch that serve routes/)
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

    it('names same-named routers from different modules apart and refuses ambiguous or self-mounting routers', () => {
      const sources = [
        { file: 'src/one/SharedRoutes.tsx', code: `import { Route, Routes } from 'react-router-dom'\nexport function SharedRoutes() { return <Routes><Route path="/one" /></Routes> }` },
        { file: 'src/two/SharedRoutes.tsx', code: `import { Route, Routes } from 'react-router-dom'\nexport function SharedRoutes() { return <Routes><Route path="/two" /></Routes> }` },
      ]
      const routers = resolveRouters(extractRouters(sources))
      expect(routers.flatMap(router => router.handles.map(label))).toEqual(['SharedRoutes /one', 'SharedRoutes#2 /two'])
      expect(resolveRouters(extractRouters([...sources].reverse()))).toEqual(routers)
      expect(() => resolveRouters([
        { name: 'Ambiguous', file: 'src/a.tsx', component: 'Ambiguous', routes: [] },
        { name: 'Ambiguous', file: 'src/b.tsx', component: 'Ambiguous', routes: [] },
      ])).toThrow(/multiple <Routes> components are named Ambiguous/)
      const loop = { file: 'src/loop.tsx', code: `import { Route, Routes } from 'react-router-dom'\nexport function Loop() { return <Routes><Route path="/a/*" element={<Loop />} /></Routes> }` }
      expect(() => resolveRouters(extractRouters([loop]))).toThrow(/Loop renders itself through its routes/)
    })
  })
})
