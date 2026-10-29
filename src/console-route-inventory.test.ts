import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, realpathSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { dirname, extname, isAbsolute, join, relative, resolve } from 'node:path'
import { tmpdir } from 'node:os'
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
  /** Explicit React Router path case handling. */
  caseSensitive?: boolean
  /** The components that its element renders, such as a descendant router. */
  renders: string[]
  /** Local imported components must expose a statically named nested router in wildcard routes. */
  localRenders?: string[]
  /** Local component values whose render bodies cannot be followed safely. */
  unreadableLocalRenders?: string[]
  /** External package components the inventory cannot inspect for nested routes. */
  uninspectableRenders: { component: string; source: string; file: string }[]
  children: SourceRoute[]
}

type SourceRouter = {
  /** The component that renders the `<Routes>`. */
  name: string
  routes: SourceRoute[]
}

type SourceFile = { file: string; code: string }
const compareSourceFiles = (left: SourceFile, right: SourceFile) => left.file < right.file ? -1 : left.file > right.file ? 1 : 0

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

/** TypeScript, parenthesized, and parser wrappers ignored when identifying a loader expression. */
const transparentExpressionTypes = new Set([
  'TSAsExpression',
  'TSTypeAssertion',
  'TSNonNullExpression',
  'TSSatisfiesExpression',
  'TSInstantiationExpression',
  'ParenthesizedExpression',
  'ChainExpression',
])

function unwrapTransparentExpression(node: Node | undefined): Node | undefined {
  let expression = node
  while (expression && transparentExpressionTypes.has(expression.type)) {
    const inner = expression.expression
    if (!isNode(inner)) return undefined
    expression = inner
  }
  return expression
}

function staticStringValue(node: Node | undefined): string | undefined {
  if (!node) return undefined
  if (node.type === 'Literal' && typeof node.value === 'string') return node.value
  if (node.type === 'TemplateLiteral' && (node.expressions as Node[]).length === 0) {
    const value = (node.quasis as Node[])[0].value as { cooked: string | null; raw: string }
    return value.cooked ?? value.raw
  }
  if (node.type === 'BinaryExpression' && node.operator === '+') {
    const left = staticStringValue(node.left as Node)
    const right = staticStringValue(node.right as Node)
    if (left !== undefined && right !== undefined) return left + right
  }
  const expression = unwrapTransparentExpression(node)
  if (expression !== node) return staticStringValue(expression)
  return undefined
}

function memberPropertyName(node: Node): string | undefined {
  node = unwrapTransparentExpression(node) ?? node
  if (node.type !== 'MemberExpression' && node.type !== 'OptionalMemberExpression') return undefined
  const property = node.property as Node
  return node.computed ? staticStringValue(property) : property.type === 'Identifier' ? String(property.name) : undefined
}

/** Returns a statically named identifier/member chain such as `registry.Page`. */
function staticMemberPath(node: Node | undefined): string | undefined {
  const expression = unwrapTransparentExpression(node)
  if (!expression) return undefined
  if (expression.type === 'Identifier') return String(expression.name)
  if (expression.type !== 'MemberExpression' && expression.type !== 'OptionalMemberExpression') return undefined
  const object = staticMemberPath(expression.object as Node | undefined)
  const property = memberPropertyName(expression)
  return object && property !== undefined ? `${object}.${property}` : undefined
}

/** Returns a statically named JSX member chain such as `Pages.NestedRoutes`. */
function jsxMemberStaticPath(node: Node | undefined): string | undefined {
  if (!node) return undefined
  const members: string[] = []
  let current = node
  while (current.type === 'JSXMemberExpression') {
    const property = current.property as Node | undefined
    if (property?.type !== 'JSXIdentifier') return undefined
    members.unshift(String(property.name))
    current = current.object as Node
  }
  return current.type === 'JSXIdentifier' ? [String(current.name), ...members].join('.') : undefined
}

function memberRootIdentifier(node: Node | undefined): string | undefined {
  let expression = unwrapTransparentExpression(node)
  while (expression && (expression.type === 'MemberExpression' || expression.type === 'OptionalMemberExpression')) {
    expression = unwrapTransparentExpression(expression.object as Node | undefined)
  }
  return expression?.type === 'Identifier' ? String(expression.name) : undefined
}

function isCommonJSModuleObject(node: Node | undefined, moduleAliases: Set<string>): boolean {
  node = unwrapTransparentExpression(node)
  return node?.type === 'Identifier' && moduleAliases.has(String(node.name))
}

function destructuresCommonJSRequire(pattern: Node): boolean {
  if (pattern.type !== 'ObjectPattern') return false
  return (pattern.properties as Node[]).some(property => {
    if (property.type !== 'Property' && property.type !== 'ObjectProperty') return false
    const key = property.key as Node
    const name = property.computed ? staticStringValue(key) : key.type === 'Identifier' ? String(key.name) : staticStringValue(key)
    return name === 'require'
  })
}

function isCommonJSLoader(node: Node | undefined, loaderAliases: Set<string>, moduleAliases: Set<string>): boolean {
  node = unwrapTransparentExpression(node)
  if (!node) return false
  if (node.type === 'Identifier') return loaderAliases.has(String(node.name))
  if (node.type !== 'MemberExpression' && node.type !== 'OptionalMemberExpression') return false
  const object = node.object as Node
  return isCommonJSModuleObject(object, moduleAliases) && memberPropertyName(node) === 'require'
}

function isOptionalCommonJSLoaderCall(node: Node, callee: Node): boolean {
  const unwrappedCallee = unwrapTransparentExpression(callee)
  return node.type === 'OptionalCallExpression'
    || node.optional === true
    || unwrappedCallee?.type === 'OptionalMemberExpression'
    || (unwrappedCallee?.type === 'MemberExpression' && unwrappedCallee.optional === true)
}

/**
 * Finds CommonJS loader aliases in one syntax-tree pass, then propagates
 * aliases through a dependency worklist. A chain declared in reverse order
 * therefore takes linear work instead of rescanning the whole program for
 * each newly discovered alias.
 */
function discoverCommonJSAliases(program: Node): { loaderAliases: Set<string>; moduleAliases: Set<string>; workItems: number } {
  const moduleAliasDependents = new Map<string, string[]>()
  const loaderAliasDependents = new Map<string, string[]>()
  const moduleLoaderDependents = new Map<string, string[]>()
  const createRequireAliases = new Set<string>()
  const createRequireAliasDependents = new Map<string, string[]>()
  const createRequireNamespaces = new Set<string>()
  const createRequireNamespaceDependents = new Map<string, string[]>()
  const namespaceCreateRequireDependents = new Map<string, string[]>()
  const createRequireLoaderDependents = new Map<string, string[]>()
  const namespaceLoaderDependents = new Map<string, string[]>()
  let workItems = 0

  const addDependent = (dependents: Map<string, string[]>, dependency: string, alias: string) => {
    const aliases = dependents.get(dependency) ?? []
    aliases.push(alias)
    dependents.set(dependency, aliases)
  }
  const collectAlias = (id: Node, value: Node | undefined) => {
    if (id.type !== 'Identifier' || !value) return
    const alias = String(id.name)
    const expression = unwrapTransparentExpression(value)
    if (expression?.type === 'Identifier') {
      const dependency = String(expression.name)
      // An identifier can be either kind of alias. Preserve both edges so
      // chains remain correct even when a binding has more than one role.
      addDependent(moduleAliasDependents, dependency, alias)
      addDependent(loaderAliasDependents, dependency, alias)
      return
    }
    if (expression && (expression.type === 'MemberExpression' || expression.type === 'OptionalMemberExpression')
      && memberPropertyName(expression) === 'require') {
      const object = unwrapTransparentExpression(expression.object as Node)
      if (object?.type === 'Identifier') addDependent(moduleLoaderDependents, String(object.name), alias)
    }
  }
  const propertyName = (property: Node, computed: boolean) => computed
    ? staticStringValue(property)
    : property.type === 'Identifier' ? String(property.name) : staticStringValue(property)
  const bindingName = (node: Node | undefined): string | undefined => node?.type === 'Identifier' ? String(node.name) : undefined
  const collect = (node: Node) => {
    workItems += 1
    if (node.type === 'ImportDeclaration' && ['node:module', 'module'].includes(String((node.source as Node).value))) {
      for (const specifier of node.specifiers as Node[]) {
        const localName = bindingName(specifier.local as Node)
        if (!localName) continue
        if (specifier.type === 'ImportSpecifier' && String((specifier.imported as Node).name) === 'createRequire') createRequireAliases.add(localName)
        if (specifier.type === 'ImportNamespaceSpecifier') createRequireNamespaces.add(localName)
      }
    }
    if (node.type === 'VariableDeclarator') {
      const id = node.id as Node
      const value = unwrapTransparentExpression(node.init as Node | undefined)
      collectAlias(id, node.init as Node | undefined)
      if (id.type === 'Identifier' && value?.type === 'Identifier') {
        addDependent(createRequireAliasDependents, String(value.name), String(id.name))
        addDependent(createRequireNamespaceDependents, String(value.name), String(id.name))
      }
      if (id.type === 'Identifier' && value?.type === 'MemberExpression'
        && memberPropertyName(value) === 'createRequire') {
        const object = unwrapTransparentExpression(value.object as Node)
        if (object?.type === 'Identifier') addDependent(namespaceCreateRequireDependents, String(object.name), String(id.name))
      }
      if (id.type === 'Identifier' && (value?.type === 'CallExpression' || value?.type === 'OptionalCallExpression')) {
        const callee = unwrapTransparentExpression(value.callee as Node)
        if (callee?.type === 'Identifier') addDependent(createRequireLoaderDependents, String(callee.name), String(id.name))
        else if (callee && (callee.type === 'MemberExpression' || callee.type === 'OptionalMemberExpression')
          && memberPropertyName(callee) === 'createRequire') {
          const object = unwrapTransparentExpression(callee.object as Node)
          if (object?.type === 'Identifier') addDependent(namespaceLoaderDependents, String(object.name), String(id.name))
        }
      }
      if (id.type === 'ObjectPattern' && value?.type === 'Identifier') {
        for (const property of id.properties as Node[]) {
          if (property.type !== 'Property' && property.type !== 'ObjectProperty') continue
          const key = propertyName(property.key as Node, property.computed === true)
          const alias = bindingName(property.value as Node)
          if (key === 'createRequire' && alias) addDependent(namespaceCreateRequireDependents, String(value.name), alias)
        }
      }
    }
    if (node.type === 'AssignmentExpression') {
      const id = node.left as Node
      const value = unwrapTransparentExpression(node.right as Node | undefined)
      collectAlias(id, node.right as Node | undefined)
      if (id.type === 'Identifier' && value?.type === 'Identifier') {
        addDependent(createRequireAliasDependents, String(value.name), String(id.name))
        addDependent(createRequireNamespaceDependents, String(value.name), String(id.name))
      }
      if (id.type === 'Identifier' && (value?.type === 'CallExpression' || value?.type === 'OptionalCallExpression')) {
        const callee = unwrapTransparentExpression(value.callee as Node)
        if (callee?.type === 'Identifier') addDependent(createRequireLoaderDependents, String(callee.name), String(id.name))
        else if (callee && (callee.type === 'MemberExpression' || callee.type === 'OptionalMemberExpression')
          && memberPropertyName(callee) === 'createRequire') {
          const object = unwrapTransparentExpression(callee.object as Node)
          if (object?.type === 'Identifier') addDependent(namespaceLoaderDependents, String(object.name), String(id.name))
        }
      }
      if (id.type === 'ObjectPattern' && value?.type === 'Identifier') {
        for (const property of id.properties as Node[]) {
          if (property.type !== 'Property' && property.type !== 'ObjectProperty') continue
          const key = propertyName(property.key as Node, property.computed === true)
          const alias = bindingName(property.value as Node)
          if (key === 'createRequire' && alias) addDependent(namespaceCreateRequireDependents, String(value.name), alias)
        }
      }
    }
    childNodes(node).forEach(collect)
  }
  collect(program)

  const moduleAliases = new Set(['module'])
  const loaderAliases = new Set(['require'])
  const namespaceQueue = [...createRequireNamespaces]
  const processedNamespaces = new Set<string>()
  for (let cursor = 0; cursor < namespaceQueue.length; cursor += 1) {
    const namespace = namespaceQueue[cursor]
    if (processedNamespaces.has(namespace)) continue
    processedNamespaces.add(namespace)
    for (const alias of createRequireNamespaceDependents.get(namespace) ?? []) {
      if (createRequireNamespaces.has(alias)) continue
      createRequireNamespaces.add(alias)
      namespaceQueue.push(alias)
    }
    for (const factory of namespaceCreateRequireDependents.get(namespace) ?? []) createRequireAliases.add(factory)
  }
  const factoryQueue = [...createRequireAliases]
  const processedFactories = new Set<string>()
  for (let cursor = 0; cursor < factoryQueue.length; cursor += 1) {
    const factory = factoryQueue[cursor]
    if (processedFactories.has(factory)) continue
    processedFactories.add(factory)
    for (const alias of createRequireAliasDependents.get(factory) ?? []) {
      if (createRequireAliases.has(alias)) continue
      createRequireAliases.add(alias)
      factoryQueue.push(alias)
    }
    for (const loader of createRequireLoaderDependents.get(factory) ?? []) loaderAliases.add(loader)
  }
  for (const namespace of processedNamespaces) {
    for (const loader of namespaceLoaderDependents.get(namespace) ?? []) loaderAliases.add(loader)
  }
  const processedModules = new Set<string>()
  const processedLoaders = new Set<string>()
  const worklist: { kind: 'module' | 'loader'; name: string }[] = [
    { kind: 'module', name: 'module' },
    { kind: 'loader', name: 'require' },
    ...[...loaderAliases].filter(name => name !== 'require').map(name => ({ kind: 'loader' as const, name })),
  ]
  for (let cursor = 0; cursor < worklist.length; cursor += 1) {
    const item = worklist[cursor]
    workItems += 1
    const aliases = item.kind === 'module' ? moduleAliases : loaderAliases
    const processed = item.kind === 'module' ? processedModules : processedLoaders
    if (processed.has(item.name)) continue
    processed.add(item.name)
    const dependents = item.kind === 'module' ? moduleAliasDependents : loaderAliasDependents
    for (const alias of dependents.get(item.name) ?? []) {
      workItems += 1
      if (aliases.has(alias)) continue
      aliases.add(alias)
      worklist.push({ kind: item.kind, name: alias })
    }
    if (item.kind === 'module') {
      for (const alias of moduleLoaderDependents.get(item.name) ?? []) {
        workItems += 1
        if (loaderAliases.has(alias)) continue
        loaderAliases.add(alias)
        worklist.push({ kind: 'loader', name: alias })
      }
    }
  }

  return { loaderAliases, moduleAliases, workItems }
}

type RuntimeModuleLoad = { node: Node; specifier: string }

function isOpaqueExternalPackage(specifier: string, isLocalSpecifier: (specifier: string) => boolean): boolean {
  return !isLocalSpecifier(specifier)
    && !specifier.startsWith('node:')
    && specifier !== 'react'
    && !specifier.startsWith('react/')
    && specifier !== 'react-dom'
    && !specifier.startsWith('react-dom/')
    && ![...routerModules].some(module => specifier === module || specifier.startsWith(`${module}/`))
    && specifier !== 'lucide-react'
}

function rejectUninspectableRouterLoads(program: Node, file: string): RuntimeModuleLoad[] {
  const { loaderAliases, moduleAliases } = discoverCommonJSAliases(program)
  const moduleLoads: RuntimeModuleLoad[] = []
  type Ancestor = { node: Node; field: string; parent?: Ancestor }
  type Visit = { node: Node; ancestors?: Ancestor }

  const isRouterModule = (specifier: string) => [...routerModules].some(module => specifier === module || specifier.startsWith(`${module}/`))
  const isLoaderBindingPosition = (ancestors: Ancestor | undefined) => {
    let edge = ancestors
    while (edge && transparentExpressionTypes.has(edge.node.type) && edge.field === 'expression') edge = edge.parent
    const parent = edge?.node
    const field = edge?.field
    return (parent?.type === 'VariableDeclarator' && field === 'init')
      || (parent?.type === 'AssignmentExpression' && field === 'right')
  }
  const isLoaderCallCallee = (ancestors: Ancestor | undefined) => {
    let edge = ancestors
    while (edge && transparentExpressionTypes.has(edge.node.type) && edge.field === 'expression') edge = edge.parent
    return (edge?.node.type === 'CallExpression' || edge?.node.type === 'OptionalCallExpression') && edge.field === 'callee'
  }
  const isLoaderBindingName = (node: Node, ancestors: Ancestor | undefined) => {
    if (node.type !== 'Identifier') return false
    const parent = ancestors
    return (parent?.node.type === 'VariableDeclarator' && parent.field === 'id')
      || (parent?.node.type === 'AssignmentExpression' && parent.field === 'left')
  }
  const isTypePosition = (node: Node, ancestors: Ancestor | undefined) => {
    if (node.type !== 'Identifier') return false
    for (let edge = ancestors; edge; edge = edge.parent) {
      if (edge.node.type.startsWith('TS') && edge.field !== 'expression') return true
    }
    return false
  }
  const pending: Visit[] = [{ node: program }]
  while (pending.length) {
    const { node, ancestors } = pending.pop()!
    if (node.type === 'VariableDeclarator' && (node.id as Node).type === 'ObjectPattern') {
      const id = node.id as Node
      const init = node.init as Node | undefined
      if (isCommonJSModuleObject(init, moduleAliases) && destructuresCommonJSRequire(id)) {
        throw new Error(`${file} destructures a CommonJS module loader; the console route inventory cannot rule out router APIs`)
      }
      if (isCommonJSLoader(init, loaderAliases, moduleAliases)) {
        throw new Error(`${file} destructures properties from a CommonJS module loader; the console route inventory cannot rule out router APIs`)
      }
    }
    if (node.type === 'AssignmentExpression' && (node.left as Node).type === 'ObjectPattern') {
      const left = node.left as Node
      const right = node.right as Node
      if (isCommonJSModuleObject(right, moduleAliases) && destructuresCommonJSRequire(left)) {
        throw new Error(`${file} destructures a CommonJS module loader; the console route inventory cannot rule out router APIs`)
      }
      if (isCommonJSLoader(right, loaderAliases, moduleAliases)) {
        throw new Error(`${file} destructures properties from a CommonJS module loader; the console route inventory cannot rule out router APIs`)
      }
    }

    if (node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression') {
      const member = node as Node
      if (['apply', 'bind', 'call'].includes(memberPropertyName(member) ?? '') && isCommonJSLoader(member.object as Node, loaderAliases, moduleAliases)) {
        throw new Error(`${file} binds or rebinds a CommonJS module loader; the console route inventory cannot rule out router APIs`)
      }
    }

    const parent = ancestors
    const isStaticProperty = node.type === 'Identifier'
      && ((parent?.field === 'property' && (parent.node.type === 'MemberExpression' || parent.node.type === 'OptionalMemberExpression')
        && parent.node.computed !== true)
        || ((parent?.node.type === 'Property' || parent?.node.type === 'ObjectProperty') && parent.field === 'key'
          && parent.node.computed !== true))
    if ((node.type === 'Identifier' || node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression')
      && !isStaticProperty
      && !isLoaderBindingName(node, ancestors)
      && !isTypePosition(node, ancestors)
      && isCommonJSLoader(node, loaderAliases, moduleAliases)
      && !isLoaderBindingPosition(ancestors)
      && !isLoaderCallCallee(ancestors)) {
      throw new Error(`${file} uses a CommonJS module loader as a value outside a direct module load; the console route inventory cannot rule out router APIs`)
    }

    let source: Node | undefined
    let kind: string | undefined
    if (node.type === 'ImportExpression') {
      source = node.source as Node
      kind = 'dynamic import'
    } else if (node.type === 'CallExpression' || node.type === 'OptionalCallExpression') {
      const callee = node.callee as Node
      if (callee.type === 'Import') {
        source = (node.arguments as Node[])[0]
        kind = 'dynamic import'
      } else if (isCommonJSLoader(callee, loaderAliases, moduleAliases)) {
        if (isOptionalCommonJSLoaderCall(node, callee)) {
          throw new Error(`${file} uses an optional CommonJS module load; the console route inventory cannot rule out router APIs`)
        }
        source = (node.arguments as Node[])[0]
        kind = 'CommonJS module load'
      }
    }

    if (kind) {
      const specifier = staticStringValue(source)
      if (specifier === undefined) {
        throw new Error(`${file} uses a ${kind} with a non-static module specifier; the console route inventory cannot rule out router APIs`)
      }
      if ((kind === 'CommonJS module load' || kind === 'dynamic import') && (specifier === 'module' || specifier === 'node:module')) {
        throw new Error(`${file} loads the CommonJS module factory ${specifier}; the console route inventory cannot rule out router APIs created with createRequire`)
      }
      if (isRouterModule(specifier)) {
        throw new Error(`${file} dynamically loads router module ${specifier}; the console route inventory requires static named router imports`)
      }
      moduleLoads.push({ node, specifier })
    }
    const children: { node: Node; field: string }[] = []
    for (const [field, value] of Object.entries(node)) {
      if (field === 'parent') continue
      if (Array.isArray(value)) value.filter(isNode).forEach(child => children.push({ node: child, field }))
      else if (isNode(value)) children.push({ node: value, field })
    }
    for (let index = children.length - 1; index >= 0; index -= 1) {
      const child = children[index]
      pending.push({ node: child.node, ancestors: { node, field: child.field, parent: ancestors } })
    }
  }
  return moduleLoads
}

/** Associates opaque bare-package runtime loads with the local values they produce. */
function opaqueRuntimeModuleBindings(
  program: Node,
  moduleLoads: RuntimeModuleLoad[],
  isLocalSpecifier: (specifier: string) => boolean,
): Map<string, { source: string }> {
  const loads = new Map(moduleLoads
    .filter(load => isOpaqueExternalPackage(load.specifier, isLocalSpecifier))
    .map(load => [load.node, load.specifier]))
  const direct = new Map<string, { source: string }>()
  const functionOrigins = new Map<string, { source: string }>()
  const localFunctions = new Map<string, Set<Node>>()
  const localFunctionAliases = new Map<string, Set<string>>()
  const functionSourceCache = new Map<string, { version: number; source?: string }>()
  let directVersion = 0
  const addLocalFunction = (name: string, fn: Node) => {
    const overloads = localFunctions.get(name) ?? new Set<Node>()
    overloads.add(fn)
    localFunctions.set(name, overloads)
  }
  const addLocalFunctionAlias = (name: string, target: string) => {
    const aliases = localFunctionAliases.get(name) ?? new Set<string>()
    aliases.add(target)
    localFunctionAliases.set(name, aliases)
  }
  const isFunctionValue = (node: Node | undefined) => !!node && [
    'ArrowFunctionExpression', 'FunctionExpression', 'ObjectMethod', 'ClassMethod', 'ClassPrivateMethod', 'MethodDefinition',
  ].includes(node.type)
  const staticKey = (node: Node | undefined) => node?.type === 'Identifier' ? String(node.name) : staticStringValue(node)
  const collectObjectMethods = (object: Node, owner: string) => {
    for (const property of (object.properties as Node[] | undefined) ?? []) {
      const key = staticKey(property.key as Node | undefined)
      if (!key) continue
      const path = `${owner}.${key}`
      const value = property.type === 'RestElement' ? property.argument as Node | undefined : property.value as Node | undefined
      if (isFunctionValue(property) || isFunctionValue(value)) addLocalFunction(path, (isFunctionValue(property) ? property : value) as Node)
      if (value?.type === 'ObjectExpression') collectObjectMethods(value, path)
    }
  }
  const collectClassMethods = (classNode: Node, owner: string) => {
    const body = classNode.body as Node | undefined
    for (const method of (body?.body as Node[] | undefined) ?? []) {
      if (!['ClassMethod', 'ClassPrivateMethod', 'MethodDefinition'].includes(method.type)) continue
      const key = staticKey(method.key as Node | undefined)
      if (!key) continue
      addLocalFunction(method.static === true ? `${owner}.${key}` : `${owner}.prototype.${key}`, method)
    }
  }
  const functionReference = (node: Node | undefined) => {
    const value = unwrapTransparentExpression(node)
    return value?.type === 'Identifier' || value?.type === 'MemberExpression' || value?.type === 'OptionalMemberExpression'
      ? staticMemberPath(value)
      : undefined
  }
  const collectLocalFunctions = (node: Node, parent?: Node, enclosingClass?: string) => {
    let className = enclosingClass
    if ((node.type === 'ClassDeclaration' || node.type === 'ClassExpression')) {
      const id = node.id as Node | undefined
      if (id?.type === 'Identifier') className = String(id.name)
      else if (parent?.type === 'VariableDeclarator' && (parent.id as Node | undefined)?.type === 'Identifier') {
        className = String((parent.id as Node).name)
      }
      if (className) collectClassMethods(node, className)
    }
    if (node.type === 'FunctionDeclaration' && isNode(node.id)) {
      addLocalFunction(String((node.id as Node).name), node)
    }
    if ((node.type === 'ClassMethod' || node.type === 'ClassPrivateMethod' || node.type === 'MethodDefinition') && className) {
      const key = staticKey(node.key as Node | undefined)
      if (key) addLocalFunction(node.static === true ? `${className}.${key}` : `${className}.prototype.${key}`, node)
    }
    if (node.type === 'VariableDeclarator' && (node.id as Node).type === 'Identifier') {
      const name = String((node.id as Node).name)
      const value = unwrapTransparentExpression(node.init as Node | undefined)
      if (value && isFunctionValue(value)) addLocalFunction(name, value)
      else {
        const reference = functionReference(value)
        if (reference) addLocalFunctionAlias(name, reference)
        if (value?.type === 'ObjectExpression') collectObjectMethods(value, name)
        if (value?.type === 'ClassExpression') collectClassMethods(value, name)
      }
    }
    if (node.type === 'AssignmentExpression' && (node.left as Node | undefined)?.type === 'Identifier') {
      const target = String((node.left as Node).name)
      const reference = functionReference(node.right as Node | undefined)
      if (reference) addLocalFunctionAlias(target, reference)
    }
    childNodes(node).forEach(child => collectLocalFunctions(child, node, className))
  }
  collectLocalFunctions(program)

  const namesInPattern = (pattern: Node | undefined, target: Set<string>) => {
    if (!pattern) return
    if (pattern.type === 'Identifier') target.add(String(pattern.name))
    else if (pattern.type === 'MemberExpression' || pattern.type === 'OptionalMemberExpression') {
      const path = staticMemberPath(pattern)
      if (path) target.add(`@member:${path}`)
      else {
        const root = memberRootIdentifier(pattern)
        if (root) target.add(`@member-root:${root}`)
      }
    }
    else if (pattern.type === 'RestElement' || pattern.type === 'AssignmentPattern') {
      namesInPattern((pattern.argument ?? pattern.left) as Node | undefined, target)
    } else if (pattern.type === 'ObjectPattern') {
      for (const property of pattern.properties as Node[]) {
        namesInPattern((property.type === 'RestElement' ? property.argument : property.value) as Node | undefined, target)
      }
    } else if (pattern.type === 'ArrayPattern') {
      for (const element of pattern.elements as (Node | null)[]) if (element) namesInPattern(element, target)
    }
  }
  const returnedExpressions = (fn: Node): Node[] => {
    const body = fn.type === 'MethodDefinition'
      ? ((fn.value as Node | undefined)?.body as Node | undefined)
      : ['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression', 'ObjectMethod', 'ClassMethod', 'ClassPrivateMethod'].includes(fn.type)
        ? fn.body as Node | undefined
        : undefined
    if (!body) return []
    if (body.type !== 'BlockStatement') return [body]
    const expressions: Node[] = []
    const visit = (current: Node) => {
      if (current !== body && ['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression'].includes(current.type)) return
      if (current.type === 'ReturnStatement' && isNode(current.argument)) expressions.push(current.argument as Node)
      childNodes(current).forEach(visit)
    }
    visit(body)
    return expressions
  }
  const scanSource = (node: Node | undefined, functionQueue: Set<string>): string | undefined => {
    if (!node) return undefined
    const expression = unwrapTransparentExpression(node)
    if (!expression) return undefined
    const loaded = loads.get(expression)
    if (loaded) return loaded
    if (expression.type === 'Identifier') {
      const name = String(expression.name)
      const known = direct.get(name)?.source
      if (known) return known
      if (localFunctions.has(name) || localFunctionAliases.has(name)) functionQueue.add(name)
      return undefined
    }
    if (expression.type === 'AwaitExpression' || expression.type === 'ChainExpression') {
      return scanSource((expression.argument ?? expression.expression) as Node | undefined, functionQueue)
    }
    if (expression.type === 'MemberExpression' || expression.type === 'OptionalMemberExpression') {
      const path = staticMemberPath(expression)
      const memberSource = path ? direct.get(`@member:${path}`)?.source : undefined
      if (memberSource) return memberSource
      const root = memberRootIdentifier(expression)
      const rootSource = root ? direct.get(`@member-root:${root}`)?.source : undefined
      if (rootSource) return rootSource
      if (path && (localFunctions.has(path) || localFunctionAliases.has(path))) functionQueue.add(path)
      return scanSource(expression.object as Node | undefined, functionQueue)
    }
    if (expression.type === 'ConditionalExpression') {
      return scanSource(expression.consequent as Node | undefined, functionQueue)
        ?? scanSource(expression.alternate as Node | undefined, functionQueue)
        ?? scanSource(expression.test as Node | undefined, functionQueue)
    }
    if (expression.type === 'LogicalExpression') {
      return scanSource(expression.left as Node | undefined, functionQueue)
        ?? scanSource(expression.right as Node | undefined, functionQueue)
    }
    if (expression.type === 'CallExpression' || expression.type === 'OptionalCallExpression') {
      // Promise transformations such as import('pkg').then(...) keep the load
      // in the callee tree. Local calls can hide the load in their return body.
      const calleeSource = scanSource(expression.callee as Node | undefined, functionQueue)
      if (calleeSource) return calleeSource
      for (const argument of (expression.arguments as Node[] | undefined) ?? []) {
        const source = scanSource(argument, functionQueue)
        if (source) return source
      }
      return undefined
    }
    if (isFunctionValue(expression) || expression.type === 'FunctionDeclaration') {
      for (const value of returnedExpressions(expression)) {
        const source = scanSource(value, functionQueue)
        if (source) return source
      }
      return undefined
    }
    for (const child of childNodes(expression)) {
      const source = scanSource(child, functionQueue)
      if (source) return source
    }
    return undefined
  }
  const sourceFromLocalFunctions = (names: Set<string>): string | undefined => {
    const pending = [...names]
    const queued = new Set(pending)
    const visited = new Set<string>()
    let source: string | undefined
    for (let cursor = 0; cursor < pending.length && !source; cursor += 1) {
      const name = pending[cursor]
      const cached = functionSourceCache.get(name)
      if (cached?.source) {
        source = cached.source
        continue
      }
      if (cached?.version === directVersion) {
        continue
      }
      if (visited.has(name)) continue
      visited.add(name)
      const enqueue = (dependency: string) => {
        if (queued.has(dependency)) return
        queued.add(dependency)
        pending.push(dependency)
      }
      for (const alias of localFunctionAliases.get(name) ?? []) enqueue(alias)
      for (const fn of localFunctions.get(name) ?? []) {
        for (const value of returnedExpressions(fn)) {
          const dependencies = new Set<string>()
          source = scanSource(value, dependencies)
          for (const dependency of dependencies) enqueue(dependency)
          if (source) break
        }
        if (source) break
      }
    }
    for (const name of visited) functionSourceCache.set(name, { version: directVersion, source })
    return source
  }
  const sourceIn = (node: Node | undefined): string | undefined => {
    const functionQueue = new Set<string>()
    const source = scanSource(node, functionQueue)
    return source ?? sourceFromLocalFunctions(functionQueue)
  }
  const setDirect = (name: string, source: string) => {
    if (direct.get(name)?.source === source) return
    direct.set(name, { source })
    directVersion += 1
  }
  const collect = (node: Node) => {
    if (node.type === 'VariableDeclarator') {
      const source = sourceIn(node.init as Node | undefined)
      if (source) {
        const names = new Set<string>()
        namesInPattern(node.id as Node | undefined, names)
        for (const name of names) setDirect(name, source)
      }
    }
    if (node.type === 'AssignmentExpression') {
      const source = sourceIn(node.right as Node | undefined)
      if (source) {
        const names = new Set<string>()
        namesInPattern(node.left as Node | undefined, names)
        for (const name of names) setDirect(name, source)
      }
    }
    if (node.type === 'FunctionDeclaration' && isNode(node.id)) {
      const source = sourceIn(node)
      if (source) functionOrigins.set(String((node.id as Node).name), { source })
    }
    childNodes(node).forEach(collect)
  }
  collect(program)
  for (const [name, origin] of functionOrigins) direct.set(name, origin)
  return importedComponentAliases(program, direct)
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

function jsxMemberRootIdentifier(node: Node): string | undefined {
  let current = node
  while (current.type === 'JSXMemberExpression') current = current.object as Node
  return current.type === 'JSXIdentifier' ? String(current.name) : undefined
}

function referencedRouterAPI(node: Node | undefined, local: { Route: Set<string>; Routes: Set<string> }): string | undefined {
  if (!node) return undefined
  if (node.type === 'Identifier') {
    const name = String(node.name)
    return local.Route.has(name) ? 'Route' : local.Routes.has(name) ? 'Routes' : undefined
  }
  if (node.type === 'Property') {
    const api = referencedRouterAPI(node.value as Node, local)
    return api ?? (node.computed ? referencedRouterAPI(node.key as Node, local) : undefined)
  }
  if (node.type === 'MemberExpression') {
    const api = referencedRouterAPI(node.object as Node, local)
    return api ?? (node.computed ? referencedRouterAPI(node.property as Node, local) : undefined)
  }
  if (node.type === 'VariableDeclarator') return referencedRouterAPI(node.init as Node | undefined, local)
  if (node.type === 'FunctionDeclaration' || node.type === 'FunctionExpression' || node.type === 'ArrowFunctionExpression') {
    return referencedRouterAPI(node.body as Node | undefined, local)
  }
  if (node.type === 'ClassDeclaration' || node.type === 'ClassExpression') {
    const api = referencedRouterAPI(node.superClass as Node | undefined, local)
    return api ?? referencedRouterAPI(node.body as Node | undefined, local)
  }
  return childNodes(node).map(child => referencedRouterAPI(child, local)).find(Boolean)
}

function jsxAttribute(element: Node, name: string): Node | undefined {
  const attributes = (element.openingElement as Node).attributes as Node[]
  return attributes.find(attribute => attribute.type === 'JSXAttribute' && ((attribute.name as Node).name === name))
}

function jsxExpressionAttribute(attribute: Node | undefined): Node | undefined {
  const value = attribute?.value as Node | null | undefined
  if (value?.type !== 'JSXExpressionContainer') return undefined
  return unwrapTransparentExpression(value.expression as Node)
}

function functionParametersIncludingAliases(functionValue: Node, inherited = new Set<string>()): Set<string> {
  const actual = functionValue.type === 'MethodDefinition' ? functionValue.value as Node : functionValue
  const names = (pattern: Node | undefined, target: Set<string>) => {
    if (!pattern) return
    if (pattern.type === 'Identifier') target.add(String(pattern.name))
    else if (pattern.type === 'RestElement' || pattern.type === 'AssignmentPattern') names((pattern.argument ?? pattern.left) as Node | undefined, target)
    else if (pattern.type === 'ObjectPattern') {
      for (const property of pattern.properties as Node[]) names((property.type === 'RestElement' ? property.argument : property.value) as Node | undefined, target)
    } else if (pattern.type === 'ArrayPattern') {
      for (const item of pattern.elements as (Node | null)[]) if (item) names(item, target)
    }
  }
  const parameters = new Set(inherited)
  for (const parameter of (actual.params as Node[] | undefined) ?? []) names(parameter, parameters)
  const dependents = new Map<string, Set<string>>()
  const addAliases = (binding: Node | undefined, value: Node | undefined) => {
    const targets = new Set<string>()
    names(binding, targets)
    if (!targets.size || !value) return
    const sources = new Set<string>()
    const visitValue = (node: Node, parent?: Node, field?: string) => {
      if (node.type === 'Identifier') {
        const staticName = ((parent?.type === 'Property' || parent?.type === 'ObjectProperty') && field === 'key' && !parent.computed)
          || ((parent?.type === 'MemberExpression' || parent?.type === 'OptionalMemberExpression') && field === 'property' && !parent.computed)
        if (!staticName) sources.add(String(node.name))
        return
      }
      if (node.type.startsWith('TS')) return
      for (const [key, child] of Object.entries(node)) {
        if (key === 'parent') continue
        if (Array.isArray(child)) child.filter(isNode).forEach(item => visitValue(item, node, key))
        else if (isNode(child)) visitValue(child, node, key)
      }
    }
    visitValue(value)
    for (const source of sources) {
      const aliases = dependents.get(source) ?? new Set<string>()
      for (const target of targets) aliases.add(target)
      dependents.set(source, aliases)
    }
  }
  const body = actual.body as Node | undefined
  const collect = (node: Node, root: Node) => {
    if (node !== root && ['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression', 'ObjectMethod', 'ClassMethod', 'MethodDefinition'].includes(node.type)) return
    if (node.type === 'VariableDeclarator') addAliases(node.id as Node | undefined, node.init as Node | undefined)
    if (node.type === 'AssignmentExpression') addAliases(node.left as Node | undefined, node.right as Node | undefined)
    childNodes(node).forEach(child => collect(child, root))
  }
  if (body) collect(body, body)
  const queue = [...parameters]
  for (let cursor = 0; cursor < queue.length; cursor += 1) {
    for (const alias of dependents.get(queue[cursor]) ?? []) {
      if (parameters.has(alias)) continue
      parameters.add(alias)
      queue.push(alias)
    }
  }
  return parameters
}

function staticallyReadableComponentBindings(
  program: Node,
  reactNamespaces: Set<string>,
  readableLazyCalls: Set<Node>,
  opaqueComponentBindings: Set<string>,
  reactFactories: { factories: Set<string>; namespaces: Set<string> },
  routerComponents: { Route: Set<string>; Routes: Set<string> },
  knownRouterComponents: Set<string>,
): { bindings: Set<string>; unreadableComponents: Set<string> } {
  const bindings = new Set<string>()
  const aliasDependents = new Map<string, Set<string>>()
  const componentBodies = new Map<string, Set<Node>>()
  const classesWithoutOwnRender = new Set<string>()
  const addPatternNames = (pattern: Node | undefined, target: Set<string>) => {
    if (!pattern) return
    if (pattern.type === 'Identifier') target.add(String(pattern.name))
    else if (pattern.type === 'RestElement' || pattern.type === 'AssignmentPattern') {
      addPatternNames((pattern.argument ?? pattern.left) as Node | undefined, target)
    } else if (pattern.type === 'ObjectPattern') {
      for (const property of pattern.properties as Node[]) {
        addPatternNames((property.type === 'RestElement' ? property.argument : property.value) as Node | undefined, target)
      }
    } else if (pattern.type === 'ArrayPattern') {
      for (const element of pattern.elements as (Node | null)[]) if (element) addPatternNames(element, target)
    }
  }
  const addAlias = (source: string, target: string) => {
    const aliases = aliasDependents.get(source) ?? new Set<string>()
    aliases.add(target)
    aliasDependents.set(source, aliases)
  }
  const visit = (node: Node, parent?: Node) => {
    if (node.type === 'ImportDeclaration') {
      for (const specifier of node.specifiers as Node[]) addPatternNames(specifier.local as Node | undefined, bindings)
    }
    if ((node.type === 'FunctionDeclaration' || node.type === 'ClassDeclaration') && isNode(node.id)) {
      const name = String((node.id as Node).name)
      bindings.add(name)
      if (node.type === 'FunctionDeclaration') {
        const bodies = componentBodies.get(name) ?? new Set<Node>()
        bodies.add(node)
        componentBodies.set(name, bodies)
      } else {
        let hasOwnRender = false
        const bodies = componentBodies.get(name) ?? new Set<Node>()
        for (const method of ((node.body as Node).body as Node[])) {
          const key = method.key as Node | undefined
          const isRender = (key?.type === 'Identifier' && method.computed !== true && key.name === 'render')
            || staticStringValue(key) === 'render'
          if (!isRender) continue
          if (method.type === 'ClassMethod' || method.type === 'MethodDefinition') {
            bodies.add(method)
            hasOwnRender = true
          } else if ((method.type === 'ClassProperty' || method.type === 'PropertyDefinition')
            && ['ArrowFunctionExpression', 'FunctionExpression'].includes((method.value as Node | undefined)?.type ?? '')) {
            bodies.add(method.value as Node)
            hasOwnRender = true
          }
        }
        if (hasOwnRender) componentBodies.set(name, bodies)
        else classesWithoutOwnRender.add(name)
      }
    }
    if (node.type === 'VariableDeclarator' && parent?.type === 'VariableDeclaration' && parent.kind === 'const'
      && (node.id as Node).type === 'Identifier') {
      const name = String((node.id as Node).name)
      const value = unwrapTransparentExpression(node.init as Node | undefined)
      if (value?.type === 'ArrowFunctionExpression' || value?.type === 'FunctionExpression' || (value && readableLazyCalls.has(value))) {
        bindings.add(name)
        if (value.type === 'ArrowFunctionExpression' || value.type === 'FunctionExpression') {
          const bodies = componentBodies.get(name) ?? new Set<Node>()
          bodies.add(value)
          componentBodies.set(name, bodies)
        }
      } else if (value?.type === 'Identifier') {
        addAlias(String(value.name), name)
      } else if ((value?.type === 'MemberExpression' || value?.type === 'OptionalMemberExpression')
        && (value.object as Node).type === 'Identifier'
        && reactNamespaces.has(String((value.object as Node).name))) {
        bindings.add(name)
      }
    }
    childNodes(node).forEach(child => visit(child, node))
  }
  visit(program)
  const queue = [...bindings]
  for (let cursor = 0; cursor < queue.length; cursor += 1) {
    for (const alias of aliasDependents.get(queue[cursor]) ?? []) {
      if (bindings.has(alias)) continue
      bindings.add(alias)
      queue.push(alias)
    }
  }
  // A value alias initialized from a parameter or another runtime expression
  // can shadow a same-named top-level component. Since this syntax-only check
  // does not build lexical scopes, remove every binding name with such a
  // declaration instead of treating a different declaration with that name
  // as proof that the wildcard value is readable.
  const unreadableNames = new Set<string>()
  const findUnreadableDeclarations = (node: Node, parent?: Node) => {
    if (node.type === 'VariableDeclarator' && isNode(node.id)) {
      const names = new Set<string>()
      addPatternNames(node.id as Node, names)
      const name = node.id.type === 'Identifier' ? String(node.id.name) : undefined
      const value = unwrapTransparentExpression(node.init as Node | undefined)
      const known = name !== undefined && parent?.type === 'VariableDeclaration' && parent.kind === 'const'
        && (value?.type === 'ArrowFunctionExpression' || value?.type === 'FunctionExpression'
          || (value && readableLazyCalls.has(value))
          || (value?.type === 'Identifier' && bindings.has(String(value.name)))
          || ((value?.type === 'MemberExpression' || value?.type === 'OptionalMemberExpression')
            && (value.object as Node).type === 'Identifier'
            && reactNamespaces.has(String((value.object as Node).name)))
        )
      if (!known) for (const binding of names) unreadableNames.add(binding)
    }
    if (node.type === 'AssignmentExpression' && (node.left as Node).type === 'Identifier') {
      unreadableNames.add(String((node.left as Node).name))
    } else if (node.type === 'AssignmentExpression') {
      const names = new Set<string>()
      addPatternNames(node.left as Node | undefined, names)
      for (const name of names) unreadableNames.add(name)
    }
    childNodes(node).forEach(child => findUnreadableDeclarations(child, node))
  }
  findUnreadableDeclarations(program)
  const readableQueue = [...bindings].filter(name => !unreadableNames.has(name))
  const readable = new Set(readableQueue)
  for (let cursor = 0; cursor < readableQueue.length; cursor += 1) {
    for (const alias of aliasDependents.get(readableQueue[cursor]) ?? []) {
      if (unreadableNames.has(alias) || readable.has(alias)) continue
      readable.add(alias)
      readableQueue.push(alias)
    }
  }
  const componentDependents = new Map<string, Set<string>>()
  const unsafeComponents = new Set<string>(classesWithoutOwnRender)
  const addComponentDependency = (component: string, owner: string) => {
    const dependents = componentDependents.get(component) ?? new Set<string>()
    dependents.add(owner)
    componentDependents.set(component, dependents)
  }
  const returnedExpressions = (component: Node): Node[] => {
    const functionNode = component.type === 'MethodDefinition' ? component.value as Node : component
    const body = functionNode.body as Node | undefined
    if (!body) return []
    if (body.type !== 'BlockStatement') return [body]
    const expressions: Node[] = []
    const visitReturns = (node: Node) => {
      if (node !== body && ['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression'].includes(node.type)) return
      if (node.type === 'ReturnStatement' && isNode(node.argument)) expressions.push(node.argument as Node)
      childNodes(node).forEach(visitReturns)
    }
    visitReturns(body)
    return expressions
  }
  type ComponentScope = { parameters: Set<string>; locals: Map<string, Node>; parent?: ComponentScope }
  const globalValues = new Map<string, Node>()
  for (const statement of program.body as Node[]) {
    if (statement.type !== 'VariableDeclaration' || statement.kind !== 'const') continue
    for (const declaration of statement.declarations as Node[]) {
      if ((declaration.id as Node | undefined)?.type === 'Identifier' && isNode(declaration.init)) {
        globalValues.set(String((declaration.id as Node).name), declaration.init as Node)
      }
    }
  }
  const globalScope: ComponentScope = { parameters: new Set(), locals: globalValues }
  const scopeFor = (functionValue: Node, parent: ComponentScope = globalScope): ComponentScope => {
    const actual = functionValue.type === 'MethodDefinition' ? functionValue.value as Node : functionValue
    const scope: ComponentScope = {
      parameters: functionParametersIncludingAliases(actual, parent.parameters),
      locals: new Map(),
      parent,
    }
    const body = actual.body as Node | undefined
    const collectLocals = (node: Node, root: Node) => {
      if (node !== root && ['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression', 'ObjectMethod', 'ClassMethod', 'MethodDefinition'].includes(node.type)) return
      if (node.type === 'VariableDeclarator' && isNode(node.id)) {
        if (node.id.type === 'Identifier' && isNode(node.init)) {
          scope.locals.set(String(node.id.name), node.init as Node)
        } else {
          const names = new Set<string>()
          addPatternNames(node.id as Node, names)
          for (const name of names) scope.parameters.add(name)
        }
      }
      childNodes(node).forEach(child => collectLocals(child, root))
    }
    if (body) collectLocals(body, body)
    return scope
  }
  const localValue = (scope: ComponentScope, name: string): Node | undefined => {
    for (let current: ComponentScope | undefined = scope; current; current = current.parent) {
      const value = current.locals.get(name)
      if (value) return value
    }
    return undefined
  }
  const opaqueValueNodes = new WeakSet<Node>()
  const markOpaqueValues = (node: Node, parent?: Node, field?: string): boolean => {
    if (node.type.startsWith('TS')) return false
    let found = false
    if (node.type === 'Identifier') {
      const staticProperty = ((parent?.type === 'Property' || parent?.type === 'ObjectProperty') && field === 'key' && !parent.computed)
        || ((parent?.type === 'MemberExpression' || parent?.type === 'OptionalMemberExpression') && field === 'property' && !parent.computed)
      const bindingName = (parent?.type === 'VariableDeclarator' && field === 'id')
        || ((parent?.type === 'FunctionDeclaration' || parent?.type === 'FunctionExpression' || parent?.type === 'ClassDeclaration' || parent?.type === 'ClassExpression') && field === 'id')
      found = !staticProperty && !bindingName && opaqueComponentBindings.has(String(node.name))
    }
    if (node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression') {
      const path = staticMemberPath(node)
      const root = memberRootIdentifier(node)
      found = found || (!!path && opaqueComponentBindings.has(`@member:${path}`))
        || (!!root && (opaqueComponentBindings.has(root) || opaqueComponentBindings.has(`@member-root:${root}`)))
    }
    for (const [key, value] of Object.entries(node)) {
      if (key === 'parent') continue
      if (Array.isArray(value)) {
        for (const child of value.filter(isNode)) found = markOpaqueValues(child, node, key) || found
      } else if (isNode(value)) found = markOpaqueValues(value, node, key) || found
    }
    if (found) opaqueValueNodes.add(node)
    return found
  }
  markOpaqueValues(program)
  const inspectComponentType = (owner: string, node: Node | undefined, scope: ComponentScope) => {
    const type = unwrapTransparentExpression(node)
    if (!type) {
      unsafeComponents.add(owner)
      return
    }
    if (type.type === 'Literal' && typeof type.value === 'string') return
    if (type.type === 'Identifier') {
      const name = String(type.name)
      if (routerComponents.Route.has(name) || routerComponents.Routes.has(name) || opaqueComponentBindings.has(name)
        || !readable.has(name) || scope.parameters.has(name)) {
        unsafeComponents.add(owner)
      } else if (componentBodies.has(name)) addComponentDependency(name, owner)
      else unsafeComponents.add(owner)
      return
    }
    if (type.type === 'MemberExpression' || type.type === 'OptionalMemberExpression') {
      const path = staticMemberPath(type)
      const root = memberRootIdentifier(type)
      if ((path && opaqueComponentBindings.has(`@member:${path}`))
        || (root && (opaqueComponentBindings.has(root) || opaqueComponentBindings.has(`@member-root:${root}`)))) {
        unsafeComponents.add(owner)
        return
      }
      if (root && reactNamespaces.has(root) && memberPropertyName(type) === 'Fragment') return
      unsafeComponents.add(owner)
      return
    }
    if (type.type === 'ConditionalExpression' || type.type === 'LogicalExpression') {
      inspectComponentType(owner, type.type === 'ConditionalExpression' ? type.consequent as Node : type.left as Node, scope)
      inspectComponentType(owner, type.type === 'ConditionalExpression' ? type.alternate as Node : type.right as Node, scope)
      return
    }
    unsafeComponents.add(owner)
  }
  const inspectComponentTree = (owner: string, node: Node, scope: ComponentScope, seenValues = new Set<Node>()): void => {
    if (opaqueValueNodes.has(node)) unsafeComponents.add(owner)
    if (['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression', 'ObjectMethod', 'ClassMethod', 'MethodDefinition'].includes(node.type)) return
    if (node.type === 'JSXElement') {
      const opening = node.openingElement as Node
      const tag = opening.name as Node
      let root: string | undefined
      if (tag.type === 'JSXIdentifier' && /^[A-Z]/.test(String(tag.name))) root = String(tag.name)
      else if (tag.type === 'JSXMemberExpression') root = jsxMemberRootIdentifier(tag)
      if (root) {
        const path = tag.type === 'JSXMemberExpression' ? jsxMemberStaticPath(tag) : undefined
        if ((path && opaqueComponentBindings.has(`@member:${path}`))
          || opaqueComponentBindings.has(root) || opaqueComponentBindings.has(`@member-root:${root}`)
          || !readable.has(root) || scope.parameters.has(root)) unsafeComponents.add(owner)
        else if (componentBodies.has(root)) addComponentDependency(root, owner)
        else if (routerComponents.Route.has(root) || routerComponents.Routes.has(root) || knownRouterComponents.has(root)) {
          // Router elements and recognized primitives are statically named,
          // but Route/Routes descendants still need inspection: a runtime
          // component inside their route table can itself own hidden routes.
        }
        else if (!reactNamespaces.has(root) && !knownRouterComponents.has(root) && !readable.has(root)) unsafeComponents.add(owner)
      }
      for (const attribute of opening.attributes as Node[]) {
        const attributeName = attribute.type === 'JSXAttribute'
          ? String(((attribute.name as Node | undefined)?.name ?? ''))
          : undefined
        const value = attribute.type === 'JSXSpreadAttribute'
          ? attribute.argument as Node | undefined
          : jsxExpressionAttribute(attribute)
        if (!value) continue
        if (opaqueValueNodes.has(value)) unsafeComponents.add(owner)
        const eventHandler = attributeName !== undefined && /^on[A-Z]/.test(attributeName)
        const renderProp = attributeName !== undefined && /^(?:Component|component|element|children|view|render|route|routes|fallback|Route|Routes)$/.test(attributeName)
        if ((value.type === 'ArrowFunctionExpression' || value.type === 'FunctionExpression') && !eventHandler) {
          for (const returned of returnedExpressions(value)) inspectComponentTree(owner, returned, scopeFor(value, scope), seenValues)
        } else if (value.type === 'JSXElement' || value.type === 'JSXFragment'
          || (renderProp && ['CallExpression', 'OptionalCallExpression', 'ConditionalExpression', 'LogicalExpression', 'ArrayExpression'].includes(value.type))
          || (renderProp && value.type === 'Identifier')) {
          inspectComponentTree(owner, value, scope, seenValues)
        } else if (value.type === 'Identifier') {
          const name = String(value.name)
          if (renderProp && scope.parameters.has(name)) unsafeComponents.add(owner)
          else if (componentBodies.has(name) && renderProp) addComponentDependency(name, owner)
          else if (renderProp) {
            const value = localValue(scope, name)
            if (value && !seenValues.has(value)) {
              seenValues.add(value)
              inspectComponentTree(owner, value, scope, seenValues)
            }
          }
        }
      }
      for (const child of node.children as Node[]) inspectComponentTree(owner, child, scope, seenValues)
      return
    }
    if (node.type === 'JSXFragment') {
      for (const child of node.children as Node[]) inspectComponentTree(owner, child, scope, seenValues)
      return
    }
    if (node.type === 'JSXExpressionContainer') {
      const expression = unwrapTransparentExpression(node.expression as Node)
      if (expression?.type === 'Identifier') {
        const name = String(expression.name)
        if (scope.parameters.has(name)) unsafeComponents.add(owner)
        else if (componentBodies.has(name)) addComponentDependency(name, owner)
        else {
          const value = localValue(scope, name)
          if (value && !seenValues.has(value)) {
            seenValues.add(value)
            inspectComponentTree(owner, value, scope, seenValues)
          }
        }
        return
      }
      inspectComponentTree(owner, expression ?? node.expression as Node, scope, seenValues)
      return
    }
    if (node.type === 'ConditionalExpression') {
      inspectComponentTree(owner, node.consequent as Node, scope, seenValues)
      inspectComponentTree(owner, node.alternate as Node, scope, seenValues)
      return
    }
    if (node.type === 'LogicalExpression') {
      if (node.operator === '&&') inspectComponentTree(owner, node.right as Node, scope, seenValues)
      else {
        inspectComponentTree(owner, node.left as Node, scope, seenValues)
        inspectComponentTree(owner, node.right as Node, scope, seenValues)
      }
      return
    }
    if (node.type === 'CallExpression' || node.type === 'OptionalCallExpression') {
      const callee = unwrapTransparentExpression(node.callee as Node | undefined)
      const isCreateElement = callee?.type === 'Identifier'
        ? reactFactories.factories.has(String(callee.name))
        : !!callee && (callee.type === 'MemberExpression' || callee.type === 'OptionalMemberExpression')
          && (callee.object as Node).type === 'Identifier'
          && reactFactories.namespaces.has(String((callee.object as Node).name))
          && memberPropertyName(callee) === 'createElement'
      const arguments_ = (node.arguments as Node[] | undefined) ?? []
      if (isCreateElement) {
        inspectComponentType(owner, arguments_[0], scope)
        for (const argument of arguments_.slice(1)) inspectComponentTree(owner, argument, scope, seenValues)
        return
      }
      const method = callee && (callee.type === 'MemberExpression' || callee.type === 'OptionalMemberExpression')
        ? memberPropertyName(callee)
        : undefined
      if (method === 'map' || method === 'flatMap') {
        const callback = unwrapTransparentExpression(arguments_[0])
        if (callback?.type === 'ArrowFunctionExpression' || callback?.type === 'FunctionExpression') {
          const callbackScope = scopeFor(callback, scope)
          for (const returned of returnedExpressions(callback)) inspectComponentTree(owner, returned, callbackScope, seenValues)
        } else if (callback?.type === 'Identifier' && componentBodies.has(String(callback.name))) {
          addComponentDependency(String(callback.name), owner)
        } else unsafeComponents.add(owner)
        return
      }
      const calleeName = callee?.type === 'Identifier' ? String(callee.name) : undefined
      if (calleeName && componentBodies.has(calleeName)) addComponentDependency(calleeName, owner)
      else unsafeComponents.add(owner)
      return
    }
    if (node.type === 'Identifier') {
      const name = String(node.name)
      if (scope.parameters.has(name)) unsafeComponents.add(owner)
      else if (componentBodies.has(name)) addComponentDependency(name, owner)
      else {
        const value = localValue(scope, name)
        if (value && !seenValues.has(value)) {
          seenValues.add(value)
          inspectComponentTree(owner, value, scope, seenValues)
        }
      }
      return
    }
    if (node.type.startsWith('TS')) return
    childNodes(node).forEach(child => inspectComponentTree(owner, child, scope, seenValues))
  }
  for (const [name, bodies] of componentBodies) {
    for (const body of bodies) {
      const scope = scopeFor(body)
      for (const expression of returnedExpressions(body)) inspectComponentTree(name, expression, scope)
    }
  }
  const unsafeQueue = [...unsafeComponents]
  for (let cursor = 0; cursor < unsafeQueue.length; cursor += 1) {
    const component = unsafeQueue[cursor]
    for (const dependent of componentDependents.get(component) ?? []) {
      if (unsafeComponents.has(dependent)) continue
      unsafeComponents.add(dependent)
      unsafeQueue.push(dependent)
    }
    for (const alias of aliasDependents.get(component) ?? []) {
      if (unsafeComponents.has(alias)) continue
      unsafeComponents.add(alias)
      unsafeQueue.push(alias)
    }
  }
  for (const component of unsafeComponents) readable.delete(component)
  return { bindings: readable, unreadableComponents: new Set([...unsafeComponents, ...unreadableNames]) }
}

function readableComponentExpression(
  node: Node | undefined,
  readableLazyCalls: Set<Node>,
  reactNamespaces: Set<string>,
  staticallyReadableBindings: Set<string>,
  parameterBindings: Set<string>,
): boolean {
  const expression = unwrapTransparentExpression(node)
  if (!expression) return false
  if (expression.type === 'Identifier') {
    const name = String(expression.name)
    return staticallyReadableBindings.has(name) && !parameterBindings.has(name)
  }
  if (readableLazyCalls.has(expression)) return true
  if (expression.type === 'Literal' && expression.value === null) return true
  if (expression.type === 'MemberExpression' || expression.type === 'OptionalMemberExpression') {
    const property = expression.property as Node
    const object = unwrapTransparentExpression(expression.object as Node)
    return (!expression.computed || staticStringValue(property) !== undefined)
      && object?.type === 'Identifier'
      && reactNamespaces.has(String(object.name))
      && staticallyReadableBindings.has(String(object.name))
      && !parameterBindings.has(String(object.name))
  }
  if (expression.type === 'ConditionalExpression') {
    return readableComponentExpression(expression.consequent as Node, readableLazyCalls, reactNamespaces, staticallyReadableBindings, parameterBindings)
      && readableComponentExpression(expression.alternate as Node, readableLazyCalls, reactNamespaces, staticallyReadableBindings, parameterBindings)
  }
  if (expression.type === 'LogicalExpression') {
    return readableComponentExpression(expression.left as Node, readableLazyCalls, reactNamespaces, staticallyReadableBindings, parameterBindings)
      && readableComponentExpression(expression.right as Node, readableLazyCalls, reactNamespaces, staticallyReadableBindings, parameterBindings)
  }
  return false
}

function isCanonicalWildcardPath(path: string | undefined, file: string, where: string): boolean {
  if (!path || !path.includes('*')) return false
  if ((path === '*' || path.endsWith('/*')) && path.indexOf('*') === path.length - 1) return true
  throw new Error(`${file}: <Route> in ${where} uses non-canonical wildcard path ${path}; put the splat '*' in its own final path segment so the inventory can audit it`)
}

function readableRouteElementExpression(
  node: Node | undefined,
  reactFactories: { factories: Set<string>; namespaces: Set<string> },
  readableLazyCalls: Set<Node>,
  reactNamespaces: Set<string>,
  readableBindings: Set<string>,
  parameterBindings: Set<string>,
  knownRouterComponents: Set<string>,
): boolean {
  const expression = unwrapTransparentExpression(node)
  if (!expression) return false
  const jsxValueIsReadable = (value: Node, allowRuntimeDOMProp = false): boolean => {
    const item = unwrapTransparentExpression(value)
    if (!item) return false
    // DOM attributes and event handlers do not create React descendants. Their
    // runtime values therefore cannot add routes to the JSX tree being read.
    if (allowRuntimeDOMProp) return true
    if (item.type === 'JSXElement' || item.type === 'JSXFragment') return readableJSX(item)
    if (item.type === 'ConditionalExpression') {
      return jsxValueIsReadable(item.consequent as Node) && jsxValueIsReadable(item.alternate as Node)
    }
    if (item.type === 'LogicalExpression') {
      return item.operator === '&&'
        ? jsxValueIsReadable(item.right as Node)
        : jsxValueIsReadable(item.left as Node) && jsxValueIsReadable(item.right as Node)
    }
    if (item.type === 'Literal') return item.value === null || ['string', 'number', 'boolean'].includes(typeof item.value)
    if (item.type === 'Identifier') {
      const name = String(item.name)
      return readableBindings.has(name) && !parameterBindings.has(name)
    }
    if (item.type === 'ArrayExpression') {
      return (item.elements as (Node | null)[]).every(element => element === null || jsxValueIsReadable(element))
    }
    if (item.type === 'ObjectExpression') {
      return (item.properties as Node[]).every(property => {
        if (property.type === 'SpreadElement' || property.type === 'SpreadProperty' || property.type === 'RestElement') return false
        const key = property.key as Node | undefined
        if (property.computed && staticStringValue(key) === undefined) return false
        const candidate = (property.type === 'Property' || property.type === 'ObjectProperty') ? property.value as Node | undefined : undefined
        return !!candidate && jsxValueIsReadable(candidate)
      })
    }
    if (item.type === 'TemplateLiteral' && (item.expressions as Node[]).length === 0) return true
    return readableRouteElementExpression(item, reactFactories, readableLazyCalls, reactNamespaces, readableBindings, parameterBindings, knownRouterComponents)
  }
  const readableJSX = (value: Node): boolean => {
    if (value.type === 'JSXFragment') {
      return (value.children as Node[]).every(child => child.type === 'JSXText'
        || (child.type === 'JSXExpressionContainer'
          ? jsxValueIsReadable(child.expression as Node)
          : readableJSX(child)))
    }
    if (value.type !== 'JSXElement') return false
    const opening = value.openingElement as Node
    const tag = opening.name as Node
    const componentName = tag.type === 'JSXIdentifier' ? String(tag.name) : undefined
    const intrinsic = !!componentName && (/^[a-z]/.test(componentName) || componentName.includes('-'))
    const knownRouter = !!componentName && knownRouterComponents.has(componentName)
    if (tag.type === 'JSXIdentifier') {
      const name = String(tag.name)
      if (!/^[a-z]/.test(name) && !name.includes('-')
        && (!readableBindings.has(name) || parameterBindings.has(name))) return false
    } else if (tag.type === 'JSXMemberExpression') {
      const root = jsxMemberRootIdentifier(tag)
      if (!root || !readableBindings.has(root) || parameterBindings.has(root)) return false
    } else if (tag.type !== 'JSXNamespacedName') {
      return false
    }
    for (const attribute of opening.attributes as Node[]) {
      if (attribute.type === 'JSXSpreadAttribute') return false
      const attributeValue = attribute.value as Node | null | undefined
      const attributeName = (attribute.name as Node | undefined)?.type === 'JSXIdentifier'
        ? String((attribute.name as Node).name)
        : undefined
      const eventHandler = attributeName !== undefined && /^on[A-Z]/.test(attributeName)
      if (attributeValue?.type === 'JSXExpressionContainer'
        && !jsxValueIsReadable(attributeValue.expression as Node, intrinsic || knownRouter || eventHandler)) return false
    }
    return (value.children as Node[]).every(child => child.type === 'JSXText'
      || (child.type === 'JSXExpressionContainer'
        ? jsxValueIsReadable(child.expression as Node)
        : readableJSX(child)))
  }
  if (expression.type === 'JSXElement' || expression.type === 'JSXFragment') return readableJSX(expression)
  if (expression.type === 'Literal') return expression.value === null || ['string', 'number', 'boolean'].includes(typeof expression.value)
  if (expression.type === 'ArrayExpression') {
    return (expression.elements as (Node | null)[]).every(element => element === null
      || readableRouteElementExpression(element, reactFactories, readableLazyCalls, reactNamespaces, readableBindings, parameterBindings, knownRouterComponents))
  }
  if (readableLazyCalls.has(expression)) return true
  if (expression.type === 'ConditionalExpression') {
    return readableRouteElementExpression(expression.consequent as Node, reactFactories, readableLazyCalls, reactNamespaces, readableBindings, parameterBindings, knownRouterComponents)
      && readableRouteElementExpression(expression.alternate as Node, reactFactories, readableLazyCalls, reactNamespaces, readableBindings, parameterBindings, knownRouterComponents)
  }
  if (expression.type === 'LogicalExpression') {
    if (expression.operator === '&&') return readableRouteElementExpression(expression.right as Node, reactFactories, readableLazyCalls, reactNamespaces, readableBindings, parameterBindings, knownRouterComponents)
    return readableRouteElementExpression(expression.left as Node, reactFactories, readableLazyCalls, reactNamespaces, readableBindings, parameterBindings, knownRouterComponents)
      && readableRouteElementExpression(expression.right as Node, reactFactories, readableLazyCalls, reactNamespaces, readableBindings, parameterBindings, knownRouterComponents)
  }
  if (expression.type === 'CallExpression') {
    const callee = unwrapTransparentExpression(expression.callee as Node | undefined)
    const isCreateElement = callee?.type === 'Identifier'
      ? reactFactories.factories.has(String(callee.name))
      : !!callee && (callee.type === 'MemberExpression' || callee.type === 'OptionalMemberExpression')
        && (callee.object as Node).type === 'Identifier'
        && reactFactories.namespaces.has(String((callee.object as Node).name))
        && memberPropertyName(callee) === 'createElement'
    if (!isCreateElement) return false
    const args = ((expression.arguments as Node[] | undefined) ?? []).filter(isNode)
    if (args.length === 0) return false
    const component = unwrapTransparentExpression(args[0])
    const intrinsicTag = component?.type === 'Literal' && typeof component.value === 'string'
    if (!intrinsicTag && !readableComponentExpression(component, readableLazyCalls, reactNamespaces, readableBindings, parameterBindings)) return false
    const readableValue = (value: Node): boolean => {
      const item = unwrapTransparentExpression(value)
      if (!item) return false
      if (item.type === 'Literal') return true
      if (item.type === 'JSXElement' || item.type === 'JSXFragment') return readableJSX(item)
      if (item.type === 'Identifier') return readableBindings.has(String(item.name)) && !parameterBindings.has(String(item.name))
      if (item.type === 'ArrayExpression') return (item.elements as (Node | null)[]).every(element => element === null || readableValue(element))
      if (item.type === 'ObjectExpression') {
        return (item.properties as Node[]).every(property => {
          if (property.type === 'SpreadElement' || property.type === 'SpreadProperty') return false
          const candidate = (property.type === 'Property' || property.type === 'ObjectProperty') ? property.value as Node | undefined : undefined
          return !!candidate && readableValue(candidate)
        })
      }
      if (item.type === 'ConditionalExpression') return readableValue(item.consequent as Node) && readableValue(item.alternate as Node)
      if (item.type === 'LogicalExpression') return readableValue(item.left as Node) && readableValue(item.right as Node)
      return false
    }
    if (args.length > 1 && args[1].type !== 'Literal' && !readableValue(args[1])) return false
    return args.slice(2).every(readableValue)
  }
  return false
}

function routeIndexAttribute(element: Node, file: string, where: string): boolean {
  const attribute = jsxAttribute(element, 'index')
  if (!attribute) return false
  if (attribute.value === null) return true
  const value = attribute.value as Node
  const expression = value.type === 'JSXExpressionContainer'
    ? unwrapTransparentExpression(value.expression as Node)
    : undefined
  if (expression?.type === 'Literal' && typeof expression.value === 'boolean') return expression.value
  throw new Error(`${file}: <Route> in ${where} has a non-literal index prop; use shorthand or a boolean literal so the console route inventory can determine whether it is an index route`)
}

function routeBooleanAttribute(element: Node, name: string, file: string, where: string): boolean | undefined {
  const attribute = jsxAttribute(element, name)
  if (!attribute) return undefined
  if (attribute.value === null) return true
  const value = attribute.value as Node
  const expression = value.type === 'JSXExpressionContainer'
    ? unwrapTransparentExpression(value.expression as Node)
    : undefined
  if (expression?.type === 'Literal' && typeof expression.value === 'boolean') return expression.value
  throw new Error(`${file}: <Route> in ${where} has a non-literal ${name} prop; use shorthand or a boolean literal so the console route inventory can preserve route matching`)
}

/** Router imports may only appear as JSX tag names, never as component values. */
function rejectRouterAPIValues(program: Node, file: string, local: { Route: Set<string>; Routes: Set<string> }): void {
  const visit = (node: Node, parent?: Node, field?: string) => {
    if (node.type === 'Identifier') {
      const name = String(node.name)
      const api = local.Route.has(name) ? 'Route' : local.Routes.has(name) ? 'Routes' : undefined
      if (api) {
        const isStaticPropertyName = (parent?.type === 'Property' || parent?.type === 'MethodDefinition' || parent?.type === 'ClassMethod') && field === 'key' && !parent.computed
          || parent?.type === 'MemberExpression' && field === 'property' && !parent.computed
        if (!isStaticPropertyName) {
          throw new Error(`${file} uses imported ${api} as a value outside a JSX tag; the console route inventory cannot follow router components passed through props, objects, or function calls`)
        }
      }
    }
    if (node.type === 'ImportDeclaration') return
    for (const [key, value] of Object.entries(node)) {
      if (key === 'parent') continue
      if (Array.isArray(value)) value.filter(isNode).forEach(child => visit(child, node, key))
      else if (isNode(value)) visit(value, node, key)
    }
  }
  visit(program)
}

/** The components that a JSX expression renders, by name. */
function renderedComponents(node: Node | undefined): string[] {
  if (!node) return []
  const names: string[] = []
  const visit = (current: Node) => {
    const name = jsxName(current)
    if (name && /^[A-Z]/.test(name)) names.push(name)
    else if (current.type === 'JSXElement') {
      const tag = ((current.openingElement as Node).name as Node)
      if (tag.type === 'JSXMemberExpression') {
        const root = jsxMemberRootIdentifier(tag)
        if (root) names.push(root)
      }
    }
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

function reactCreateElementAliases(program: Node, importedFactories: Set<string>, importedNamespaces: Set<string>): { factories: Set<string>; namespaces: Set<string> } {
  const namespaceDependents = new Map<string, Set<string>>()
  const factoryDependents = new Map<string, Set<string>>()
  const namespaceFactoryDependents = new Map<string, Set<string>>()
  const addDependent = (dependents: Map<string, Set<string>>, dependency: string, alias: string) => {
    const aliases = dependents.get(dependency) ?? new Set<string>()
    aliases.add(alias)
    dependents.set(dependency, aliases)
  }
  const bindFactoryFromNamespace = (namespace: string, binding: Node) => {
    if (binding.type === 'Identifier') addDependent(namespaceFactoryDependents, namespace, String(binding.name))
  }
  const collect = (node: Node) => {
    if (node.type === 'VariableDeclarator' || node.type === 'AssignmentExpression') {
      const binding = (node.type === 'VariableDeclarator' ? node.id : node.left) as Node
      const value = unwrapTransparentExpression((node.type === 'VariableDeclarator' ? node.init : node.right) as Node | undefined)
      if (binding.type === 'Identifier') {
        const name = String(binding.name)
        if (value?.type === 'Identifier') {
          addDependent(namespaceDependents, String(value.name), name)
          addDependent(factoryDependents, String(value.name), name)
        } else if (value && (value.type === 'MemberExpression' || value.type === 'OptionalMemberExpression')
          && memberPropertyName(value) === 'createElement') {
          const object = unwrapTransparentExpression(value.object as Node | undefined)
          if (object?.type === 'Identifier') bindFactoryFromNamespace(String(object.name), binding)
        }
      } else if (binding.type === 'ObjectPattern' && value?.type === 'Identifier') {
        for (const property of binding.properties as Node[]) {
          if (property.type !== 'Property' && property.type !== 'ObjectProperty') continue
          const key = property.key as Node
          const imported = property.computed ? staticStringValue(key) : key.type === 'Identifier' ? String(key.name) : staticStringValue(key)
          if (imported === 'createElement') bindFactoryFromNamespace(String(value.name), property.value as Node)
        }
      }
    }
    childNodes(node).forEach(collect)
  }
  collect(program)

  const namespaces = new Set(importedNamespaces)
  const namespaceQueue = [...namespaces]
  for (let cursor = 0; cursor < namespaceQueue.length; cursor += 1) {
    for (const alias of namespaceDependents.get(namespaceQueue[cursor]) ?? []) {
      if (namespaces.has(alias)) continue
      namespaces.add(alias)
      namespaceQueue.push(alias)
    }
  }

  const factories = new Set(importedFactories)
  const factoryQueue = [...factories]
  for (const namespace of namespaces) {
    for (const alias of namespaceFactoryDependents.get(namespace) ?? []) {
      if (factories.has(alias)) continue
      factories.add(alias)
      factoryQueue.push(alias)
    }
  }
  for (let cursor = 0; cursor < factoryQueue.length; cursor += 1) {
    for (const alias of factoryDependents.get(factoryQueue[cursor]) ?? []) {
      if (factories.has(alias)) continue
      factories.add(alias)
      factoryQueue.push(alias)
    }
  }
  return { factories, namespaces }
}

/** Tracks React.lazy aliases so opaque dynamic package components can be guarded. */
function reactLazyAliases(program: Node, importedLazies: Set<string>, namespaces: Set<string>): Set<string> {
  const dependents = new Map<string, Set<string>>()
  const namespaceLazies = new Map<string, Set<string>>()
  const add = (map: Map<string, Set<string>>, dependency: string, alias: string) => {
    const aliases = map.get(dependency) ?? new Set<string>()
    aliases.add(alias)
    map.set(dependency, aliases)
  }
  const bindPattern = (pattern: Node, namespace: string) => {
    if (pattern.type !== 'ObjectPattern') return
    for (const property of pattern.properties as Node[]) {
      if (property.type !== 'Property' && property.type !== 'ObjectProperty') continue
      const key = property.key as Node
      const imported = property.computed ? staticStringValue(key) : key.type === 'Identifier' ? String(key.name) : staticStringValue(key)
      if (imported !== 'lazy') continue
      const value = property.value as Node
      if (value.type === 'Identifier') add(namespaceLazies, namespace, String(value.name))
    }
  }
  const collect = (node: Node) => {
    if (node.type === 'VariableDeclarator' || node.type === 'AssignmentExpression') {
      const binding = (node.type === 'VariableDeclarator' ? node.id : node.left) as Node
      const value = unwrapTransparentExpression((node.type === 'VariableDeclarator' ? node.init : node.right) as Node | undefined)
      if (binding.type === 'Identifier' && value?.type === 'Identifier') {
        add(dependents, String(value.name), String(binding.name))
      } else if (binding.type === 'Identifier' && value
        && (value.type === 'MemberExpression' || value.type === 'OptionalMemberExpression')
        && memberPropertyName(value) === 'lazy') {
        const object = unwrapTransparentExpression(value.object as Node | undefined)
        if (object?.type === 'Identifier' && namespaces.has(String(object.name))) importedLazies.add(String(binding.name))
      } else if (value?.type === 'Identifier' && namespaces.has(String(value.name))) {
        bindPattern(binding, String(value.name))
      }
    }
    childNodes(node).forEach(collect)
  }
  collect(program)

  const lazies = new Set(importedLazies)
  for (const namespace of namespaces) {
    for (const alias of namespaceLazies.get(namespace) ?? []) lazies.add(alias)
  }
  const queue = [...lazies]
  for (let cursor = 0; cursor < queue.length; cursor += 1) {
    for (const alias of dependents.get(queue[cursor]) ?? []) {
      if (lazies.has(alias)) continue
      lazies.add(alias)
      queue.push(alias)
    }
  }
  return lazies
}

function dynamicLazyComponentImports(
  program: Node,
  lazyFactories: Set<string>,
  namespaces: Set<string>,
  isLocalSpecifier: (specifier: string) => boolean,
  loadedModuleBindings: Map<string, { source: string }>,
  file: string,
): { bindings: Map<string, { source: string }>; calls: Map<Node, { component: string; source: string }>; readableCalls: Set<Node> } {
  const imports = new Map<string, { source: string }>()
  const calls = new Map<Node, { component: string; source: string }>()
  const readableCalls = new Set<Node>()
  const isOpaquePackage = (specifier: string) => isOpaqueExternalPackage(specifier, isLocalSpecifier)
  const lazyCall = (node: Node | undefined) => {
    const callee = unwrapTransparentExpression(node)
    if (callee?.type === 'Identifier') return lazyFactories.has(String(callee.name))
    if (!callee || (callee.type !== 'MemberExpression' && callee.type !== 'OptionalMemberExpression')) return false
    const object = unwrapTransparentExpression(callee.object as Node | undefined)
    return memberPropertyName(callee) === 'lazy' && object?.type === 'Identifier' && namespaces.has(String(object.name))
  }
  const loaderFunctions = new Map<string, Set<Node>>()
  const loaderAliases = new Map<string, Set<string>>()
  const addLoaderFunction = (name: string, fn: Node) => {
    const functions = loaderFunctions.get(name) ?? new Set<Node>()
    functions.add(fn)
    loaderFunctions.set(name, functions)
  }
  const addLoaderAlias = (name: string, target: string) => {
    const aliases = loaderAliases.get(name) ?? new Set<string>()
    aliases.add(target)
    loaderAliases.set(name, aliases)
  }
  const collectLoaderBindings = (node: Node, parent?: Node) => {
    if (node.type === 'FunctionDeclaration' && isNode(node.id)) {
      addLoaderFunction(String((node.id as Node).name), node)
    }
    if (node.type === 'VariableDeclarator' && parent?.type === 'VariableDeclaration' && parent.kind === 'const') {
      const binding = node.id as Node
      const value = unwrapTransparentExpression(node.init as Node | undefined)
      if (binding.type === 'Identifier' && value) {
        const name = String(binding.name)
        if (value.type === 'ArrowFunctionExpression' || value.type === 'FunctionExpression') addLoaderFunction(name, value)
        else if (value.type === 'Identifier') addLoaderAlias(name, String(value.name))
      }
    }
    for (const child of childNodes(node)) collectLoaderBindings(child, node)
  }
  collectLoaderBindings(program)
  const resolveLoaderFunction = (name: string, seen = new Set<string>()): Node | undefined => {
    if (seen.has(name)) return undefined
    seen.add(name)
    const functions = loaderFunctions.get(name)
    const aliases = loaderAliases.get(name)
    if ((functions?.size ?? 0) > 1 || (functions?.size && aliases?.size)) return undefined
    if (functions?.size === 1) return [...functions][0]
    if (aliases?.size !== 1) return undefined
    return resolveLoaderFunction([...aliases][0], seen)
  }
  const opaqueImportsIn = (node: Node | undefined): string[] => {
    if (!node) return []
    const sources: string[] = []
    const visit = (current: Node) => {
      if (current.type === 'Identifier') {
        const loadedSource = loadedModuleBindings.get(String(current.name))?.source
        if (loadedSource) sources.push(loadedSource)
      }
      let specifier: string | undefined
      if (current.type === 'ImportExpression') specifier = staticStringValue(current.source as Node | undefined)
      else if ((current.type === 'CallExpression' || current.type === 'OptionalCallExpression')
        && (current.callee as Node).type === 'Import') {
        specifier = staticStringValue((current.arguments as Node[] | undefined)?.[0])
      }
      if (specifier && isOpaquePackage(specifier)) sources.push(specifier)
      childNodes(current).forEach(visit)
    }
    visit(node)
    return sources
  }
  const hasLiteralDynamicImport = (nodes: Node[]): boolean => {
    let found = false
    const visit = (current: Node) => {
      if (current.type === 'ImportExpression' && staticStringValue(current.source as Node | undefined) !== undefined) found = true
      if ((current.type === 'CallExpression' || current.type === 'OptionalCallExpression')
        && (current.callee as Node).type === 'Import'
        && staticStringValue((current.arguments as Node[] | undefined)?.[0]) !== undefined) found = true
      childNodes(current).forEach(visit)
    }
    nodes.forEach(visit)
    return found
  }
  const lazyReturnExpressions = (callback: Node | undefined): { readable: boolean; values: Node[] } => {
    const expression = unwrapTransparentExpression(callback)
    const fn = expression?.type === 'Identifier'
      ? resolveLoaderFunction(String(expression.name))
      : expression
    if (fn?.type !== 'ArrowFunctionExpression' && fn?.type !== 'FunctionExpression' && fn?.type !== 'FunctionDeclaration') {
      return { readable: false, values: [] }
    }
    const body = fn.body as Node
    if (body.type !== 'BlockStatement') return { readable: true, values: [body] }
    const values: Node[] = []
    const visit = (node: Node) => {
      if (node !== body && ['ArrowFunctionExpression', 'FunctionExpression', 'FunctionDeclaration'].includes(node.type)) return
      if (node.type === 'ReturnStatement' && isNode(node.argument)) values.push(node.argument as Node)
      childNodes(node).forEach(visit)
    }
    visit(body)
    return { readable: true, values }
  }
  const opaqueLazyCall = (node: Node): { component: string; source: string } | undefined => {
    if ((node.type !== 'CallExpression' && node.type !== 'OptionalCallExpression') || !lazyCall(node.callee as Node | undefined)) return undefined
    const callee = unwrapTransparentExpression(node.callee as Node | undefined)
    const object = callee && (callee.type === 'MemberExpression' || callee.type === 'OptionalMemberExpression')
      ? unwrapTransparentExpression(callee.object as Node | undefined)
      : undefined
    const component = callee?.type === 'Identifier' ? String(callee.name) : `${String(object?.type === 'Identifier' ? object.name : 'React')}.lazy`
    const callback = (node.arguments as Node[] | undefined)?.[0]
    const loader = lazyReturnExpressions(callback)
    if (!loader.readable) {
      throw new Error(`${file}: ${component} has a React.lazy callback the route inventory cannot read; use an inline function or a statically declared loader function/arrow binding`)
    }
    const importedSources = loader.values.flatMap(opaqueImportsIn)
    // A syntactically readable callback can still return a component from a
    // runtime registry or other value the inventory cannot trace. Only accept
    // loaders whose returned expression contains a literal dynamic import or
    // a tracked opaque module value; wildcard route checks can then distinguish
    // inspectable local pages from opaque package components.
    if (!hasLiteralDynamicImport(loader.values) && importedSources.length === 0) return undefined
    readableCalls.add(node)
    const source = importedSources[0]
    return source ? { component, source } : undefined
  }
  const originIn = (node: Node | undefined): { component: string; source: string } | undefined => {
    if (!node || node.type === 'ArrowFunctionExpression' || node.type === 'FunctionExpression' || node.type === 'FunctionDeclaration') return undefined
    const origin = calls.get(node)
    if (origin) return origin
    for (const child of childNodes(node)) {
      const nested = originIn(child)
      if (nested) return nested
    }
    return undefined
  }
  const inspectCalls = (node: Node) => {
    if (node.type === 'CallExpression' || node.type === 'OptionalCallExpression') {
      const origin = opaqueLazyCall(node)
      if (origin) calls.set(node, origin)
    }
    childNodes(node).forEach(inspectCalls)
  }
  const inspectBindings = (node: Node) => {
    if (node.type === 'VariableDeclarator' || node.type === 'AssignmentExpression') {
      const binding = (node.type === 'VariableDeclarator' ? node.id : node.left) as Node
      const value = unwrapTransparentExpression((node.type === 'VariableDeclarator' ? node.init : node.right) as Node | undefined)
      const origin = originIn(value)
      if (binding.type === 'Identifier' && origin) imports.set(String(binding.name), { source: origin.source })
    }
    childNodes(node).forEach(inspectBindings)
  }
  inspectCalls(program)
  inspectBindings(program)
  return { bindings: imports, calls, readableCalls }
}

function renderedImportedComponents(
  node: Node | undefined,
  imports: Map<string, { source: string }>,
  file: string,
  factories: Set<string>,
  namespaces: Set<string>,
  dynamicLazyCalls: Map<Node, { component: string; source: string }>,
  inspectRootValues = false,
  opaqueRuntimeModuleLoads = new Map<Node, string>(),
): { component: string; source: string; file: string }[] {
  if (!node) return []
  const rendered = new Map<string, { component: string; source: string; file: string }>()
  const add = (binding: string | undefined) => {
    const source = binding ? imports.get(binding)?.source : undefined
    if (binding && source) {
      const component = binding.startsWith('@member:') ? binding.slice('@member:'.length)
        : binding.startsWith('@member-root:') ? binding.slice('@member-root:'.length)
          : binding
      rendered.set(binding, { component, source, file })
    }
  }
  const addImportedValues = (value: Node) => {
    const visitValues = (current: Node, parent?: Node, field?: string) => {
      if (current.type === 'MemberExpression' || current.type === 'OptionalMemberExpression') {
        const path = staticMemberPath(current)
        if (path) {
          add(`@member:${path}`)
          const root = memberRootIdentifier(current)
          if (root) add(root)
        }
        else {
          const root = memberRootIdentifier(current)
          if (root) add(`@member-root:${root}`)
        }
      }
      if (current.type === 'Identifier') {
        const isStaticPropertyName = (parent?.type === 'Property' || parent?.type === 'ObjectProperty') && field === 'key' && !parent.computed
          || (parent?.type === 'MemberExpression' || parent?.type === 'OptionalMemberExpression') && field === 'property' && !parent.computed
        if (!isStaticPropertyName) add(String(current.name))
      }
      for (const [key, child] of Object.entries(current)) {
        if (key === 'parent') continue
        if (Array.isArray(child)) child.filter(isNode).forEach(item => visitValues(item, current, key))
        else if (isNode(child)) visitValues(child, current, key)
      }
    }
    visitValues(value)
  }
  if (inspectRootValues && node) addImportedValues(node)
  const visit = (current: Node, parent?: Node, field?: string) => {
    const runtimeSource = opaqueRuntimeModuleLoads.get(current)
    if (runtimeSource) {
      rendered.set(`runtime:${String(current.start ?? rendered.size)}`, { component: 'runtime module load', source: runtimeSource, file })
    }
    const dynamicLazyComponent = dynamicLazyCalls.get(current)
    if (dynamicLazyComponent) {
      const key = `lazy:${String(current.start ?? rendered.size)}:${dynamicLazyComponent.source}`
      rendered.set(key, { ...dynamicLazyComponent, file })
    }
    if (current.type === 'Identifier') {
      const isStaticPropertyName = (parent?.type === 'Property' || parent?.type === 'ObjectProperty') && field === 'key' && !parent.computed
        || (parent?.type === 'MemberExpression' || parent?.type === 'OptionalMemberExpression') && field === 'property' && !parent.computed
      if (!isStaticPropertyName && /^[A-Z]/.test(String(current.name))) add(String(current.name))
    }
    if (current.type === 'CallExpression' || current.type === 'OptionalCallExpression') {
      const callee = unwrapTransparentExpression(current.callee as Node | undefined)
      const isCreateElement = callee?.type === 'Identifier'
        ? factories.has(String(callee.name))
        : !!callee && (callee.type === 'MemberExpression' || callee.type === 'OptionalMemberExpression')
          && isNode(callee.object) && callee.object.type === 'Identifier' && namespaces.has(String(callee.object.name))
          && memberPropertyName(callee) === 'createElement'
      const firstArgument = (current.arguments as Node[] | undefined)?.[0]
      const propsArgument = (current.arguments as Node[] | undefined)?.[1]
      if (isCreateElement) {
        // A factory can render its first argument directly or forward an
        // imported component through props to a wrapper's JSX tag. Inspect
        // both values; the alias map includes local bindings and transparent
        // TypeScript expressions.
        if (firstArgument) addImportedValues(firstArgument)
        if (propsArgument) addImportedValues(propsArgument)
      }
    }
    if (current.type === 'CallExpression' || current.type === 'OptionalCallExpression' || current.type === 'NewExpression') {
      for (const argument of (current.arguments as Node[]).filter(isNode)) addImportedValues(argument)
    }
    if (current.type === 'JSXElement') {
      const name = (current.openingElement as Node).name as Node
      if (name.type === 'JSXIdentifier') add(String(name.name))
      else if (name.type === 'JSXMemberExpression') {
        const path = jsxMemberStaticPath(name)
        if (path) add(`@member:${path}`)
        add(jsxMemberRootIdentifier(name))
      }
      for (const attribute of (current.openingElement as Node).attributes as Node[]) {
        if (attribute.type === 'JSXSpreadAttribute') {
          addImportedValues(attribute.argument as Node)
          continue
        }
        const value = attribute.value as Node | null | undefined
        if (value?.type === 'JSXExpressionContainer') {
          addImportedValues(value.expression as Node)
        }
      }
    }
    for (const [key, value] of Object.entries(current)) {
      if (key === 'parent') continue
      if (Array.isArray(value)) value.filter(isNode).forEach(child => visit(child, current, key))
      else if (isNode(value)) visit(value, current, key)
    }
  }
  visit(node)
  return [...rendered.values()]
}

/** Propagates package-component provenance through local bindings and values. */
function importedComponentAliases(program: Node, imports: Map<string, ComponentOrigin>): Map<string, ComponentOrigin> {
  const dependents = new Map<string, Set<string>>()
  const addBindingNames = (pattern: Node | undefined, names: Set<string>) => {
    if (!pattern) return
    if (pattern.type === 'Identifier') {
      names.add(String(pattern.name))
      return
    }
    if (pattern.type === 'MemberExpression' || pattern.type === 'OptionalMemberExpression') {
      const path = staticMemberPath(pattern)
      if (path) names.add(`@member:${path}`)
      else {
        const root = memberRootIdentifier(pattern)
        if (root) names.add(`@member-root:${root}`)
      }
      return
    }
    if (pattern.type === 'RestElement' || pattern.type === 'AssignmentPattern') {
      addBindingNames((pattern.argument ?? pattern.left) as Node | undefined, names)
      return
    }
    if (pattern.type === 'ObjectPattern') {
      for (const property of pattern.properties as Node[]) {
        addBindingNames((property.type === 'RestElement' ? property.argument : property.value) as Node | undefined, names)
      }
      return
    }
    if (pattern.type === 'ArrayPattern') {
      for (const element of pattern.elements as (Node | null)[]) if (element) addBindingNames(element, names)
    }
  }
  const addDependencies = (binding: Node | undefined, value: Node | undefined) => {
    const names = new Set<string>()
    addBindingNames(binding, names)
    if (!names.size || !value) return
    const references = new Set<string>()
    const addReference = (node: Node, parent?: Node, field?: string) => {
      if (node.type !== 'Identifier') return
      const isStaticPropertyName = ((parent?.type === 'Property' || parent?.type === 'ObjectProperty') && field === 'key' && !parent.computed)
        || ((parent?.type === 'MemberExpression' || parent?.type === 'OptionalMemberExpression') && field === 'property' && !parent.computed)
      const isBindingIdentifier = (parent?.type === 'VariableDeclarator' && field === 'id')
        || ((parent?.type === 'FunctionDeclaration' || parent?.type === 'FunctionExpression' || parent?.type === 'ClassDeclaration' || parent?.type === 'ClassExpression') && field === 'id')
      if (!isStaticPropertyName && !isBindingIdentifier) references.add(String(node.name))
    }
    function visitComponentValueReferences(node: Node | undefined, parent?: Node, field?: string): void {
      if (!node) return
      const expression = unwrapTransparentExpression(node)
      if (expression !== node) {
        if (expression) visitComponentValueReferences(expression, parent, field)
        return
      }
      if (node.type.startsWith('TS')) return
      if (node.type === 'Identifier') {
        addReference(node, parent, field)
        return
      }
      if (node.type === 'JSXElement') {
        const opening = node.openingElement as Node
        const name = opening.name as Node
        if (name.type === 'JSXIdentifier') references.add(String(name.name))
        else if (name.type === 'JSXMemberExpression') {
          const root = jsxMemberRootIdentifier(name)
          const path = jsxMemberStaticPath(name)
          if (path) references.add(`@member:${path}`)
          if (root) references.add(root)
        }
        for (const attribute of opening.attributes as Node[]) {
          if (attribute.type === 'JSXSpreadAttribute') {
            visitComponentValueReferences(attribute.argument as Node | undefined, attribute, 'argument')
            continue
          }
          const attributeValue = attribute.value as Node | null | undefined
          if (attributeValue?.type === 'JSXExpressionContainer') {
            visitComponentValueReferences(attributeValue.expression as Node | undefined, attributeValue, 'expression')
          }
        }
        for (const child of node.children as Node[]) visitComponentBodyReferences(child)
        return
      }
      if (node.type === 'JSXFragment') {
        for (const child of node.children as Node[]) visitComponentBodyReferences(child)
        return
      }
      if (node.type === 'FunctionDeclaration' || node.type === 'FunctionExpression' || node.type === 'ArrowFunctionExpression'
        || node.type === 'ObjectMethod' || node.type === 'ClassMethod' || node.type === 'MethodDefinition') {
        visitComponentBodyReferences(node.body as Node | undefined)
        return
      }
      for (const [key, value] of Object.entries(node)) {
        if (key === 'parent') continue
        if (Array.isArray(value)) value.filter(isNode).forEach(child => visitComponentValueReferences(child, node, key))
        else if (isNode(value)) visitComponentValueReferences(value, node, key)
      }
    }
    function visitComponentBodyReferences(node: Node | undefined): void {
      if (!node) return
      if (node.type === 'JSXElement' || node.type === 'JSXFragment') {
        visitComponentValueReferences(node)
        return
      }
      if (node.type === 'ReturnStatement') {
        visitComponentValueReferences(node.argument as Node | undefined, node, 'argument')
        return
      }
      if (node.type === 'JSXExpressionContainer') {
        visitComponentValueReferences(node.expression as Node | undefined, node, 'expression')
        return
      }
      if (node.type === 'JSXSpreadChild') {
        visitComponentValueReferences(node.expression as Node | undefined, node, 'expression')
        return
      }
      if (node.type === 'CallExpression' || node.type === 'OptionalCallExpression' || node.type === 'NewExpression') {
        for (const argument of (node.arguments as Node[] | undefined) ?? []) visitComponentValueReferences(argument, node, 'arguments')
        return
      }
      if (node.type === 'FunctionDeclaration' || node.type === 'FunctionExpression' || node.type === 'ArrowFunctionExpression'
        || node.type === 'ObjectMethod' || node.type === 'ClassMethod' || node.type === 'MethodDefinition') return
      for (const [key, value] of Object.entries(node)) {
        if (key === 'parent') continue
        if (Array.isArray(value)) value.filter(isNode).forEach(visitComponentBodyReferences)
        else if (isNode(value)) visitComponentBodyReferences(value)
      }
    }
    const visitReferences = (node: Node | undefined, parent?: Node, field?: string) => {
      if (!node) return
      const expression = unwrapTransparentExpression(node)
      if (expression !== node) {
        if (expression) visitReferences(expression, parent, field)
        return
      }
      if (node.type.startsWith('TS')) return
      if (node.type === 'Identifier') {
        addReference(node, parent, field)
        return
      }
      if (node.type === 'FunctionDeclaration' || node.type === 'FunctionExpression' || node.type === 'ArrowFunctionExpression'
        || node.type === 'ObjectMethod' || node.type === 'ClassMethod' || node.type === 'MethodDefinition') {
        visitComponentBodyReferences(node.body as Node | undefined)
        return
      }
      if (node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression') {
        const path = staticMemberPath(node)
        if (path) {
          references.add(`@member:${path}`)
          const root = memberRootIdentifier(node)
          if (root) references.add(root)
        }
        else {
          const root = memberRootIdentifier(node)
          if (root) references.add(`@member-root:${root}`)
          visitReferences(node.object as Node | undefined, node, 'object')
        }
        return
      }
      if (node.type === 'ConditionalExpression') {
        visitReferences(node.consequent as Node | undefined, node, 'consequent')
        visitReferences(node.alternate as Node | undefined, node, 'alternate')
        return
      }
      if (node.type === 'LogicalExpression') {
        visitReferences(node.left as Node | undefined, node, 'left')
        visitReferences(node.right as Node | undefined, node, 'right')
        return
      }
      if (node.type === 'ArrayExpression') {
        for (const element of node.elements as (Node | null)[]) if (element) visitReferences(element, node, 'elements')
        return
      }
      if (node.type === 'ObjectExpression') {
        for (const property of node.properties as Node[]) {
          visitReferences((property.type === 'RestElement' ? property.argument : property.value) as Node | undefined, property, 'value')
        }
        return
      }
      if (node.type === 'ImportDeclaration') return
      for (const [key, value] of Object.entries(node)) {
        if (key === 'parent') continue
        if (Array.isArray(value)) value.filter(isNode).forEach(child => visitReferences(child, node, key))
        else if (isNode(value)) visitReferences(value, node, key)
      }
    }
    visitReferences(value)
    for (const reference of references) {
      const aliases = dependents.get(reference) ?? new Set<string>()
      for (const name of names) aliases.add(name)
      dependents.set(reference, aliases)
    }
  }
  const collect = (node: Node) => {
    if (node.type === 'VariableDeclarator') addDependencies(node.id as Node | undefined, node.init as Node | undefined)
    if (node.type === 'AssignmentExpression') addDependencies(node.left as Node | undefined, node.right as Node | undefined)
    if (node.type === 'FunctionDeclaration' && isNode(node.id)) addDependencies(node.id, node)
    if (node.type === 'ClassDeclaration' && isNode(node.id)) addDependencies(node.id, node)
    childNodes(node).forEach(collect)
  }
  collect(program)

  const resolved = new Map(imports)
  const worklist = [...imports.keys()]
  for (let cursor = 0; cursor < worklist.length; cursor += 1) {
    const source = resolved.get(worklist[cursor])!
    for (const alias of dependents.get(worklist[cursor]) ?? []) {
      if (resolved.has(alias)) continue
      resolved.set(alias, source)
      worklist.push(alias)
    }
  }
  return resolved
}

/** Resolves value aliases of local component imports without treating metadata reads as renders. */
function localComponentValueAliases(
  program: Node,
  imports: Map<string, { source: string }>,
  namespaceImports: Set<string>,
): Map<string, { source: string }> {
  const dependents = new Map<string, Set<string>>()
  const componentReferences = (node: Node | undefined): Set<string> => {
    const references = new Set<string>()
    const visit = (value: Node | undefined) => {
      const expression = unwrapTransparentExpression(value)
      if (!expression) return
      if (expression.type === 'Identifier') {
        references.add(String(expression.name))
      } else if (expression.type === 'ConditionalExpression') {
        visit(expression.consequent as Node | undefined)
        visit(expression.alternate as Node | undefined)
      } else if (expression.type === 'LogicalExpression') {
        visit(expression.left as Node | undefined)
        visit(expression.right as Node | undefined)
      } else if (expression.type === 'MemberExpression' || expression.type === 'OptionalMemberExpression') {
        const root = memberRootIdentifier(expression)
        if (root && namespaceImports.has(root)) references.add(root)
      }
    }
    visit(node)
    return references
  }
  const addAlias = (binding: Node | undefined, value: Node | undefined) => {
    if (binding?.type !== 'Identifier') return
    const alias = String(binding.name)
    for (const source of componentReferences(value)) {
      const aliases = dependents.get(source) ?? new Set<string>()
      aliases.add(alias)
      dependents.set(source, aliases)
    }
  }
  const collect = (node: Node) => {
    if (node.type === 'VariableDeclarator') addAlias(node.id as Node | undefined, node.init as Node | undefined)
    if (node.type === 'AssignmentExpression') addAlias(node.left as Node | undefined, node.right as Node | undefined)
    childNodes(node).forEach(collect)
  }
  collect(program)

  const sources = new Map<string, Set<string>>()
  const queue: string[] = []
  for (const [name, origin] of imports) {
    sources.set(name, new Set([origin.source]))
    queue.push(name)
  }
  let propagationSteps = 0
  for (let cursor = 0; cursor < queue.length; cursor += 1) {
    const sourceName = queue[cursor]
    for (const alias of dependents.get(sourceName) ?? []) {
      const origins = sources.get(alias) ?? new Set<string>()
      let changed = false
      for (const origin of sources.get(sourceName) ?? []) {
        if (origins.has(origin)) continue
        origins.add(origin)
        changed = true
        propagationSteps += 1
        if (propagationSteps > 50_000) {
          throw new Error(`local component alias provenance exceeded 50000 propagation steps; the console route inventory cannot inspect this module`)
        }
      }
      if (changed || !sources.has(alias)) {
        sources.set(alias, origins)
        queue.push(alias)
      }
    }
  }
  return new Map([...sources].map(([name, origins]) => [
    name,
    { source: origins.size === 1 ? [...origins][0] : `@ambiguous:${name}` },
  ]))
}

/** Finds imported values that flow through local aliases to a runtime export. */
function runtimeExportedValueBindings(program: Node): Set<string> {
  const dependencies = new Map<string, Set<string>>()
  const addBindingNames = (pattern: Node | undefined, names: Set<string>) => {
    if (!pattern) return
    if (pattern.type === 'Identifier') names.add(String(pattern.name))
    else if (pattern.type === 'MemberExpression' || pattern.type === 'OptionalMemberExpression') {
      const path = staticMemberPath(pattern)
      if (path) names.add(`@member:${path}`)
      const root = memberRootIdentifier(pattern)
      if (root) names.add(root)
    } else if (pattern.type === 'RestElement' || pattern.type === 'AssignmentPattern') {
      addBindingNames((pattern.argument ?? pattern.left) as Node | undefined, names)
    } else if (pattern.type === 'ObjectPattern') {
      for (const property of pattern.properties as Node[]) {
        addBindingNames((property.type === 'RestElement' ? property.argument : property.value) as Node | undefined, names)
      }
    } else if (pattern.type === 'ArrayPattern') {
      for (const element of pattern.elements as (Node | null)[]) if (element) addBindingNames(element, names)
    }
  }
  const addValueReferences = (node: Node | undefined, references: Set<string>, parent?: Node, field?: string) => {
    if (!node) return
    const expression = unwrapTransparentExpression(node)
    if (expression !== node) {
      if (expression) addValueReferences(expression, references, parent, field)
      return
    }
    if (node.type.startsWith('TS') || node.type === 'ImportDeclaration') return
    if (node.type === 'FunctionDeclaration' || node.type === 'FunctionExpression' || node.type === 'ArrowFunctionExpression'
      || node.type === 'ObjectMethod' || node.type === 'ClassMethod' || node.type === 'MethodDefinition') return
    if (node.type === 'Identifier') {
      const staticProperty = ((parent?.type === 'Property' || parent?.type === 'ObjectProperty') && field === 'key' && parent.computed !== true)
        || ((parent?.type === 'MemberExpression' || parent?.type === 'OptionalMemberExpression') && field === 'property' && parent.computed !== true)
      if (!staticProperty) references.add(String(node.name))
      return
    }
    if (node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression') {
      const path = staticMemberPath(node)
      if (path) references.add(`@member:${path}`)
      const root = memberRootIdentifier(node)
      if (root) references.add(root)
      if (!path) {
        addValueReferences(node.object as Node | undefined, references, node, 'object')
        if (node.computed) addValueReferences(node.property as Node | undefined, references, node, 'property')
      }
      return
    }
    if (node.type === 'CallExpression' || node.type === 'OptionalCallExpression' || node.type === 'NewExpression') {
      for (const argument of (node.arguments as Node[] | undefined) ?? []) addValueReferences(argument, references, node, 'arguments')
      return
    }
    if (node.type === 'JSXElement') {
      const opening = node.openingElement as Node
      const name = opening.name as Node
      if (name.type === 'JSXIdentifier') references.add(String(name.name))
      else if (name.type === 'JSXMemberExpression') {
        const root = jsxMemberRootIdentifier(name)
        const path = jsxMemberStaticPath(name)
        if (path) references.add(`@member:${path}`)
        if (root) references.add(root)
      }
      for (const attribute of opening.attributes as Node[]) {
        const value = attribute.type === 'JSXSpreadAttribute' ? attribute.argument as Node
          : (attribute.value as Node | null | undefined)?.type === 'JSXExpressionContainer'
            ? ((attribute.value as Node).expression as Node)
            : undefined
        addValueReferences(value, references, attribute, 'value')
      }
      for (const child of node.children as Node[]) addValueReferences(child, references, node, 'children')
      return
    }
    if (node.type === 'JSXFragment') {
      for (const child of node.children as Node[]) addValueReferences(child, references, node, 'children')
      return
    }
    for (const [key, value] of Object.entries(node)) {
      if (key === 'parent') continue
      if (Array.isArray(value)) value.filter(isNode).forEach(child => addValueReferences(child, references, node, key))
      else if (isNode(value)) addValueReferences(value, references, node, key)
    }
  }
  const addDependency = (binding: Node | undefined, value: Node | undefined) => {
    const outputs = new Set<string>()
    addBindingNames(binding, outputs)
    if (!outputs.size || !value) return
    const references = new Set<string>()
    addValueReferences(value, references)
    for (const output of outputs) {
      const inputs = dependencies.get(output) ?? new Set<string>()
      for (const reference of references) inputs.add(reference)
      dependencies.set(output, inputs)
    }
  }
  const exported = new Set<string>()
  const collect = (node: Node) => {
    if (node.type === 'VariableDeclarator') addDependency(node.id as Node | undefined, node.init as Node | undefined)
    if (node.type === 'AssignmentExpression') addDependency(node.left as Node | undefined, node.right as Node | undefined)
    for (const statement of (node.type === 'Program' ? node.body as Node[] : [])) {
      if (statement.type === 'ExportDefaultDeclaration') {
        const declaration = statement.declaration as Node
        if (declaration.type === 'Identifier') exported.add(String(declaration.name))
        else if ((declaration.type === 'FunctionDeclaration' || declaration.type === 'ClassDeclaration') && isNode(declaration.id)) {
          exported.add(String((declaration.id as Node).name))
        } else addValueReferences(declaration, exported)
      }
      if (statement.type === 'ExportNamedDeclaration') {
        const declaration = statement.declaration as Node | undefined
        if (declaration?.type === 'VariableDeclaration') {
          for (const declarator of declaration.declarations as Node[]) addBindingNames(declarator.id as Node | undefined, exported)
        } else if ((declaration?.type === 'FunctionDeclaration' || declaration?.type === 'ClassDeclaration') && isNode(declaration.id)) {
          exported.add(String((declaration.id as Node).name))
        }
        for (const specifier of (statement.specifiers as Node[] | undefined) ?? []) {
          const local = specifier.local as Node | undefined
          if (local?.type === 'Identifier') exported.add(String(local.name))
        }
      }
    }
    childNodes(node).forEach(collect)
  }
  collect(program)

  const reachable = new Set(exported)
  const pending = [...exported]
  for (let cursor = 0; cursor < pending.length; cursor += 1) {
    for (const dependency of dependencies.get(pending[cursor]) ?? []) {
      if (reachable.has(dependency)) continue
      reachable.add(dependency)
      pending.push(dependency)
    }
  }
  return reachable
}

function componentBindingsUsedInJSX(program: Node): Set<string> {
  const bindings = new Set<string>()
  const importedFactories = new Set<string>()
  const importedNamespaces = new Set<string>()
  for (const statement of program.body as Node[]) {
    if (statement.type !== 'ImportDeclaration' || String((statement.source as Node).value) !== 'react') continue
    for (const specifier of statement.specifiers as Node[]) {
      if (specifier.type === 'ImportNamespaceSpecifier') importedNamespaces.add(String((specifier.local as Node).name))
      if (specifier.type === 'ImportSpecifier' && String((specifier.imported as Node).name) === 'createElement') {
        importedFactories.add(String((specifier.local as Node).name))
      }
    }
  }
  const reactFactories = reactCreateElementAliases(program, importedFactories, importedNamespaces)
  const addExpressionBindings = (node: Node | undefined, parent?: Node, field?: string) => {
    if (!node) return
    if (node.type === 'Identifier') {
      const isStaticPropertyName = ((parent?.type === 'Property' || parent?.type === 'ObjectProperty') && field === 'key' && !parent.computed)
        || ((parent?.type === 'MemberExpression' || parent?.type === 'OptionalMemberExpression') && field === 'property' && !parent.computed)
      if (!isStaticPropertyName) bindings.add(String(node.name))
      return
    }
    for (const [key, value] of Object.entries(node)) {
      if (key === 'parent') continue
      if (Array.isArray(value)) value.filter(isNode).forEach(child => addExpressionBindings(child, node, key))
      else if (isNode(value)) addExpressionBindings(value, node, key)
    }
  }
  const visit = (node: Node) => {
    if (node.type === 'CallExpression' || node.type === 'OptionalCallExpression' || node.type === 'NewExpression') {
      const callee = unwrapTransparentExpression(node.callee as Node | undefined)
      const isCreateElement = callee?.type === 'Identifier'
        ? reactFactories.factories.has(String(callee.name))
        : !!callee && (callee.type === 'MemberExpression' || callee.type === 'OptionalMemberExpression')
          && (callee.object as Node).type === 'Identifier'
          && reactFactories.namespaces.has(String((callee.object as Node).name))
          && memberPropertyName(callee) === 'createElement'
      if (isCreateElement) {
        // A local component can create an imported package component without
        // JSX (for example React.createElement(lowercaseComponent)). Track the
        // element type and props values without treating ordinary hook or
        // resolver arguments as route components.
        for (const argument of ((node.arguments as Node[] | undefined) ?? []).slice(0, 2)) addExpressionBindings(argument)
      }
    }
    if (node.type === 'JSXElement') {
      const opening = node.openingElement as Node
      const name = opening.name as Node
      if (name.type === 'JSXIdentifier') bindings.add(String(name.name))
      else if (name.type === 'JSXMemberExpression') {
        const root = jsxMemberRootIdentifier(name)
        if (root) bindings.add(root)
      }
      for (const attribute of opening.attributes as Node[]) {
        if (attribute.type === 'JSXSpreadAttribute') addExpressionBindings(attribute.argument as Node | undefined)
        else {
          const value = attribute.value as Node | null | undefined
          if (value?.type === 'JSXExpressionContainer') addExpressionBindings(value.expression as Node | undefined)
        }
      }
      for (const child of node.children as Node[]) visit(child)
      return
    }
    if (node.type === 'JSXFragment') {
      for (const child of node.children as Node[]) visit(child)
      return
    }
    childNodes(node).forEach(visit)
  }
  visit(program)
  return bindings
}

/** Lowercase imported component values passed to local wrapper functions. */
function componentBindingsPassedToLocalCalls(program: Node): Set<string> {
  const callableBindings = new Set<string>()
  const callableAliases = new Map<string, Set<string>>()
  const addCallableAlias = (target: string, alias: string) => {
    const aliases = callableAliases.get(target) ?? new Set<string>()
    aliases.add(alias)
    callableAliases.set(target, aliases)
  }
  const functionValue = (node: Node | undefined) => !!node && [
    'ArrowFunctionExpression', 'FunctionExpression', 'ObjectMethod', 'ClassMethod', 'ClassPrivateMethod', 'MethodDefinition',
  ].includes(node.type)
  const staticKey = (node: Node | undefined) => node?.type === 'Identifier' ? String(node.name) : staticStringValue(node)
  const collectObjectCallables = (object: Node, owner: string) => {
    for (const property of (object.properties as Node[] | undefined) ?? []) {
      const key = staticKey(property.key as Node | undefined)
      if (!key) continue
      const path = `${owner}.${key}`
      const value = (property.type === 'RestElement' ? property.argument : property.value) as Node | undefined
      if (functionValue(property) || functionValue(value)) callableBindings.add(path)
      if (value?.type === 'ObjectExpression') collectObjectCallables(value, path)
    }
  }
  const collectClassCallables = (classNode: Node, owner: string) => {
    const body = classNode.body as Node | undefined
    for (const method of (body?.body as Node[] | undefined) ?? []) {
      if (!['ClassMethod', 'ClassPrivateMethod', 'MethodDefinition'].includes(method.type)) continue
      const key = staticKey(method.key as Node | undefined)
      if (key) callableBindings.add(method.static === true ? `${owner}.${key}` : `${owner}.prototype.${key}`)
    }
  }
  const collectCallables = (node: Node, parent?: Node) => {
    if (node.type === 'FunctionDeclaration' && isNode(node.id)) callableBindings.add(String((node.id as Node).name))
    if ((node.type === 'ClassDeclaration' || node.type === 'ClassExpression')) {
      const id = node.id as Node | undefined
      const owner = id?.type === 'Identifier'
        ? String(id.name)
        : parent?.type === 'VariableDeclarator' && (parent.id as Node | undefined)?.type === 'Identifier'
          ? String((parent.id as Node).name)
          : undefined
      if (owner) collectClassCallables(node, owner)
    }
    if (node.type === 'VariableDeclarator' && parent?.type === 'VariableDeclaration'
      && (node.id as Node).type === 'Identifier') {
      const value = unwrapTransparentExpression(node.init as Node | undefined)
      const name = String((node.id as Node).name)
      if (value?.type === 'ArrowFunctionExpression' || value?.type === 'FunctionExpression') callableBindings.add(name)
      else if (value?.type === 'Identifier' || value?.type === 'MemberExpression' || value?.type === 'OptionalMemberExpression') {
        const target = staticMemberPath(value)
        if (target) addCallableAlias(target, name)
      }
      if (value?.type === 'ObjectExpression') collectObjectCallables(value, name)
      if (value?.type === 'ClassExpression') collectClassCallables(value, name)
    }
    if (node.type === 'AssignmentExpression' && (node.left as Node | undefined)?.type === 'Identifier') {
      const target = staticMemberPath(node.right as Node | undefined)
      if (target) addCallableAlias(target, String((node.left as Node).name))
    }
    childNodes(node).forEach(child => collectCallables(child, node))
  }
  collectCallables(program)
  const callableQueue = [...callableBindings]
  for (let cursor = 0; cursor < callableQueue.length; cursor += 1) {
    for (const alias of callableAliases.get(callableQueue[cursor]) ?? []) {
      if (callableBindings.has(alias)) continue
      callableBindings.add(alias)
      callableQueue.push(alias)
    }
  }

  const bindings = new Set<string>()
  const visit = (node: Node, parent?: Node, field?: string, insideLocalCallArgument = false) => {
    if (node.type.startsWith('TS')) return
    if (node.type === 'Identifier' && insideLocalCallArgument) {
      const staticProperty = ((parent?.type === 'Property' || parent?.type === 'ObjectProperty') && field === 'key' && !parent.computed)
        || ((parent?.type === 'MemberExpression' || parent?.type === 'OptionalMemberExpression') && field === 'property' && !parent.computed)
      if (!staticProperty) bindings.add(String(node.name))
      return
    }
    const callee = (node.type === 'CallExpression' || node.type === 'OptionalCallExpression')
      ? unwrapTransparentExpression(node.callee as Node | undefined)
      : undefined
    const calleePath = staticMemberPath(callee)
    const localCall = calleePath !== undefined && callableBindings.has(calleePath)
    for (const [key, value] of Object.entries(node)) {
      if (key === 'parent') continue
      const captureArguments = insideLocalCallArgument || (localCall && key === 'arguments')
      if (Array.isArray(value)) value.filter(isNode).forEach(child => visit(child, node, key, captureArguments))
      else if (isNode(value)) visit(value, node, key, insideLocalCallArgument)
    }
  }
  visit(program)
  return bindings
}

function namespacesDestructuredIntoJSXBindings(program: Node, jsxBindings: Set<string>): Set<string> {
  const namespaceDependents = new Map<string, Set<string>>()
  const destructuredValues = new Set<string>()
  const addNamespaceAlias = (source: string, alias: string) => {
    const dependents = namespaceDependents.get(alias) ?? new Set<string>()
    dependents.add(source)
    namespaceDependents.set(alias, dependents)
  }
  const collectBindingNames = (pattern: Node, names: Set<string>) => {
    if (pattern.type === 'Identifier') names.add(String(pattern.name))
    else if (pattern.type === 'RestElement' || pattern.type === 'AssignmentPattern') {
      collectBindingNames((pattern.argument ?? pattern.left) as Node, names)
    } else if (pattern.type === 'ObjectPattern') {
      for (const property of pattern.properties as Node[]) {
        collectBindingNames((property.type === 'RestElement' ? property.argument : property.value) as Node, names)
      }
    } else if (pattern.type === 'ArrayPattern') {
      for (const element of pattern.elements as (Node | null)[]) if (element) collectBindingNames(element, names)
    }
  }
  const collect = (node: Node) => {
    if (node.type === 'VariableDeclarator' || node.type === 'AssignmentExpression') {
      const binding = (node.type === 'VariableDeclarator' ? node.id : node.left) as Node
      const value = unwrapTransparentExpression((node.type === 'VariableDeclarator' ? node.init : node.right) as Node | undefined)
      if (binding.type === 'Identifier' && value?.type === 'Identifier') {
        addNamespaceAlias(String(value.name), String(binding.name))
      }
      if (binding.type === 'ObjectPattern' && value?.type === 'Identifier') {
        const names = new Set<string>()
        collectBindingNames(binding, names)
        if ([...names].some(name => jsxBindings.has(name))) destructuredValues.add(String(value.name))
      }
    }
    childNodes(node).forEach(collect)
  }
  collect(program)

  const required = new Set(destructuredValues)
  const queue = [...required]
  for (let cursor = 0; cursor < queue.length; cursor += 1) {
    for (const source of namespaceDependents.get(queue[cursor]) ?? []) {
      if (required.has(source)) continue
      required.add(source)
      queue.push(source)
    }
  }
  return required
}

type ComponentOrigin = {
  source: string
  api?: 'Route' | 'Routes' | '*'
  /** Canonical local declaration name for a named component export. */
  componentName?: string
  /** Whether this component declares a `<Routes>` table in its source module. */
  routeTable?: boolean
  /** Its local render tree contains values the route inventory cannot inspect. */
  unreadable?: boolean
}

/** Collects local component identities and unsafe render trees for one module. */
function localComponentReadability(
  program: Node,
  file: string,
  runtimeModuleLoads: RuntimeModuleLoad[],
  opaqueComponentBindings: Set<string>,
  isLocalSpecifier: (specifier: string) => boolean,
) {
  const reactNamespaces = new Set<string>()
  const createElementImports = new Set<string>()
  const lazyImports = new Set<string>()
  const routers = { Route: new Set<string>(), Routes: new Set<string>() }
  const knownRouterComponents = new Set<string>()
  for (const statement of program.body as Node[]) {
    if (statement.type !== 'ImportDeclaration') continue
    const source = String((statement.source as Node).value)
    for (const specifier of statement.specifiers as Node[]) {
      const localName = String((specifier.local as Node).name)
      const importedName = specifier.type === 'ImportSpecifier'
        ? String((specifier.imported as Node).name)
        : undefined
      if (source === 'react' || source === 'react/jsx-runtime') {
        if (source === 'react' && importedName === 'createElement') createElementImports.add(localName)
        if (source === 'react' && importedName === 'lazy') lazyImports.add(localName)
        if (specifier.type !== 'ImportSpecifier') reactNamespaces.add(localName)
      }
      if (!routerModules.has(source) || !importedName) continue
      if (importedName === 'Route' || importedName === 'Routes') routers[importedName].add(localName)
      else if (!unreadRouterAPIs.has(importedName)) knownRouterComponents.add(localName)
    }
  }
  const factories = reactCreateElementAliases(program, createElementImports, reactNamespaces)
  const lazies = reactLazyAliases(program, lazyImports, factories.namespaces)
  const opaqueRuntimeBindings = opaqueRuntimeModuleBindings(program, runtimeModuleLoads, isLocalSpecifier)
  const dynamicComponents = dynamicLazyComponentImports(
    program,
    lazies,
    factories.namespaces,
    isLocalSpecifier,
    opaqueRuntimeBindings,
    file,
  )
  const componentBindings = staticallyReadableComponentBindings(
    program,
    reactNamespaces,
    dynamicComponents.readableCalls,
    opaqueComponentBindings,
    factories,
    routers,
    knownRouterComponents,
  )
  const routeTableNames = new Set<string>()
  const visitRoutes = (node: Node, current: string) => {
    let owner = current
    if ((node.type === 'FunctionDeclaration' || node.type === 'ClassDeclaration') && isNode(node.id)) {
      owner = String((node.id as Node).name)
    } else if (node.type === 'VariableDeclarator' && (node.id as Node).type === 'Identifier'
      && /^[A-Z]/.test(String((node.id as Node).name))) {
      owner = String((node.id as Node).name)
    }
    if (node.type === 'JSXElement' && routers.Routes.has(jsxName(node) ?? '')) routeTableNames.add(owner)
    childNodes(node).forEach(child => visitRoutes(child, owner))
  }
  visitRoutes(program, '')
  return { ...componentBindings, routeTableNames }
}

/** Carries opaque package-component and router-API provenance through local modules. */
function localComponentOrigins(sources: SourceFile[], configRoot: string): Map<string, Map<string, ComponentOrigin>> {
  const moduleResolver = localModuleResolver(configRoot)
  const programs = sources.map(source => {
    const parsed = parseSync(source.file, source.code, { lang: source.file.endsWith('.tsx') ? 'tsx' : 'ts' })
    if (parsed.errors.length) throw new Error(`${source.file}: ${parsed.errors.map(error => error.message).join('; ')}`)
    const program = parsed.program as unknown as Node
    const jsxBindings = componentBindingsUsedInJSX(program)
    const runtimeModuleLoads = rejectUninspectableRouterLoads(program, source.file)
    return {
      ...source,
      absolutePath: resolve(repositoryRoot, source.file),
      program,
      runtimeModuleLoads,
      jsxBindings,
      jsxNamespaceBindings: namespacesDestructuredIntoJSXBindings(program, jsxBindings),
      callBindings: componentBindingsPassedToLocalCalls(program),
      opaqueRuntimeModuleLoads: new Map(runtimeModuleLoads
        .filter(load => isOpaqueExternalPackage(load.specifier, moduleResolver.isLocalSpecifier))
        .map(load => [load.node, load.specifier] as const)),
    }
  })
  const byPath = new Map(programs.map(source => [source.absolutePath, source]))
  const exportsByPath = new Map<string, Map<string, ComponentOrigin>>()
  const isOpaquePackage = (specifier: string) => isOpaqueExternalPackage(specifier, moduleResolver.isLocalSpecifier)
  const nameOf = (node: Node | undefined) => node?.type === 'Identifier' ? String(node.name) : undefined
  const maxExportPropagationSteps = 50_000
  let exportPropagationSteps = 0
  const addExport = (target: Map<string, ComponentOrigin>, name: string, origin: ComponentOrigin | undefined) => {
    if (!origin) return
    exportPropagationSteps += 1
    if (exportPropagationSteps > maxExportPropagationSteps) {
      throw new Error(`local component export provenance exceeded ${maxExportPropagationSteps} propagation steps; the console route inventory cannot inspect this module graph`)
    }
    target.set(name, origin)
  }
  const importersByPath = new Map<string, Set<string>>()
  for (const source of programs) {
    for (const statement of source.program.body as Node[]) {
      if (statement.type !== 'ImportDeclaration' && statement.type !== 'ExportNamedDeclaration' && statement.type !== 'ExportAllDeclaration') continue
      const sourceNode = statement.source as Node | null | undefined
      if (!sourceNode || !moduleResolver.isLocalSpecifier(String(sourceNode.value))) continue
      const targetPath = moduleResolver.resolve(source.absolutePath, String(sourceNode.value))
      if (!targetPath || !byPath.has(targetPath)) continue
      const importers = importersByPath.get(targetPath) ?? new Set<string>()
      importers.add(source.absolutePath)
      importersByPath.set(targetPath, importers)
    }
  }

  const worklist = programs.map(source => source.absolutePath)
  const queued = new Set(worklist)
  const enqueue = (path: string) => {
    if (queued.has(path)) return
    queued.add(path)
    worklist.push(path)
  }
  for (let cursor = 0; cursor < worklist.length; cursor += 1) {
      const path = worklist[cursor]
      queued.delete(path)
      const source = byPath.get(path)!
      let changed = false
      const importedOrigins: Map<string, ComponentOrigin> = new Map(opaqueRuntimeModuleBindings(source.program, source.runtimeModuleLoads, moduleResolver.isLocalSpecifier))
      const jsxBindings = source.jsxBindings
      const callBindings = source.callBindings
      const jsxNamespaceBindings = source.jsxNamespaceBindings
      const exportedValueBindings = runtimeExportedValueBindings(source.program)
      for (const statement of source.program.body as Node[]) {
        const isImport = statement.type === 'ImportDeclaration'
        const isReexport = statement.type === 'ExportNamedDeclaration' || statement.type === 'ExportAllDeclaration'
        if ((!isImport && !isReexport) || (isImport && statement.importKind === 'type')
          || (!isImport && statement.exportKind === 'type')) continue
        const sourceNode = statement.source as Node | null | undefined
        if (!sourceNode) continue
        const moduleSource = String(sourceNode.value)
        if (isOpaquePackage(moduleSource)) {
          if (isImport) {
            for (const specifier of statement.specifiers as Node[]) {
              if (specifier.importKind === 'type') continue
              const localName = String((specifier.local as Node).name)
              const importedName = specifier.type === 'ImportSpecifier'
                ? nameOf(specifier.imported as Node)
                : undefined
              const api = importedName === 'Route' || importedName === 'Routes'
                ? importedName
                : undefined
              if (specifier.type === 'ImportNamespaceSpecifier'
                || api
                || /^[A-Z]/.test(localName) || jsxBindings.has(localName) || jsxNamespaceBindings.has(localName)
                || callBindings.has(localName) || exportedValueBindings.has(localName)) {
                importedOrigins.set(localName, { source: moduleSource, ...(api ? { api } : {}) })
              }
            }
          }
          continue
        }
        if (!moduleResolver.isLocalSpecifier(moduleSource)) continue
        const modulePath = moduleResolver.resolve(source.absolutePath, moduleSource)
        if (!modulePath || !byPath.has(modulePath)) continue
        const targetExports = exportsByPath.get(modulePath)
        if (!targetExports) continue
        if (isImport) {
          for (const specifier of statement.specifiers as Node[]) {
            if (specifier.importKind === 'type') continue
            const localName = String((specifier.local as Node).name)
            if (specifier.type === 'ImportNamespaceSpecifier') {
              const unknownExports = targetExports.get('*')
              if (unknownExports) {
                importedOrigins.set(localName, unknownExports)
              } else {
                for (const [exportName, origin] of targetExports) {
                  importedOrigins.set(`@member:${localName}.${exportName}`, origin)
                }
              }
              continue
            }
            const importedName = specifier.type === 'ImportSpecifier' ? nameOf(specifier.imported as Node) : 'default'
            const origin = importedName
              ? targetExports.get(importedName) ?? (importedName === 'default' ? undefined : targetExports.get('*'))
              : undefined
            if (origin) importedOrigins.set(localName, origin)
          }
        }
      }

      const aliases = importedComponentAliases(source.program, importedOrigins)
      const componentReadability = localComponentReadability(
        source.program,
        source.file,
        source.runtimeModuleLoads,
        new Set([...aliases].filter(([, origin]) => !origin.componentName || origin.unreadable).map(([name]) => name)),
        moduleResolver.isLocalSpecifier,
      )
      const exportOrigin = (localName: string): ComponentOrigin | undefined => {
        const imported = aliases.get(localName)
        if (imported) return imported
        if (!/^[A-Z]/.test(localName)) return undefined
        return {
          source: source.file,
          componentName: localName,
          routeTable: componentReadability.routeTableNames.has(localName),
          unreadable: componentReadability.routeTableNames.has(localName)
            && componentReadability.unreadableComponents.has(localName),
        }
      }
      const nextExports = new Map<string, ComponentOrigin>()
      for (const statement of source.program.body as Node[]) {
        if (statement.type === 'ExportDefaultDeclaration') {
          const declaration = statement.declaration as Node
          const localName = nameOf(declaration.type === 'FunctionDeclaration' || declaration.type === 'ClassDeclaration'
            ? declaration.id as Node | undefined
            : declaration)
          addExport(nextExports, 'default', localName ? exportOrigin(localName) : undefined)
          if (!localName) {
            for (const rendered of renderedImportedComponents(
              declaration, aliases, source.file, new Set(), new Set(), new Map(), true, source.opaqueRuntimeModuleLoads,
            )) {
              addExport(nextExports, 'default', rendered.source ? { source: rendered.source } : aliases.get(rendered.component))
            }
          }
          continue
        }
        if (statement.type !== 'ExportNamedDeclaration' && statement.type !== 'ExportAllDeclaration') continue
        const moduleSource = statement.source as Node | null | undefined
        if (moduleSource) {
          const specifier = String(moduleSource.value)
          if (moduleResolver.isLocalSpecifier(specifier)) {
            const modulePath = moduleResolver.resolve(source.absolutePath, specifier)
            const targetExports = modulePath ? exportsByPath.get(modulePath) : undefined
            if (targetExports && statement.type === 'ExportAllDeclaration') {
              for (const [name, origin] of targetExports) addExport(nextExports, name, origin)
            } else if (targetExports) {
              for (const exportSpecifier of statement.specifiers as Node[]) {
                const importedName = nameOf(exportSpecifier.local as Node)
                const exportedName = nameOf(exportSpecifier.exported as Node)
                if (importedName && exportedName) addExport(nextExports, exportedName, targetExports.get(importedName))
              }
            }
          } else if (isOpaquePackage(specifier) && statement.type === 'ExportNamedDeclaration') {
            for (const exportSpecifier of statement.specifiers as Node[]) {
              const importedName = nameOf(exportSpecifier.local as Node)
              const exportedName = nameOf(exportSpecifier.exported as Node)
              const api = importedName === 'Route' || importedName === 'Routes' ? importedName : undefined
              if (exportedName) addExport(nextExports, exportedName, { source: specifier, ...(api ? { api } : {}) })
            }
          } else if (isOpaquePackage(specifier) && statement.type === 'ExportAllDeclaration') {
            // An external export-star exposes unknown names. Mark named imports
            // from a local barrel as opaque instead of pretending its export
            // inventory is complete.
            addExport(nextExports, '*', { source: specifier, api: '*' })
          }
          continue
        }

        const declaration = statement.declaration as Node | undefined
        if (declaration) {
          if ((declaration.type === 'FunctionDeclaration' || declaration.type === 'ClassDeclaration') && isNode(declaration.id)) {
            const name = String((declaration.id as Node).name)
            addExport(nextExports, name, exportOrigin(name))
          } else if (declaration.type === 'VariableDeclaration') {
            for (const declarator of declaration.declarations as Node[]) {
              const name = nameOf(declarator.id as Node)
              if (name) addExport(nextExports, name, exportOrigin(name))
            }
          }
        }
        for (const specifier of (statement.specifiers as Node[] | undefined) ?? []) {
          const localName = nameOf(specifier.local as Node)
          const exportedName = nameOf(specifier.exported as Node)
          if (localName && exportedName) addExport(nextExports, exportedName, exportOrigin(localName))
        }
      }

      const current = exportsByPath.get(source.absolutePath) ?? new Map<string, ComponentOrigin>()
      for (const [name, origin] of nextExports) {
        if (current.get(name)?.source === origin.source
          && current.get(name)?.api === origin.api
          && current.get(name)?.componentName === origin.componentName
          && current.get(name)?.routeTable === origin.routeTable
          && current.get(name)?.unreadable === origin.unreadable) continue
        current.set(name, origin)
        changed = true
      }
      exportsByPath.set(source.absolutePath, current)
      if (changed) {
        for (const importer of importersByPath.get(source.absolutePath) ?? []) enqueue(importer)
      }
  }
  return exportsByPath
}

/** Finds Route/Routes values loaded from unknown runtime modules, including aliases. */
function opaqueRuntimeRouterAPIImports(
  program: Node,
  moduleLoads: RuntimeModuleLoad[],
  runtimeBindings: Map<string, { source: string }>,
  isLocalSpecifier: (specifier: string) => boolean,
): { bindings: Map<string, { source: string }>; namespaces: Map<string, { source: string }> } {
  const loads = new Map(moduleLoads
    .filter(load => isOpaqueExternalPackage(load.specifier, isLocalSpecifier))
    .map(load => [load.node, load.specifier] as const))
  const sourceOf = (node: Node | undefined): string | undefined => {
    if (!node) return undefined
    const expression = unwrapTransparentExpression(node)
    if (!expression) return undefined
    if (expression.type === 'Identifier') return runtimeBindings.get(String(expression.name))?.source
    if (expression.type === 'MemberExpression' || expression.type === 'OptionalMemberExpression') {
      const path = staticMemberPath(expression)
      const pathSource = path ? runtimeBindings.get(`@member:${path}`)?.source : undefined
      if (pathSource) return pathSource
      const root = memberRootIdentifier(expression)
      const rootSource = root ? runtimeBindings.get(`@member-root:${root}`)?.source : undefined
      return rootSource ?? sourceOf(expression.object as Node | undefined)
    }
    const found = new Set<string>()
    const visit = (current: Node) => {
      const loaded = loads.get(current)
      if (loaded) found.add(loaded)
      for (const child of childNodes(current)) visit(child)
    }
    visit(expression)
    return found.size === 1 ? [...found][0] : undefined
  }
  const propertyName = (property: Node, computed: boolean) => computed
    ? staticStringValue(property)
    : property.type === 'Identifier' ? String(property.name) : staticStringValue(property)
  const bindingName = (node: Node | undefined): string | undefined => {
    if (node?.type === 'Identifier') return String(node.name)
    if (node?.type === 'AssignmentPattern') return bindingName(node.left as Node | undefined)
    return undefined
  }
  const bindings = new Map<string, { source: string }>()
  const namespaces = new Map<string, { source: string }>()
  const collect = (node: Node) => {
    const binding = node.type === 'VariableDeclarator'
      ? node.id as Node
      : node.type === 'AssignmentExpression' ? node.left as Node : undefined
    const value = node.type === 'VariableDeclarator'
      ? node.init as Node | undefined
      : node.type === 'AssignmentExpression' ? node.right as Node | undefined : undefined
    const source = sourceOf(value)
    if (source && binding?.type === 'Identifier') namespaces.set(String(binding.name), { source })
    if (source && binding?.type === 'ObjectPattern') {
      for (const property of binding.properties as Node[]) {
        if (property.type !== 'Property' && property.type !== 'ObjectProperty') continue
        const api = propertyName(property.key as Node, property.computed === true)
        const name = bindingName(property.value as Node | undefined)
        if ((api === 'Route' || api === 'Routes') && name) bindings.set(name, { source })
      }
    }
    childNodes(node).forEach(collect)
  }
  collect(program)
  return { bindings, namespaces }
}

/**
 * Reads every `<Routes>` of the given sources, named by the component that
 * renders it, with its `<Route>` tree.
 */
function extractRouters(sources: SourceFile[], configRoot = repositoryRoot): SourceRouter[] {
  const routers: SourceRouter[] = []
  const sourcePaths = new Set(sources.map(source => resolve(repositoryRoot, source.file)))
  const moduleResolver = localModuleResolver(configRoot)
  const orderedSources = [...sources].sort((left, right) => left.file < right.file ? -1 : left.file > right.file ? 1 : 0)
  const crossModuleComponentOrigins = localComponentOrigins(orderedSources, configRoot)
  for (const { file, code } of orderedSources) {
    const parsed = parseSync(file, code, { lang: file.endsWith('.tsx') ? 'tsx' : 'ts' })
    if (parsed.errors.length) throw new Error(`${file}: ${parsed.errors.map(error => error.message).join('; ')}`)
    const program = parsed.program as unknown as Node
    const runtimeModuleLoads = rejectUninspectableRouterLoads(program, file)
    const opaqueRuntimeModuleLoads = new Map(runtimeModuleLoads
      .filter(load => isOpaqueExternalPackage(load.specifier, moduleResolver.isLocalSpecifier))
      .map(load => [load.node, load.specifier] as const))

    const local = { Route: new Set<string>(), Routes: new Set<string>() }
    const knownRouterComponents = new Set<string>()
    const unresolvedRouterImports = new Map<string, { api: 'Route' | 'Routes'; source: string }>()
    const unresolvedRouterBindings = new Map<string, { source: string }>()
    const unresolvedLocalComponentImports = new Map<string, { source: string }>()
    const localComponentImports = new Map<string, { source: string }>()
    const localComponentNamespaceImports = new Set<string>()
    const unreadableLocalComponentImports = new Map<string, { source: string }>()
    const uninspectableExternalComponentImports = new Map<string, { source: string }>()
    const reactFragments = new Set<string>()
    const reactNamespaces = new Set<string>()
    const reactCreateElementImports = new Set<string>()
    const reactLazyImports = new Set<string>()
    for (const statement of program.body as Node[]) {
      if (statement.type !== 'ImportDeclaration') continue
      const source = String((statement.source as Node).value)
      if (source === 'react' || source === 'react/jsx-runtime') {
        for (const specifier of statement.specifiers as Node[]) {
          const localName = String((specifier.local as Node).name)
          if (specifier.type === 'ImportSpecifier') {
            if (String((specifier.imported as Node).name) === 'Fragment') reactFragments.add(localName)
            if (source === 'react' && String((specifier.imported as Node).name) === 'createElement') reactCreateElementImports.add(localName)
            if (source === 'react' && String((specifier.imported as Node).name) === 'lazy') reactLazyImports.add(localName)
          } else {
            reactNamespaces.add(localName)
          }
        }
      }
      if (!routerModules.has(source)) {
        for (const specifier of statement.specifiers as Node[]) {
          const localName = String((specifier.local as Node).name)
          const imported = specifier.type === 'ImportSpecifier' ? String((specifier.imported as Node).name) : localName
          const api = imported === 'Route' || imported === 'Routes'
            ? imported
            : localName === 'Route' || localName === 'Routes'
              ? localName
              : undefined
          if (api) {
            unresolvedRouterImports.set(localName, { api, source })
            unresolvedRouterBindings.set(localName, { source })
          } else if ((specifier.type === 'ImportNamespaceSpecifier' || specifier.type === 'ImportDefaultSpecifier')
            && source !== 'react' && source !== 'react/jsx-runtime' && source !== 'lucide-react'
            && !moduleResolver.isLocalSpecifier(source)) {
            unresolvedRouterBindings.set(localName, { source })
          }
        }
      }
      if (moduleResolver.isLocalSpecifier(source)) {
        const modulePath = moduleResolver.resolve(resolve(repositoryRoot, file), source)
        if (!modulePath || !sourcePaths.has(resolve(modulePath))) {
          for (const specifier of statement.specifiers as Node[]) {
            if (statement.importKind === 'type' || specifier.importKind === 'type') continue
            const localName = String((specifier.local as Node).name)
            unresolvedLocalComponentImports.set(localName, { source })
          }
        } else {
          const moduleOrigins = crossModuleComponentOrigins.get(resolve(modulePath))
          for (const specifier of statement.specifiers as Node[]) {
            if (statement.importKind === 'type' || specifier.importKind === 'type') continue
            const localName = String((specifier.local as Node).name)
            if (specifier.type === 'ImportNamespaceSpecifier') {
              const unknownExports = moduleOrigins?.get('*')
              let hasOpaqueExports = !!unknownExports
              if (unknownExports) {
                uninspectableExternalComponentImports.set(localName, unknownExports)
                if (unknownExports.api === '*') unresolvedRouterBindings.set(`@member-root:${localName}`, unknownExports)
              } else {
                for (const [exportName, origin] of moduleOrigins ?? []) {
                  hasOpaqueExports = true
                  uninspectableExternalComponentImports.set(`@member:${localName}.${exportName}`, origin)
                  if (origin.api) unresolvedRouterBindings.set(`@member:${localName}.${exportName}`, { source: origin.source })
                }
              }
              // Namespace members are intentionally unsupported: preserve a
              // sentinel even when the module also exposes opaque exports, so
              // an unrelated opaque export cannot make a local member vanish
              // from the wildcard guard.
              localComponentImports.set(localName, { source: `${localName}.*` })
              localComponentNamespaceImports.add(localName)
              continue
            }
            const importedName = specifier.type === 'ImportSpecifier' ? String((specifier.imported as Node).name) : 'default'
            const origin = moduleOrigins?.get(importedName)
              ?? (specifier.type === 'ImportSpecifier' ? moduleOrigins?.get('*') : undefined)
            if (origin?.componentName) {
              // Only attach a local component to a same-named route table
              // when that table is declared by the imported module. Otherwise
              // an unrelated table from another module could make an opaque
              // component look inspectable.
              localComponentImports.set(localName, {
                source: origin.routeTable
                  ? origin.componentName
                  : `@unmodeled-local:${source} export ${importedName}`,
              })
              if (origin.routeTable && origin.unreadable) {
                unreadableLocalComponentImports.set(localName, {
                  source: `local module ${source} export ${importedName}`,
                })
              }
            } else if (origin) {
              uninspectableExternalComponentImports.set(localName, origin)
              if (origin.api) {
                unresolvedRouterBindings.set(localName, { source: origin.source })
                if (origin.api === 'Route' || origin.api === 'Routes') {
                  unresolvedRouterImports.set(localName, { api: origin.api, source: origin.source })
                }
              }
            } else {
              localComponentImports.set(localName, {
                source: specifier.type === 'ImportSpecifier' ? importedName : localName,
              })
            }
          }
        }
      } else if (
        source !== 'react'
        && source !== 'react/jsx-runtime'
        // lucide-react exports presentation-only SVG icons and cannot own a route tree.
        && source !== 'lucide-react'
        && ![...routerModules].some(module => source === module || source.startsWith(`${module}/`))) {
        for (const specifier of statement.specifiers as Node[]) {
          if (statement.importKind === 'type' || specifier.importKind === 'type') continue
          const localName = String((specifier.local as Node).name)
          uninspectableExternalComponentImports.set(localName, { source })
        }
      }
      if (!routerModules.has(source)) continue
      for (const specifier of statement.specifiers as Node[]) {
        if (specifier.type !== 'ImportSpecifier') throw new Error(`${file} uses ${specifier.type} from a router module; the console route inventory check requires named router imports so it can read every route`)
        const imported = String((specifier.imported as Node).name)
        const localName = String((specifier.local as Node).name)
        if (!unreadRouterAPIs.has(imported)) knownRouterComponents.add(localName)
        if (imported === 'Route' || imported === 'Routes') local[imported].add(localName)
        if (unreadRouterAPIs.has(imported)) throw new Error(`${file} imports ${imported}; the console route inventory check reads only <Routes> and <Route> elements, so declare routes as JSX or teach src/console-route-inventory.test.ts the new API`)
      }
    }

    const reactFactories = reactCreateElementAliases(program, reactCreateElementImports, reactNamespaces)
    const reactLazies = reactLazyAliases(program, reactLazyImports, reactFactories.namespaces)
    const runtimeOpaqueModuleBindings = opaqueRuntimeModuleBindings(program, runtimeModuleLoads, moduleResolver.isLocalSpecifier)
    const runtimeRouterAPIs = opaqueRuntimeRouterAPIImports(
      program,
      runtimeModuleLoads,
      runtimeOpaqueModuleBindings,
      moduleResolver.isLocalSpecifier,
    )
    for (const [binding, origin] of runtimeRouterAPIs.bindings) unresolvedRouterBindings.set(binding, origin)
    const runtimeRouterNamespaces = importedComponentAliases(program, runtimeRouterAPIs.namespaces)
    for (const [binding, origin] of runtimeRouterNamespaces) {
      unresolvedRouterBindings.set(`@member:${binding}.Route`, origin)
      unresolvedRouterBindings.set(`@member:${binding}.Routes`, origin)
    }
    const dynamicComponents = dynamicLazyComponentImports(program, reactLazies, reactFactories.namespaces, moduleResolver.isLocalSpecifier, runtimeOpaqueModuleBindings, file)
    const opaqueComponentImports = new Map(uninspectableExternalComponentImports)
    for (const [binding, origin] of unreadableLocalComponentImports) {
      opaqueComponentImports.set(binding, origin)
    }
    for (const [binding, origin] of runtimeOpaqueModuleBindings) {
      if (!opaqueComponentImports.has(binding)) opaqueComponentImports.set(binding, origin)
    }
    for (const [binding, origin] of dynamicComponents.bindings) {
      if (!opaqueComponentImports.has(binding)) opaqueComponentImports.set(binding, origin)
    }
    const importedExternalComponentBindings = importedComponentAliases(program, opaqueComponentImports)
    const readableComponentBindings = staticallyReadableComponentBindings(
      program,
      reactNamespaces,
      dynamicComponents.readableCalls,
      new Set(importedExternalComponentBindings.keys()),
      reactFactories,
      local,
      knownRouterComponents,
    )
    for (const binding of importedExternalComponentBindings.keys()) readableComponentBindings.bindings.add(binding)

    // An unresolved local import can carry Route or Routes under any local
    // alias, including aliases created by destructuring or object properties.
    // Reject forwarding that value before the no-router-import fast path can
    // skip the file and leave its JSX outside the inventory.
    const forwardedUnresolvedImport = (node: Node | undefined): { source: string } | undefined => {
      if (!node) return undefined
      const expression = unwrapTransparentExpression(node)
      if (expression !== node) return forwardedUnresolvedImport(expression)
      if (node.type === 'VariableDeclarator') return forwardedUnresolvedImport(node.init as Node | undefined)
      if (node.type === 'Identifier') return unresolvedLocalComponentImports.get(String(node.name))
      if (node.type.startsWith('TS')) return undefined
      if (node.type === 'FunctionDeclaration' || node.type === 'FunctionExpression' || node.type === 'ArrowFunctionExpression'
        || node.type === 'ObjectMethod' || node.type === 'ClassMethod' || node.type === 'MethodDefinition') return undefined
      if (node.type === 'Property' || node.type === 'ObjectProperty') {
        return forwardedUnresolvedImport(node.value as Node | undefined)
          ?? (node.computed ? forwardedUnresolvedImport(node.key as Node | undefined) : undefined)
      }
      if (node.type === 'ClassProperty' || node.type === 'PropertyDefinition') {
        return forwardedUnresolvedImport(node.value as Node | undefined)
          ?? (node.computed ? forwardedUnresolvedImport(node.key as Node | undefined) : undefined)
      }
      if (node.type === 'MemberExpression' || node.type === 'OptionalMemberExpression') {
        return forwardedUnresolvedImport(node.object as Node | undefined)
          ?? (node.computed ? forwardedUnresolvedImport(node.property as Node | undefined) : undefined)
      }
      return childNodes(node).map(forwardedUnresolvedImport).find(Boolean)
    }
    const rejectUnresolvedLocalImportForwarding = (node: Node) => {
      const forwardedValues: (Node | undefined)[] = []
      if (node.type === 'VariableDeclarator') forwardedValues.push(node.init as Node | undefined)
      if (node.type === 'AssignmentExpression') forwardedValues.push(node.right as Node | undefined)
      if (node.type === 'AssignmentPattern') forwardedValues.push(node.right as Node | undefined)
      if (node.type === 'ArrowFunctionExpression' && (node.body as Node | undefined)?.type !== 'BlockStatement') {
        forwardedValues.push(node.body as Node | undefined)
      }
      if (node.type === 'ReturnStatement' || node.type === 'ExportDefaultDeclaration') {
        forwardedValues.push((node.argument ?? node.declaration) as Node | undefined)
      }
      if (node.type === 'CallExpression' || node.type === 'OptionalCallExpression') {
        forwardedValues.push(node.callee as Node | undefined, ...((node.arguments as Node[] | undefined) ?? []))
      }
      if (node.type === 'JSXAttribute') forwardedValues.push(node.value as Node | undefined)
      if (node.type === 'JSXSpreadAttribute') forwardedValues.push(node.argument as Node | undefined)
      if (node.type === 'JSXExpressionContainer') forwardedValues.push(node.expression as Node | undefined)
      for (const value of forwardedValues) {
        const forwarded = forwardedUnresolvedImport(value)
        if (forwarded) {
          throw new Error(`${file} forwards values from unresolved local module ${forwarded.source}; the console route inventory cannot rule out router APIs`)
        }
      }
      childNodes(node).forEach(rejectUnresolvedLocalImportForwarding)
    }
    rejectUnresolvedLocalImportForwarding(program)

    const rejectRouterAPIAliases = (node: Node) => {
      if (node.type === 'VariableDeclarator') {
        const api = referencedRouterAPI(node.init as Node | undefined, local)
        if (api) {
          const id = node.id as Node
          const alias = id.type === 'Identifier' ? String(id.name) : 'a local binding'
          throw new Error(`${file} aliases imported ${api} as ${alias}; the console route inventory check requires directly named JSX router APIs`)
        }
      }
      if (node.type === 'AssignmentExpression') {
        const api = referencedRouterAPI(node.right as Node | undefined, local)
        if (api) throw new Error(`${file} assigns imported ${api} to a local alias; the console route inventory check requires directly named JSX router APIs`)
      }
      childNodes(node).forEach(rejectRouterAPIAliases)
    }
    rejectRouterAPIAliases(program)

    const importedRouterAPI = (name: string) => local.Route.has(name) ? 'Route' : local.Routes.has(name) ? 'Routes' : undefined
    for (const statement of program.body as Node[]) {
      if (statement.type !== 'ExportNamedDeclaration' && statement.type !== 'ExportAllDeclaration') continue
      const source = statement.source as Node | null | undefined
      if (source && routerModules.has(String(source.value))) throw new Error(`${file} re-exports router APIs from ${String(source.value)}; the console route inventory check requires routes to be declared through named JSX imports`)
      if (source && moduleResolver.isLocalSpecifier(String(source.value))) {
        const specifier = String(source.value)
        const modulePath = moduleResolver.resolve(resolve(repositoryRoot, file), specifier)
        const included = modulePath && sourcePaths.has(resolve(modulePath))
        const specifiers = (statement.specifiers as Node[] | undefined) ?? []
        const hasRuntimeExports = statement.exportKind !== 'type'
          && (statement.type === 'ExportAllDeclaration' || specifiers.some(specifier => specifier.exportKind !== 'type'))
        if (hasRuntimeExports && !included) {
          throw new Error(`${file} re-exports from unreadable local module ${specifier}; the console route inventory cannot rule out router APIs`)
        }
      }
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
    for (const [localName, { api, source }] of unresolvedRouterImports) {
      const usesImportedComponent = (node: Node): boolean => jsxName(node) === localName || childNodes(node).some(usesImportedComponent)
      if (usesImportedComponent(program)) {
        throw new Error(`${file} imports ${api} from ${source} and uses it as JSX; the console route inventory cannot resolve local router API re-exports`)
      }
    }
    for (const [localName, { source }] of unresolvedLocalComponentImports) {
      const usesImportedComponent = (node: Node): boolean => {
        if (jsxName(node) === localName) return true
        if (node.type === 'JSXElement') {
          const name = (node.openingElement as Node).name as Node
          if (name.type === 'JSXMemberExpression' && jsxMemberRootIdentifier(name) === localName) return true
        }
        return childNodes(node).some(usesImportedComponent)
      }
      if (usesImportedComponent(program)) {
        throw new Error(`${file} uses JSX component ${localName} from unresolved local module ${source}; the console route inventory requires a statically readable local TypeScript module`)
      }
    }
    const unresolvedRouterAliases = importedComponentAliases(program, unresolvedRouterBindings)
    const uninspectableRouterTag = (node: Node): string | undefined => {
      if (node.type === 'JSXElement') {
        const name = (node.openingElement as Node).name as Node
        if (name.type === 'JSXIdentifier') {
          const alias = String(name.name)
          if (unresolvedRouterAliases.has(alias)) return alias
        }
        if (name.type === 'JSXMemberExpression') {
          const path = jsxMemberStaticPath(name)
          const root = jsxMemberRootIdentifier(name)
          if (path && unresolvedRouterAliases.has(`@member:${path}`)) return `@member:${path}`
          if (root && unresolvedRouterAliases.has(`@member-root:${root}`)) return `@member-root:${root}`
        }
      }
      for (const child of childNodes(node)) {
        const alias = uninspectableRouterTag(child)
        if (alias) return alias
      }
      return undefined
    }
    const unresolvedTag = uninspectableRouterTag(program)
    const unresolvedSource = unresolvedTag ? unresolvedRouterAliases.get(unresolvedTag)?.source : undefined
    if (unresolvedTag && unresolvedSource) {
      throw new Error(`${file} uses <${unresolvedTag}> from unresolved router import ${unresolvedSource}; the console route inventory cannot resolve aliased or destructured router bindings`)
    }
    const packageMapJSXUse = (node: Node, binding: string): boolean => {
      if (node.type === 'JSXElement') {
        const tag = (node.openingElement as Node).name as Node
        if ((tag.type === 'JSXIdentifier' && String(tag.name) === binding)
          || (tag.type === 'JSXMemberExpression' && jsxMemberRootIdentifier(tag) === binding)) return true
      }
      return childNodes(node).some(child => packageMapJSXUse(child, binding))
    }
    const packageImportMapBindings = importedComponentAliases(program,
      new Map([...uninspectableExternalComponentImports].filter(([, origin]) => origin.source.startsWith('#'))),
    )
    for (const [binding, origin] of packageImportMapBindings) {
      if (origin.source.startsWith('#') && packageMapJSXUse(program, binding)) {
        throw new Error(`${file} uses JSX component ${binding} from package import-map specifier ${origin.source}; the console route inventory cannot resolve package.json imports mappings`)
      }
    }
    const localComponentAliases = localComponentValueAliases(program, localComponentImports, localComponentNamespaceImports)
    if (!local.Route.size && !local.Routes.size) continue

    let routeElements = 0
    let collectedRoutes = 0
    const rejectUninspectableRouteChild = (node: Node, where: string): never => {
      throw new Error(`${file}: <Routes> in ${where} contains an unsupported non-JSX child (${node.type}); the console route inventory can only audit JSX <Route> elements`)
    }
    const isReactFragment = (node: Node) => {
      if (node.type === 'JSXFragment') return true
      if (node.type !== 'JSXElement') return false
      const name = (node.openingElement as Node).name as Node
      if (name.type === 'JSXIdentifier') return reactFragments.has(String(name.name))
      if (name.type !== 'JSXMemberExpression') return false
      const object = name.object as Node
      const property = name.property as Node
      return object.type === 'JSXIdentifier' && reactNamespaces.has(String(object.name)) && property.type === 'JSXIdentifier' && property.name === 'Fragment'
    }
    function assertReadableRouteExpression(node: Node, where: string): void {
      const expression = unwrapTransparentExpression(node)
      if (expression !== node) {
        if (expression) assertReadableRouteExpression(expression, where)
        else rejectUninspectableRouteChild(node, where)
        return
      }
      if (node.type === 'JSXEmptyExpression') return
      if (node.type === 'Literal' && (node.value === null || typeof node.value === 'boolean')) return
      if (node.type === 'JSXElement' || node.type === 'JSXFragment') {
        assertReadableRouteChild(node, where)
        return
      }
      // Conditional JSX routes are readable, but an arbitrary expression may
      // evaluate to a Route created outside JSX (for example with
      // React.createElement or an alias of createElement), which this
      // inventory cannot enumerate.
      if (node.type === 'LogicalExpression' && node.operator === '&&') {
        assertReadableRouteExpression(node.right as Node, where)
        return
      }
      if (node.type === 'ConditionalExpression') {
        assertReadableRouteExpression(node.consequent as Node, where)
        assertReadableRouteExpression(node.alternate as Node, where)
        return
      }
      if (node.type === 'ArrayExpression') {
        for (const child of node.elements as (Node | null)[]) {
          if (child) assertReadableRouteExpression(child, where)
        }
        return
      }
      rejectUninspectableRouteChild(node, where)
    }
    function assertReadableRouteChild(node: Node, where: string): void {
      if (node.type === 'JSXText') {
        if (!String(node.value).trim()) return
        rejectUninspectableRouteChild(node, where)
      }
      if (node.type === 'JSXExpressionContainer') {
        assertReadableRouteExpression(node.expression as Node, where)
        return
      }
      if (node.type === 'JSXFragment') {
        for (const child of node.children as Node[]) assertReadableRouteChild(child, where)
        return
      }
      if (node.type === 'JSXElement') {
        if (isReactFragment(node)) {
          for (const child of node.children as Node[]) assertReadableRouteChild(child, where)
          return
        }
        const name = jsxName(node)
        if (name && local.Route.has(name)) {
          const attributes = ((node.openingElement as Node).attributes as Node[])
          if (attributes.some(attribute => attribute.type === 'JSXSpreadAttribute')) {
            throw new Error(`${file}: <Route> in ${where} uses a JSX prop spread; the console route inventory requires explicit props so it can determine the effective path`)
          }
          if (jsxAttribute(node, 'children')) {
            throw new Error(`${file}: <Route> in ${where} uses a children attribute; nested routes must be declared as direct JSX children so the console route inventory can audit them`)
          }
          return
        }
        if (name && local.Routes.has(name)) return
        rejectUninspectableRouteChild(node, where)
      }
      rejectUninspectableRouteChild(node, where)
    }
    const collect = (nodes: Node[], where: string, routeParameters: Set<string>): SourceRoute[] => {
      const routes: SourceRoute[] = []
      nodes.forEach(node => assertReadableRouteChild(node, where))
      const visit = (node: Node) => {
        const name = jsxName(node)
        if (name && local.Route.has(name)) {
          collectedRoutes += 1
          const index = routeIndexAttribute(node, file, where)
          const caseSensitive = routeBooleanAttribute(node, 'caseSensitive', file, where)
          const pathAttribute = jsxAttribute(node, 'path')
          const path = pathAttribute ? stringValue(pathAttribute.value as Node, `A <Route> path in ${where} in ${file}`) : undefined
          const wildcard = isCanonicalWildcardPath(path, file, where)
          const componentAttributeNames = ['Component', 'ErrorBoundary', 'HydrateFallback']
          const elementAttributeNames = ['element', 'errorElement', 'hydrateFallbackElement']
          const componentAttributes = componentAttributeNames
            .map(name => ({ name, attribute: jsxAttribute(node, name) }))
            .filter((item): item is { name: string; attribute: Node } => item.attribute !== undefined)
          const elementAttributes = elementAttributeNames
            .map(name => ({ name, attribute: jsxAttribute(node, name) }))
            .filter((item): item is { name: string; attribute: Node } => item.attribute !== undefined)
          if (wildcard && jsxAttribute(node, 'lazy')) {
            throw new Error(`${file}: <Route> in ${where} uses a lazy prop in wildcard route ${path}; the inventory cannot inspect route components returned at runtime`)
          }
          if (wildcard) {
            for (const { name, attribute } of componentAttributes) {
              const expression = jsxExpressionAttribute(attribute)
              if (!readableComponentExpression(expression, dynamicComponents.readableCalls, reactNamespaces, readableComponentBindings.bindings, routeParameters)) {
                throw new Error(`${file}: <Route> in ${where} has a ${name} prop the route inventory cannot read in wildcard route ${path}; use a statically declared component value so it can check for nested routes`)
              }
            }
            for (const { name, attribute } of elementAttributes) {
              if (!readableRouteElementExpression(
                jsxExpressionAttribute(attribute),
                reactFactories,
                dynamicComponents.readableCalls,
                reactNamespaces,
                readableComponentBindings.bindings,
                routeParameters,
                knownRouterComponents,
              )) {
                throw new Error(`${file}: <Route> in ${where} has an unreadable ${name} prop in wildcard route ${path}; use literal JSX so the inventory can check for nested routes`)
              }
            }
          }
          const componentReferences = (value: Node | undefined): string[] => {
            const expression = unwrapTransparentExpression(value)
            if (!expression) return []
            if (expression.type === 'Identifier') return [String(expression.name)]
            if (expression.type === 'MemberExpression' || expression.type === 'OptionalMemberExpression') {
              return componentReferences(expression.object as Node)
            }
            if (expression.type === 'ConditionalExpression') {
              return [
                ...componentReferences(expression.consequent as Node),
                ...componentReferences(expression.alternate as Node),
              ]
            }
            if (expression.type === 'LogicalExpression') {
              return [
                ...componentReferences(expression.left as Node),
                ...componentReferences(expression.right as Node),
              ]
            }
            if (expression.type === 'CallExpression' || expression.type === 'OptionalCallExpression') {
              const callee = unwrapTransparentExpression(expression.callee as Node | undefined)
              const isCreateElement = callee?.type === 'Identifier'
                ? reactFactories.factories.has(String(callee.name))
                : !!callee && (callee.type === 'MemberExpression' || callee.type === 'OptionalMemberExpression')
                  && (callee.object as Node).type === 'Identifier'
                  && reactFactories.namespaces.has(String((callee.object as Node).name))
                  && memberPropertyName(callee) === 'createElement'
              if (isCreateElement) return componentReferences((expression.arguments as Node[] | undefined)?.[0])
            }
            return renderedComponents(expression)
          }
          const uninspectableRenders = elementAttributes.flatMap(({ attribute }) =>
            renderedImportedComponents(attribute.value as Node | undefined, importedExternalComponentBindings, file, reactFactories.factories, reactFactories.namespaces, dynamicComponents.calls, true, opaqueRuntimeModuleLoads))
            .concat(componentAttributes.flatMap(({ attribute }) =>
              renderedImportedComponents(attribute.value as Node | undefined, importedExternalComponentBindings, file, reactFactories.factories, reactFactories.namespaces, dynamicComponents.calls, true, opaqueRuntimeModuleLoads)))
          const renderedNames = [
            ...elementAttributes.flatMap(({ attribute }) => componentReferences(jsxExpressionAttribute(attribute))),
            ...componentAttributes.flatMap(({ attribute }) => componentReferences(jsxExpressionAttribute(attribute))),
          ]
          const renders = renderedNames.map(name => localComponentAliases.get(name)?.source ?? name)
          routes.push({
            path,
            index,
            caseSensitive,
            renders,
            localRenders: [...new Set(renderedNames.flatMap(name => {
              const local = localComponentAliases.get(name)
              return local ? [local.source] : []
            }))],
            unreadableLocalRenders: [...new Set(renderedNames.flatMap(name => {
              const local = localComponentAliases.get(name)
              const component = local?.source ?? name
              return readableComponentBindings.unreadableComponents.has(name)
                || readableComponentBindings.unreadableComponents.has(component)
                ? [component]
                : []
            }))],
            uninspectableRenders,
            children: collect(node.children as Node[], where, routeParameters),
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

    const walk = (node: Node, component: string, inheritedParameters = new Set<string>()) => {
      let current = component
      const functionNode = node.type === 'MethodDefinition' ? node.value as Node : node
      const currentParameters = ['FunctionDeclaration', 'FunctionExpression', 'ArrowFunctionExpression', 'ObjectMethod', 'ClassMethod', 'MethodDefinition'].includes(node.type)
        ? functionParametersIncludingAliases(functionNode, inheritedParameters)
        : new Set(inheritedParameters)
      if (node.type === 'FunctionDeclaration' && node.id) current = String((node.id as Node).name)
      if (node.type === 'VariableDeclarator' && (node.id as Node).type === 'Identifier' && /^[A-Z]/.test(String((node.id as Node).name))) current = String((node.id as Node).name)
      const name = jsxName(node)
      if (name && local.Route.has(name)) routeElements += 1
      if (name && local.Routes.has(name)) {
        if (!current) throw new Error(`${file}: a <Routes> outside a named component`)
        const attributes = (node.openingElement as Node).attributes as Node[]
        if (attributes.some(attribute => attribute.type === 'JSXSpreadAttribute') || jsxAttribute(node, 'children')) {
          throw new Error(`${file}: <Routes> in ${current} must declare route children as direct JSX children, not a children prop or prop spread`)
        }
        if (jsxAttribute(node, 'location')) {
          throw new Error(`${file}: <Routes> in ${current} uses a location prop; the route inventory must audit the browser location that the accessibility checks visit`)
        }
        const count = routers.filter(router => router.name === current || router.name.startsWith(`${current}#`)).length
        routers.push({
          name: count ? `${current}#${count + 1}` : current,
          routes: collect(node.children as Node[], current, currentParameters),
        })
      }
      childNodes(node).forEach(child => walk(child, current, currentParameters))
    }
    walk(program, '')
    if (routeElements !== collectedRoutes) throw new Error(`${file}: a <Route> is outside every <Routes>, which the console route inventory check cannot place`)
    rejectRouterAPIValues(program, file, local)
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
  const localRenderLabel = (name: string) => {
    if (!name.startsWith('@unmodeled-local:')) return name
    const exportSeparator = name.lastIndexOf(' export ')
    return exportSeparator >= 0 ? name.slice(exportSeparator + ' export '.length) : name
  }
  const byName = new Map<string, SourceRouter>()
  for (const router of routers) {
    if (byName.has(router.name)) {
      throw new Error(`multiple <Routes> components are named ${router.name}; the console route inventory requires unique router component names`)
    }
    byName.set(router.name, router)
  }
  const mounted = new Set<string>()

  const build = (declaring: string, routes: SourceRoute[], parent: string, handles: RouteHandle[], seen: Set<string>): RouteObject[] => routes.map(route => {
    const pattern = joinPattern(parent, route.path)
    const base = pattern.replace(/\/\*$/, '') || '/'
    if (route.path === '*' || route.path?.endsWith('/*')) {
      const uninspectable = route.uninspectableRenders[0]
      if (uninspectable) {
        throw new Error(`${uninspectable.file} renders imported component ${uninspectable.component} from ${uninspectable.source} in wildcard route ${pattern}; the console route inventory cannot inspect whether it owns nested <Routes>. Import a readable local TypeScript component or declare the nested routes directly in the audited JSX tree`)
      }
      const unmodeledLocalRender = route.localRenders?.find(name => !byName.has(name))
      if (unmodeledLocalRender) {
        throw new Error(`wildcard route ${pattern} renders local component ${localRenderLabel(unmodeledLocalRender)} without a statically named nested <Routes>; the console route inventory cannot verify routes owned by an imported component`)
      }
      const unreadableLocalRender = route.unreadableLocalRenders?.[0]
      if (unreadableLocalRender) {
        throw new Error(`wildcard route ${pattern} renders local component ${unreadableLocalRender} with an unreadable render tree; the console route inventory cannot verify routes it may own`)
      }
    }
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

type LocalModuleResolver = {
  isLocalSpecifier(specifier: string): boolean
  resolve(importer: string, specifier: string): string | undefined
}

function pathWildcardIndex(value: string, description: string): number {
  const wildcard = value.indexOf('*')
  if (wildcard >= 0 && value.indexOf('*', wildcard + 1) >= 0) {
    throw new Error(`${description} contains more than one '*' wildcard; the console route inventory cannot resolve it`)
  }
  return wildcard
}

function substitutePathWildcard(target: string, substitution: string): string {
  const wildcard = pathWildcardIndex(target, `TypeScript path target ${target}`)
  if (wildcard < 0) return target
  return `${target.slice(0, wildcard)}${substitution}${target.slice(wildcard + 1)}`
}

function pathAliasMatches(specifier: string, pattern: string): boolean {
  const wildcard = pathWildcardIndex(pattern, `TypeScript path pattern ${pattern}`)
  if (wildcard < 0) return specifier === pattern
  const prefix = pattern.slice(0, wildcard)
  const suffix = pattern.slice(wildcard + 1)
  return specifier.startsWith(prefix) && specifier.endsWith(suffix) && specifier.length >= prefix.length + suffix.length
}

function parseJsonConfig(source: string): unknown {
  let uncommented = ''
  let inString = false
  let escaped = false
  for (let index = 0; index < source.length; index += 1) {
    const character = source[index]
    const next = source[index + 1]
    if (inString) {
      uncommented += character
      if (escaped) escaped = false
      else if (character === '\\') escaped = true
      else if (character === '"') inString = false
      continue
    }
    if (character === '"') {
      inString = true
      uncommented += character
      continue
    }
    if (character === '/' && next === '/') {
      while (index < source.length && source[index] !== '\n') index += 1
      uncommented += '\n'
      continue
    }
    if (character === '/' && next === '*') {
      index += 2
      while (index < source.length && !(source[index] === '*' && source[index + 1] === '/')) index += 1
      index += 1
      continue
    }
    if (character === ',') {
      let lookahead = index + 1
      while (/\s/.test(source[lookahead] ?? '')) lookahead += 1
      if (source[lookahead] === '}' || source[lookahead] === ']') continue
    }
    uncommented += character
  }
  return JSON.parse(uncommented) as unknown
}

function pathIsWithin(root: string, candidate: string): boolean {
  const rel = relative(root, candidate)
  return rel === '' || (rel !== '..' && !rel.startsWith(`..${process.platform === 'win32' ? '\\' : '/'}`) && !isAbsolute(rel))
}

function localModuleResolver(configRoot: string): LocalModuleResolver {
  const canonicalConfigRoot = realpathSync(configRoot)
  const isAllowedPath = (path: string) => {
    const canonical = realpathSync(path)
    return pathIsWithin(canonicalConfigRoot, canonical) ? canonical : undefined
  }
  const configPath = join(canonicalConfigRoot, 'tsconfig.json')
  if (existsSync(configPath) && !isAllowedPath(configPath)) {
    throw new Error(`TypeScript config ${configPath} resolves outside allowed root ${canonicalConfigRoot}`)
  }
  const config = existsSync(configPath)
    ? parseJsonConfig(readFileSync(configPath, 'utf8')) as { extends?: unknown; compilerOptions?: { baseUrl?: unknown; paths?: unknown } }
    : {}
  if (config.extends !== undefined) {
    throw new Error(`${configPath} extends another config; the console route inventory cannot resolve aliases through an extended tsconfig`)
  }
  const compilerOptions = config.compilerOptions ?? {}
  const baseUrl = typeof compilerOptions.baseUrl === 'string' ? resolve(canonicalConfigRoot, compilerOptions.baseUrl) : canonicalConfigRoot
  const paths = typeof compilerOptions.paths === 'object' && compilerOptions.paths !== null
    ? compilerOptions.paths as Record<string, unknown>
    : {}
  const aliases = Object.entries(paths).flatMap(([pattern, targets]) => Array.isArray(targets)
    ? targets.filter((target): target is string => typeof target === 'string').map(target => {
        pathWildcardIndex(pattern, `TypeScript path pattern ${pattern}`)
        pathWildcardIndex(target, `TypeScript path target ${target}`)
        return { pattern, target }
      })
    : [])
  const pathAliases = aliases.map(alias => alias.pattern)
  const isLocalSpecifier = (specifier: string) => specifier.startsWith('.')
    || specifier.startsWith('/')
    || pathAliases.some(pattern => pathAliasMatches(specifier, pattern))

  const typeScriptFile = (path: string, specifier: string): string | undefined => {
    const extension = extname(specifier)
    const tsExtensions = new Set(['.ts', '.tsx', '.mts', '.cts'])
    const jsExtensions = new Set(['.js', '.jsx', '.mjs', '.cjs'])
    if (extension && !tsExtensions.has(extension) && !jsExtensions.has(extension)) return undefined
    // An explicit JavaScript extension names a runtime file. Do not substitute
    // a nearby TypeScript file with the same stem; that could make the audit
    // inspect different route code from the application.
    if (jsExtensions.has(extension)) return undefined
    // Match Vite's default extension order. If Vite would select JavaScript,
    // JSX, or JSON before a TypeScript sibling, fail closed rather than audit
    // a different module than the application executes.
    const candidates = tsExtensions.has(extension)
      ? [path]
      : [
          ...['.mjs', '.js', '.mts', '.ts', '.jsx', '.tsx', '.json'].map(suffix => `${path}${suffix}`),
          ...['index.mjs', 'index.js', 'index.mts', 'index.ts', 'index.jsx', 'index.tsx', 'index.json'].map(name => join(path, name)),
        ]
    for (const candidate of candidates) {
      if (!existsSync(candidate) || !statSync(candidate).isFile() || candidate.endsWith('.d.ts') || /\.test\.(?:ts|tsx)$/.test(candidate)) continue
      if (jsExtensions.has(extname(candidate)) || extname(candidate) === '.json') {
        throw new Error(`local module ${specifier} resolves first to ${relative(canonicalConfigRoot, candidate)} under Vite's extension order, which the console route inventory cannot inspect as TypeScript`)
      }
      const canonical = isAllowedPath(candidate)
      if (!canonical) {
        throw new Error(`local module ${specifier} resolves outside allowed root ${canonicalConfigRoot}; the console route inventory cannot inspect the module selected by the application`)
      }
      return canonical
    }
    return undefined
  }

  return {
    isLocalSpecifier,
    resolve(importer, specifier) {
      if (!isLocalSpecifier(specifier)) return undefined
      if (specifier.startsWith('.') || specifier.startsWith('/')) return typeScriptFile(resolve(dirname(importer), specifier), specifier)

      const matchingAliases = aliases
        .filter(alias => pathAliasMatches(specifier, alias.pattern))
        .sort((left, right) => {
          const leftPrefix = left.pattern.indexOf('*') < 0 ? left.pattern.length : left.pattern.indexOf('*')
          const rightPrefix = right.pattern.indexOf('*') < 0 ? right.pattern.length : right.pattern.indexOf('*')
          return rightPrefix - leftPrefix || right.pattern.length - left.pattern.length
        })
      for (const alias of matchingAliases) {
        const wildcard = pathWildcardIndex(alias.pattern, `TypeScript path pattern ${alias.pattern}`)
        const suffix = wildcard < 0 ? '' : alias.pattern.slice(wildcard + 1)
        const substitution = wildcard < 0 ? '' : specifier.slice(wildcard, specifier.length - suffix.length)
        const target = wildcard < 0 ? alias.target : substitutePathWildcard(alias.target, substitution)
        const candidate = typeScriptFile(resolve(baseUrl, target), target)
        if (candidate) return candidate
      }
      return undefined
    },
  }
}

function sourceFiles(directory = sourceRoot, configRoot = repositoryRoot): SourceFile[] {
  const files: SourceFile[] = []
  const seen = new Set<string>()
  const canonicalConfigRoot = realpathSync(configRoot)
  const canonicalDirectory = realpathSync(directory)
  if (!pathIsWithin(canonicalConfigRoot, canonicalDirectory)) {
    throw new Error(`source directory ${directory} resolves outside allowed root ${canonicalConfigRoot}`)
  }
  const moduleResolver = localModuleResolver(canonicalConfigRoot)
  const addFile = (path: string) => {
    const absolutePath = realpathSync(path)
    if (!pathIsWithin(canonicalConfigRoot, absolutePath)) {
      throw new Error(`source file ${path} resolves outside allowed root ${canonicalConfigRoot}`)
    }
    if (seen.has(absolutePath)) return
    seen.add(absolutePath)
    const file = relative(repositoryRoot, absolutePath).split(/[\\/]/).join('/')
    files.push({ file, code: readFileSync(absolutePath, 'utf8') })
  }
  const scanDirectory = (path: string) => {
    const canonicalPath = realpathSync(path)
    if (!pathIsWithin(canonicalConfigRoot, canonicalPath)) {
      throw new Error(`source directory ${path} resolves outside allowed root ${canonicalConfigRoot}`)
    }
    for (const entry of readdirSync(canonicalPath, { withFileTypes: true }).sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0)) {
      const childPath = join(canonicalPath, entry.name)
      const file = relative(repositoryRoot, childPath).split(/[\\/]/).join('/')
      if (entry.isDirectory()) {
        if (file !== 'src/test' && file !== 'src/generated') scanDirectory(childPath)
      } else if (/\.tsx?$/.test(entry.name) && !/\.test\.tsx?$/.test(entry.name) && !entry.name.endsWith('.d.ts')) {
        addFile(childPath)
      }
    }
  }

  scanDirectory(directory)
  // Follow statically resolvable local module edges, including dynamic loads
  // and configured tsconfig path aliases. A helper can otherwise hide renamed
  // Route and Routes re-exports outside src.
  for (let index = 0; index < files.length; index += 1) {
    const source = files[index]
    const parsed = parseSync(source.file, source.code, { lang: source.file.endsWith('.tsx') ? 'tsx' : 'ts' })
    if (parsed.errors.length) continue
    const program = parsed.program as unknown as Node
    const importer = resolve(repositoryRoot, source.file)
    const runtimeModuleLoads = rejectUninspectableRouterLoads(program, source.file)
    const moduleSpecifiers = new Set(runtimeModuleLoads.map(load => load.specifier))
    for (const statement of program.body as Node[]) {
      const hasModuleSource = statement.type === 'ImportDeclaration'
        || statement.type === 'ExportNamedDeclaration'
        || statement.type === 'ExportAllDeclaration'
      if (!hasModuleSource || (statement.type === 'ImportDeclaration' && statement.importKind === 'type') || (statement.type !== 'ImportDeclaration' && statement.exportKind === 'type')) continue
      const moduleSource = statement.source as Node | null | undefined
      if (moduleSource?.type === 'Literal' && typeof moduleSource.value === 'string') moduleSpecifiers.add(moduleSource.value)
    }
    for (const specifier of moduleSpecifiers) {
      if (!moduleResolver.isLocalSpecifier(specifier)) continue
      const path = moduleResolver.resolve(importer, specifier)
      if (!path && (runtimeModuleLoads.some(load => load.specifier === specifier) || /\.(?:js|jsx|mjs|cjs)$/i.test(specifier))) {
        throw new Error(`${source.file} loads local module ${specifier} that the console route inventory cannot inspect as TypeScript`)
      }
      if (path) addFile(path)
    }
  }
  return files.sort(compareSourceFiles)
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

  it('preserves same-named routers from different modules and rejects ambiguous router inputs', () => {
    const sources = [
      {
        file: 'src/one/SharedRoutes.tsx',
        code: `import { Route, Routes } from 'react-router-dom'
export function SharedRoutes() { return <Routes><Route path="/one" /></Routes> }`,
      },
      {
        file: 'src/two/SharedRoutes.tsx',
        code: `import { Route, Routes } from 'react-router-dom'
export function SharedRoutes() { return <Routes><Route path="/two" /></Routes> }`,
      },
    ]

    const resolved = resolveRouters(extractRouters(sources))
    expect(resolved.map(router => router.name)).toEqual(['SharedRoutes', 'SharedRoutes#2'])
    expect(resolved.flatMap(router => router.handles.map(label))).toEqual(['SharedRoutes /one', 'SharedRoutes#2 /two'])
    expect(resolveRouters(extractRouters([...sources].reverse()))).toEqual(resolved)
    expect(() => resolveRouters([
      { name: 'Ambiguous', routes: [] },
      { name: 'Ambiguous', routes: [] },
    ])).toThrow(
      /multiple <Routes> components are named Ambiguous; the console route inventory requires unique router component names/,
    )
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

    it('fails closed when an imported package component could own routes under a wildcard parent', () => {
      const sources = [
        {
          file: 'src/external-nested-routes.tsx',
          code: `import { Route, Routes } from 'react-router-dom'
import { NestedRoutes as PackageNestedRoutes } from 'third-party-router'
const NestedRoutes = PackageNestedRoutes
export function Shell() {
  return <Routes><Route path="/known/*" element={<NestedRoutes />} /></Routes>
}`,
        },
        {
          file: 'src/external-nested-routes-prop.tsx',
          code: `import { Route, Routes } from 'react-router-dom'
import { NestedRoutes } from 'third-party-router'
function Wrapper({ Component }: { Component: React.ComponentType }) { return <Component /> }
export function Shell() {
  return <Routes><Route path="/known/*" element={<Wrapper Component={NestedRoutes} />} /></Routes>
}`,
        },
      ]

      // An inventory entry for /known cannot cover a hidden /known/child route.
      for (const source of sources) {
        expect(() => resolveRouters(extractRouters([source])), source.file).toThrow(/(?:renders imported component NestedRoutes from third-party-router in wildcard route \/known\/\*; the console route inventory cannot inspect whether it owns nested <Routes>|unreadable element prop in wildcard route \/known\/\*)/)
      }
    })

    it('fails closed when a local wildcard fallback renders an opaque package component', () => {
      const sources = [
        {
          file: 'src/local-fallback-with-external-routes.tsx',
          code: `import { Route, Routes } from 'react-router-dom'
import { NestedRoutes } from 'third-party-router'
function Fallback() { return <NestedRoutes /> }
export function AuthRoutes() { return <Routes><Route path="*" element={<Fallback />} /></Routes> }`,
        },
        {
          file: 'src/local-fallback-forwards-external-routes.tsx',
          code: `import { Route, Routes } from 'react-router-dom'
import { NestedRoutes } from 'third-party-router'
function Fallback() { const child = NestedRoutes; return <RouteHost Component={child} /> }
function RouteHost({ Component }: { Component: React.ComponentType }) { return <Component /> }
export function AuthRoutes() { return <Routes><Route path="*" element={<Fallback />} /></Routes> }`,
        },
        {
          file: 'src/local-fallback-passes-external-routes.tsx',
          code: `import { Route, Routes } from 'react-router-dom'
import { NestedRoutes } from 'third-party-router'
function Fallback() { registerRoutes(NestedRoutes); return <main /> }
export function AuthRoutes() { return <Routes><Route path="*" element={<Fallback />} /></Routes> }`,
        },
      ]
      const inventory: Inventory = {
        consoleRoutes: [],
        surfaces: [
          { path: '/public', router: 'public', state: 'public', heading: '' },
          { path: '/public/unit', router: 'public', state: 'public', heading: '' },
        ],
        scopeRouters: { unit: ['AuthRoutes'], platform: [], shared: [] },
        exclusions: [{ router: 'AuthRoutes', path: '*', reason: 'The fallback has no page of its own.' }],
        tabKeys: [],
      }

      // Excluding the visible fallback must not hide a package-owned child route.
      for (const source of sources) {
        expect(() => inventoryProblems(resolveRouters(extractRouters([source])), inventory), source.file).toThrow(
          /renders imported component (?:NestedRoutes|Fallback) from third-party-router in wildcard route \*; the console route inventory cannot inspect whether it owns nested <Routes>/,
        )
      }

      const safeWrapper = {
        file: 'src/local-fallback-with-package-hook.tsx',
        code: `import { Route, Routes } from 'react-router-dom'
import { useTitle } from 'third-party-router'
function Fallback() { useTitle('fallback'); return <main /> }
export function AuthRoutes() { return <Routes><Route path="*" element={<Fallback />} /></Routes> }`,
      }
      expect(resolveRouters(extractRouters([safeWrapper]))[0].handles.map(label)).toEqual(['AuthRoutes *'])
    })

    it('resolves long local runtime-loader chains without recursive rescans', () => {
      const functionCount = 2000
      const functions = [
        `function load0() { return require('third-party-router').NestedRoutes }`,
        ...Array.from({ length: functionCount - 1 }, (_unused, index) => `function load${index + 1}() { return load${index}() }`),
      ].join('\n')
      const source = {
        file: 'src/long-runtime-loader-chain.tsx',
        code: `import * as React from 'react'
import { Route, Routes } from 'react-router-dom'
${functions}
const NestedRoutes = load${functionCount - 1}()
function Fallback() { return React.createElement(NestedRoutes) }
export function Shell() { return <Routes><Route path="*" element={<Fallback />} /></Routes> }`,
      }

      expect(() => resolveRouters(extractRouters([source]))).toThrow(
        /renders imported component (?:Fallback|NestedRoutes) from third-party-router in wildcard route \*; the console route inventory cannot inspect whether it owns nested <Routes>/,
      )
    })

    it('carries opaque nested-router provenance across local TypeScript modules', () => {
      const fixtureRoot = mkdtempSync(join(tmpdir(), 'edgewatch-cross-module-router-'))
      const sourceDirectory = join(fixtureRoot, 'src')
      mkdirSync(sourceDirectory, { recursive: true })
      writeFileSync(join(sourceDirectory, 'Shell.tsx'), `import { Route, Routes } from 'react-router-dom'
import { Fallback } from './Fallback'
export function Shell() { return <Routes><Route path="*" element={<Fallback />} /></Routes> }
`)
      const wrapperPath = join(sourceDirectory, 'Fallback.tsx')

      try {
        writeFileSync(wrapperPath, `import { NestedRoutes } from 'third-party-router'
export function Fallback() { return <NestedRoutes /> }
`)
        const opaqueSources = sourceFiles(sourceDirectory, fixtureRoot)
        expect(() => resolveRouters(extractRouters(opaqueSources, fixtureRoot))).toThrow(
          /renders imported component Fallback from third-party-router in wildcard route \*; the console route inventory cannot inspect whether it owns nested <Routes>/,
        )

        writeFileSync(wrapperPath, `import * as React from 'react'
import { NestedRoutes as nestedRoutes } from 'third-party-router'
function renderComponent(Component: React.ComponentType) { return React.createElement(Component) }
export function Fallback() { return renderComponent(nestedRoutes) }
`)
        const helperCallSources = sourceFiles(sourceDirectory, fixtureRoot)
        expect(() => resolveRouters(extractRouters(helperCallSources, fixtureRoot))).toThrow(
          /renders imported component Fallback from third-party-router in wildcard route \*; the console route inventory cannot inspect whether it owns nested <Routes>/,
        )

        writeFileSync(wrapperPath, `import * as React from 'react'
import { NestedRoutes as nestedRoutes } from 'third-party-router'
function renderComponent(Component: React.ComponentType) { return React.createElement(Component) }
const renderAlias = renderComponent
export function Fallback() { return renderAlias(nestedRoutes) }
`)
        const aliasedHelperCallSources = sourceFiles(sourceDirectory, fixtureRoot)
        expect(() => resolveRouters(extractRouters(aliasedHelperCallSources, fixtureRoot))).toThrow(
          /renders imported component Fallback from third-party-router in wildcard route \*; the console route inventory cannot inspect whether it owns nested <Routes>/,
        )

        writeFileSync(wrapperPath, `import * as React from 'react'
import { NestedRoutes as nestedRoutes } from 'third-party-router'
function renderComponent(Component: React.ComponentType) { return React.createElement(Component) }
let renderAlias = renderComponent
export function Fallback() { return renderAlias(nestedRoutes) }
`)
        const mutableAliasSources = sourceFiles(sourceDirectory, fixtureRoot)
        expect(() => resolveRouters(extractRouters(mutableAliasSources, fixtureRoot))).toThrow(
          /renders imported component Fallback from third-party-router in wildcard route \*; the console route inventory cannot inspect whether it owns nested <Routes>/,
        )

        writeFileSync(wrapperPath, `import * as React from 'react'
import { NestedRoutes as nestedRoutes } from 'third-party-router'
const wrappers = { render(Component: React.ComponentType) { return React.createElement(Component) } }
export function Fallback() { return wrappers.render(nestedRoutes) }
`)
        const memberCallSources = sourceFiles(sourceDirectory, fixtureRoot)
        expect(() => resolveRouters(extractRouters(memberCallSources, fixtureRoot))).toThrow(
          /renders imported component Fallback from third-party-router in wildcard route \*; the console route inventory cannot inspect whether it owns nested <Routes>/,
        )

        writeFileSync(wrapperPath, `import * as React from 'react'
import { NestedRoutes as nestedRoutes } from 'third-party-router'
class Wrappers { static render(Component: React.ComponentType) { return React.createElement(Component) } }
export function Fallback() { return Wrappers.render(nestedRoutes) }
`)
        const classMethodCallSources = sourceFiles(sourceDirectory, fixtureRoot)
        expect(() => resolveRouters(extractRouters(classMethodCallSources, fixtureRoot))).toThrow(
          /renders imported component Fallback from third-party-router in wildcard route \*; the console route inventory cannot inspect whether it owns nested <Routes>/,
        )

        writeFileSync(wrapperPath, `import * as React from 'react'
function loadRoutes() { return require('third-party-router').NestedRoutes }
export function Fallback() { const NestedRoutes = loadRoutes(); return React.createElement(NestedRoutes) }
`)
        const runtimeLoaderSources = sourceFiles(sourceDirectory, fixtureRoot)
        expect(() => resolveRouters(extractRouters(runtimeLoaderSources, fixtureRoot))).toThrow(
          /renders imported component Fallback from third-party-router in wildcard route \*; the console route inventory cannot inspect whether it owns nested <Routes>/,
        )

        writeFileSync(wrapperPath, `import * as React from 'react'
class Loader { static async load() { return (await import('third-party-router')).NestedRoutes } }
const NestedRoutes = await Loader.load()
export function Fallback() { return React.createElement(NestedRoutes) }
`)
        const classLoaderSources = sourceFiles(sourceDirectory, fixtureRoot)
        expect(() => resolveRouters(extractRouters(classLoaderSources, fixtureRoot))).toThrow(
          /renders imported component Fallback from third-party-router in wildcard route \*; the console route inventory cannot inspect whether it owns nested <Routes>/,
        )

        writeFileSync(wrapperPath, `import * as React from 'react'
const registry: Record<string, React.ComponentType> = {}
registry.NestedRoutes = (await import('third-party-router')).NestedRoutes
export function Fallback() { return React.createElement(registry.NestedRoutes) }
`)
        const memberAssignmentSources = sourceFiles(sourceDirectory, fixtureRoot)
        expect(() => resolveRouters(extractRouters(memberAssignmentSources, fixtureRoot))).toThrow(
          /renders imported component Fallback from third-party-router in wildcard route \*; the console route inventory cannot inspect whether it owns nested <Routes>/,
        )

        writeFileSync(join(sourceDirectory, 'Shell.tsx'), `import { Route, Routes } from 'react-router-dom'
import Fallback from './Fallback'
export function Shell() { return <Routes><Route path="*" element={<Fallback />} /></Routes> }
`)
        writeFileSync(wrapperPath, `export default () => <RouteHost Component={require('third-party-router').NestedRoutes} />
`)
        const anonymousDefaultSources = sourceFiles(sourceDirectory, fixtureRoot)
        expect(() => resolveRouters(extractRouters(anonymousDefaultSources, fixtureRoot))).toThrow(
          /renders imported component Fallback from third-party-router in wildcard route \*; the console route inventory cannot inspect whether it owns nested <Routes>/,
        )

        writeFileSync(wrapperPath, `import { useTitle } from 'third-party-router'
export function Fallback() { useTitle('safe'); return <main /> }
`)
        const safeSources = sourceFiles(sourceDirectory, fixtureRoot)
        expect(() => resolveRouters(extractRouters(safeSources, fixtureRoot))).toThrow(
          /wildcard route \* renders local component Fallback without a statically named nested <Routes>/,
        )

        writeFileSync(join(sourceDirectory, 'Shell.tsx'), `import { Route, Routes } from 'react-router-dom'
import Fallback from './Fallback'
export function Shell() { return <Routes><Route path="*" element={<Fallback />} /></Routes> }
`)
        writeFileSync(wrapperPath, `import { NestedRoutes as routes } from 'third-party-router'
const forwarded = routes
export default forwarded
`)
        const reexportedAliasSources = sourceFiles(sourceDirectory, fixtureRoot)
        expect(() => resolveRouters(extractRouters(reexportedAliasSources, fixtureRoot))).toThrow(
          /renders imported component Fallback from third-party-router in wildcard route \*; the console route inventory cannot inspect whether it owns nested <Routes>/,
        )

        writeFileSync(wrapperPath, `export * from 'third-party-router'
`)
        writeFileSync(join(sourceDirectory, 'Shell.tsx'), `import { Route, Routes } from 'react-router-dom'
import { NestedRoutes as Fallback } from './Fallback'
export function Shell() { return <Routes><Route path="*" element={<Fallback />} /></Routes> }
`)
        const exportStarSources = sourceFiles(sourceDirectory, fixtureRoot)
        expect(() => resolveRouters(extractRouters(exportStarSources, fixtureRoot))).toThrow(
          /uses <Fallback> from unresolved router import third-party-router/,
        )
      } finally {
        rmSync(fixtureRoot, { recursive: true, force: true })
      }
    })

    it('tracks lowercase components read from opaque package namespaces', () => {
      const source = {
        file: 'src/namespace-member-alias.tsx',
        code: `import { Route, Routes } from 'react-router-dom'
import * as thirdParty from 'third-party-router'
const Page = thirdParty.NestedRoutes
export function Shell() { return <Routes><Route path="*" element={<Page />} /></Routes> }`,
      }

      expect(() => resolveRouters(extractRouters([source]))).toThrow(
        /uses <Page> from unresolved router import third-party-router/,
      )
    })

    it('keeps opaque exports visible through local namespace imports', () => {
      const fixtureRoot = mkdtempSync(join(tmpdir(), 'edgewatch-opaque-namespace-export-'))
      const sourceDirectory = join(fixtureRoot, 'src')
      mkdirSync(sourceDirectory, { recursive: true })
      writeFileSync(join(sourceDirectory, 'Shell.tsx'), `import { Route, Routes } from 'react-router-dom'
import * as Pages from './barrel'
export function Shell() {
  return <Routes><Route path="/known/*" element={<Pages.NestedRoutes />} /></Routes>
}
`)
      writeFileSync(join(sourceDirectory, 'barrel.ts'), `export { NestedRoutes } from 'third-party-router'
`)

      try {
        const sources = sourceFiles(sourceDirectory, fixtureRoot)
        expect(() => resolveRouters(extractRouters(sources, fixtureRoot))).toThrow(
          /renders imported component Pages\.NestedRoutes from third-party-router in wildcard route \/known\/\*/,
        )

        writeFileSync(join(sourceDirectory, 'Shell.tsx'), `import { Route, Routes } from 'react-router-dom'
import * as Pages from './barrel'
export function Shell() {
  return <Routes><Route path="/known/*" element={<Pages.SafePage />} /></Routes>
}
`)
        writeFileSync(join(sourceDirectory, 'barrel.ts'), `export { NestedRoutes } from 'third-party-router'
export function SafePage() { return null }
`)
        const safeNamespaceSources = sourceFiles(sourceDirectory, fixtureRoot)
        expect(() => resolveRouters(extractRouters(safeNamespaceSources, fixtureRoot))).toThrow(
          /renders imported component Pages\.SafePage from .+ in wildcard route \/known\/\*/,
        )
      } finally {
        rmSync(fixtureRoot, { recursive: true, force: true })
      }
    })

    it('tracks lowercase package components created without JSX in local wrapper modules', () => {
      const fixtureRoot = mkdtempSync(join(tmpdir(), 'edgewatch-lowercase-factory-router-'))
      const sourceDirectory = join(fixtureRoot, 'src')
      mkdirSync(sourceDirectory, { recursive: true })
      writeFileSync(join(sourceDirectory, 'Shell.tsx'), `import { Route, Routes } from 'react-router-dom'
import { Fallback } from './Fallback'
export function Shell() { return <Routes><Route path="*" element={<Fallback />} /></Routes> }
`)
      writeFileSync(join(sourceDirectory, 'Fallback.tsx'), `import * as React from 'react'
import { NestedRoutes as nestedRoutes } from 'third-party-router'
export function Fallback() { return React.createElement(nestedRoutes) }
`)

      try {
        const sources = sourceFiles(sourceDirectory, fixtureRoot)
        expect(() => resolveRouters(extractRouters(sources, fixtureRoot))).toThrow(
          /renders imported component Fallback from third-party-router in wildcard route \*; the console route inventory cannot inspect whether it owns nested <Routes>/,
        )
      } finally {
        rmSync(fixtureRoot, { recursive: true, force: true })
      }
    })

    it('tracks opaque package provenance through React component wrapper call results', () => {
      const inventory: Inventory = {
        consoleRoutes: [],
        surfaces: [
          { path: '/public', router: 'public', state: 'public', heading: '' },
          { path: '/public/unit', router: 'public', state: 'public', heading: '' },
        ],
        scopeRouters: { unit: ['AuthRoutes'], platform: [], shared: [] },
        exclusions: [{ router: 'AuthRoutes', path: '*', reason: 'The fallback has no page of its own.' }],
        tabKeys: [],
      }
      const sources = [
        {
          file: 'src/memoized-external-fallback.tsx',
          code: `import * as React from 'react'
import { Route, Routes } from 'react-router-dom'
import { NestedRoutes } from 'third-party-router'
const Wrapped = React.memo(NestedRoutes)
export function AuthRoutes() { return <Routes><Route path="*" element={<Wrapped />} /></Routes> }`,
        },
        {
          file: 'src/aliased-memoized-external-fallback.tsx',
          code: `import { memo as wrap } from 'react'
import { Route, Routes } from 'react-router-dom'
import { NestedRoutes } from 'third-party-router'
const memoComponent = wrap
const Wrapped = memoComponent(NestedRoutes)
export function AuthRoutes() { return <Routes><Route path="*" element={<Wrapped />} /></Routes> }`,
        },
      ]

      for (const source of sources) {
        expect(() => inventoryProblems(resolveRouters(extractRouters([source])), inventory), source.file).toThrow(
          /renders imported component (?:NestedRoutes|Wrapped) from third-party-router in wildcard route \*; the console route inventory cannot inspect whether it owns nested <Routes>/,
        )
      }
    })

    it('tracks opaque runtime loads through branches, helper calls, lazy loaders, and JSX props', () => {
      const exactInventory: Inventory = {
        consoleRoutes: [{ path: '/known/child', scope: 'unit' }],
        surfaces: [],
        scopeRouters: { unit: ['Shell'], platform: [], shared: [] },
        exclusions: [],
        tabKeys: [],
      }
      const sources = [
        {
          file: 'src/runtime-branch-routes.tsx',
          code: `import { Route, Routes } from 'react-router-dom'
function LocalRoutes() { return <main /> }
const NestedRoutes = window.useExternalRoutes
  ? require('third-party-router').NestedRoutes
  : LocalRoutes
export function Shell() { return <Routes><Route path="/known/*" element={<NestedRoutes />} /></Routes> }`,
        },
        {
          file: 'src/runtime-helper-routes.tsx',
          code: `import { Route, Routes } from 'react-router-dom'
function loadRoutes() { return require('third-party-router').NestedRoutes }
const NestedRoutes = loadRoutes()
export function Shell() { return <Routes><Route path="/known/*" element={<NestedRoutes />} /></Routes> }`,
        },
        {
          file: 'src/runtime-inline-route-prop.tsx',
          code: `import { Route, Routes } from 'react-router-dom'
function RouteHost({ Component }: { Component: React.ComponentType }) { return <Component /> }
export function Shell() {
  return <Routes><Route path="/known/*" element={<RouteHost Component={require('third-party-router').NestedRoutes} />} /></Routes>
}`,
        },
        {
          file: 'src/runtime-lazy-helper-routes.tsx',
          code: `import * as React from 'react'
import { Route, Routes } from 'react-router-dom'
function loadRoutes() { return import('third-party-router') }
const NestedRoutes = React.lazy(() => loadRoutes())
export function Shell() { return <Routes><Route path="/known/*" element={<NestedRoutes />} /></Routes> }`,
        },
      ]

      for (const source of sources) {
        expect(
          () => inventoryProblems(resolveRouters(extractRouters([source])), exactInventory),
          source.file,
        ).toThrow(/(?:renders imported component .* from third-party-router|unreadable element prop) in wildcard route \/known\/\*/)
      }
    })

    it('checks Route.Component values in the full inventory under wildcard paths', () => {
      const exactInventory: Inventory = {
        consoleRoutes: [{ path: '/known/child', scope: 'unit' }],
        surfaces: [],
        scopeRouters: { unit: ['Shell'], platform: [], shared: [] },
        exclusions: [],
        tabKeys: [],
      }
      const sources = [
        {
          file: 'src/external-route-component-prop.tsx',
          code: `import { Route, Routes } from 'react-router-dom'
import { NestedRoutes } from 'third-party-router'
export function Shell() {
  return <Routes><Route path="/known/*" Component={NestedRoutes} /></Routes>
}`,
        },
        {
          file: 'src/external-route-component-lowercase-prop.tsx',
          code: `import { Route, Routes } from 'react-router-dom'
import { NestedRoutes as nestedRoutes } from 'third-party-router'
export function Shell() {
  return <Routes><Route path="/known/*" Component={nestedRoutes} /></Routes>
}`,
        },
      ]

      for (const source of sources) {
        expect(() => inventoryProblems(resolveRouters(extractRouters([source])), exactInventory), source.file).toThrow(
          /renders imported component (NestedRoutes|nestedRoutes) from third-party-router in wildcard route \/known\/\*/,
        )
      }

      const unreadable = {
        file: 'src/unreadable-route-component-prop.tsx',
        code: `import { Route, Routes } from 'react-router-dom'
export function Shell() {
  return <Routes><Route path="/known/*" Component={resolveComponent()} /></Routes>
}`,
      }
      expect(() => extractRouters([unreadable])).toThrow(/Component prop the route inventory cannot read in wildcard route \/known\/\*/)

      const parameter = {
        file: 'src/parameter-route-component-prop.tsx',
        code: `import { Route, Routes } from 'react-router-dom'
export function Shell({ Page }: { Page: React.ComponentType }) {
  return <Routes><Route path="/known/*" Component={Page} /></Routes>
}`,
      }
      expect(() => extractRouters([parameter])).toThrow(/Component prop the route inventory cannot read in wildcard route \/known\/\*/)

      const localFunction = {
        file: 'src/local-route-component-prop.tsx',
        code: `import { Route, Routes } from 'react-router-dom'
function KnownPage() { return <main /> }
export function Shell() { return <Routes><Route path="/known/*" Component={KnownPage} /></Routes> }`,
      }
      expect(resolveRouters(extractRouters([localFunction]))[0].handles.map(label)).toEqual(['Shell /known/*'])

      const unrelatedParameter = {
        file: 'src/unrelated-component-parameter.tsx',
        code: `import { Route, Routes } from 'react-router-dom'
function Page() { return <main>Known page</main> }
function Unrelated({ Page }: { Page: React.ComponentType }) { return <Page /> }
export function Shell() { return <Routes><Route path="/known/*" element={<Page />} /></Routes> }`,
      }
      expect(resolveRouters(extractRouters([unrelatedParameter]))[0].handles.map(label)).toEqual(['Shell /known/*'])
    })

    it('fails closed when a local wildcard fallback renders a runtime registry component', () => {
      const source = {
        file: 'src/runtime-registry-fallback.tsx',
        code: `import { Route, Routes } from 'react-router-dom'
const Page = window.routeRegistry.current
function Fallback() { return <Page /> }
export function Shell() { return <Routes><Route path="/known/*" element={<Fallback />} /></Routes> }`,
      }
      expect(() => extractRouters([source])).toThrow(/unreadable element prop in wildcard route \/known\/\*/)
    })

    it('fails closed for unreadable local component render trees', () => {
      const sources = [
        {
          file: 'src/local-fallback-renders-package-route.tsx',
          code: `import { Route, Routes } from 'react-router-dom'
import { NestedRoutes } from 'third-party-router'
function Fallback() { return <NestedRoutes /> }
export function Shell() { return <Routes><Route path="/known/*" element={<Fallback />} /></Routes> }`,
        },
        {
          file: 'src/local-class-fallback-registry.tsx',
          code: `import * as React from 'react'
import { Route, Routes } from 'react-router-dom'
class Fallback extends React.Component { render() { const Page = window.routeRegistry.current; return <Page /> } }
export function Shell() { return <Routes><Route path="/known/*" element={<Fallback />} /></Routes> }`,
        },
        {
          file: 'src/local-factory-fallback-registry.tsx',
          code: `import * as React from 'react'
import { Route, Routes } from 'react-router-dom'
function Fallback() { return React.createElement(window.routeRegistry.current) }
export function Shell() { return <Routes><Route path="/known/*" element={<Fallback />} /></Routes> }`,
        },
        {
          file: 'src/local-helper-fallback-registry.tsx',
          code: `import * as React from 'react'
import { Route, Routes } from 'react-router-dom'
function getFallbackContent() {
  const Page = window.routeRegistry.current
  const content = React.createElement(Page)
  return content
}
function Fallback() { return <main>{getFallbackContent()}</main> }
export function Shell() { return <Routes><Route path="/known/*" element={<Fallback />} /></Routes> }`,
        },
        {
          file: 'src/local-map-fallback-parameter.tsx',
          code: `import { Route, Routes } from 'react-router-dom'
function Fallback({ pages }: { pages: React.ComponentType[] }) {
  return <main>{pages.map((Page, index) => <Page key={index} />)}</main>
}
export function Shell() { return <Routes><Route path="/known/*" element={<Fallback pages={[]} />} /></Routes> }`,
        },
        {
          file: 'src/local-destructured-shadow-fallback.tsx',
          code: `import { Route, Routes } from 'react-router-dom'
function Page() { return <main /> }
function Fallback() { const { Page } = window.routeRegistry; return <Page /> }
export function Shell() { return <Routes><Route path="/known/*" element={<Fallback />} /></Routes> }`,
        },
        {
          file: 'src/local-class-field-fallback-registry.tsx',
          code: `import * as React from 'react'
import { Route, Routes } from 'react-router-dom'
class Fallback extends React.Component { render = () => { const Page = window.routeRegistry.current; return <Page /> } }
export function Shell() { return <Routes><Route path="/known/*" element={<Fallback />} /></Routes> }`,
        },
        {
          file: 'src/local-inherited-render-fallback-registry.tsx',
          code: `import * as React from 'react'
import { Route, Routes } from 'react-router-dom'
class Base extends React.Component { render() { const Page = window.routeRegistry.current; return <Page /> } }
class Fallback extends Base {}
export function Shell() { return <Routes><Route path="/known/*" element={<Fallback />} /></Routes> }`,
        },
      ]

      for (const source of sources) {
        expect(() => resolveRouters(extractRouters([source])), source.file).toThrow(
          /(?:unreadable element prop in wildcard route \/known\/\*|renders imported component .* in wildcard route \/known\/\*)/,
        )
      }
    })

    it('requires an imported local wildcard component to provide its own named route table', () => {
      const fixtureRoot = mkdtempSync(join(tmpdir(), 'edgewatch-local-wildcard-component-'))
      const sourceDirectory = join(fixtureRoot, 'src')
      mkdirSync(sourceDirectory, { recursive: true })
      const shellPath = join(sourceDirectory, 'Shell.tsx')
      const fallbackPath = join(sourceDirectory, 'Fallback.tsx')

      try {
        writeFileSync(shellPath, `import { Route, Routes } from 'react-router-dom'
import { Fallback } from './Fallback'
export function Shell() { return <Routes><Route path="/known/*" element={<Fallback />} /></Routes> }
`)
        writeFileSync(fallbackPath, `export function Fallback() { const Page = window.routeRegistry.current; return <Page /> }
`)
        expect(() => resolveRouters(extractRouters(sourceFiles(sourceDirectory, fixtureRoot), fixtureRoot))).toThrow(
          /wildcard route \/known\/\* renders local component Fallback without a statically named nested <Routes>/,
        )

        writeFileSync(fallbackPath, `import { Route, Routes } from 'react-router-dom'
export function Fallback() { return <Routes><Route path="child" element={<p>Child</p>} /></Routes> }
`)
        const routers = resolveRouters(extractRouters(sourceFiles(sourceDirectory, fixtureRoot), fixtureRoot))
        expect(matchRoutes(routers.find(router => router.name === 'Shell')!.objects, '/known/child')).not.toBeNull()
      } finally {
        rmSync(fixtureRoot, { recursive: true, force: true })
      }
    })

    it('tracks local imported component provenance through value aliases', () => {
      const fixtureRoot = mkdtempSync(join(tmpdir(), 'edgewatch-local-wildcard-alias-'))
      const sourceDirectory = join(fixtureRoot, 'src')
      mkdirSync(sourceDirectory, { recursive: true })

      try {
        writeFileSync(join(sourceDirectory, 'Shell.tsx'), `import { Route, Routes } from 'react-router-dom'
import { Fallback as ImportedFallback } from './Fallback'
const Alias = ImportedFallback
export function Shell() { return <Routes><Route path="/known/*" element={<Alias />} /></Routes> }
`)
        writeFileSync(join(sourceDirectory, 'Fallback.tsx'), `export function Fallback() { const Page = window.routeRegistry.current; return <Page /> }
`)

        expect(() => resolveRouters(extractRouters(sourceFiles(sourceDirectory, fixtureRoot), fixtureRoot))).toThrow(
          /wildcard route \/known\/\* renders local component Fallback without a statically named nested <Routes>/,
        )

        writeFileSync(join(sourceDirectory, 'Fallback.tsx'), `import { Route, Routes } from 'react-router-dom'
export function Fallback() { return <Routes><Route path="child" element={<p>Child</p>} /></Routes> }
`)
        const routers = resolveRouters(extractRouters(sourceFiles(sourceDirectory, fixtureRoot), fixtureRoot))
        expect(matchRoutes(routers.find(router => router.name === 'Shell')!.objects, '/known/child')).not.toBeNull()
      } finally {
        rmSync(fixtureRoot, { recursive: true, force: true })
      }
    })

    it('attaches renamed local component exports to their declaration route table', () => {
      const fixtureRoot = mkdtempSync(join(tmpdir(), 'edgewatch-renamed-local-component-export-'))
      const sourceDirectory = join(fixtureRoot, 'src')
      mkdirSync(sourceDirectory, { recursive: true })

      try {
        writeFileSync(join(sourceDirectory, 'Shell.tsx'), `import { Route, Routes } from 'react-router-dom'
import { Fallback as ImportedFallback } from './Fallback'
export function Shell() { return <Routes><Route path="/known/*" element={<ImportedFallback />} /></Routes> }
`)
        writeFileSync(join(sourceDirectory, 'Fallback.tsx'), `import { Route, Routes } from 'react-router-dom'
function RuntimeFallback() { return <Routes><Route path="child" element={<p>Child</p>} /></Routes> }
export { RuntimeFallback as Fallback }
`)

        const routers = resolveRouters(extractRouters(sourceFiles(sourceDirectory, fixtureRoot), fixtureRoot))
        expect(matchRoutes(routers.find(router => router.name === 'Shell')!.objects, '/known/child')).not.toBeNull()
      } finally {
        rmSync(fixtureRoot, { recursive: true, force: true })
      }
    })

    it('keeps unreadable local re-export provenance distinct from a same-named safe route table', () => {
      const fixtureRoot = mkdtempSync(join(tmpdir(), 'edgewatch-renamed-unreadable-local-export-'))
      const sourceDirectory = join(fixtureRoot, 'src')
      mkdirSync(sourceDirectory, { recursive: true })

      try {
        writeFileSync(join(sourceDirectory, 'Shell.tsx'), `import { Route, Routes } from 'react-router-dom'
import { Fallback as ImportedFallback } from './runtime-routes'
import { Fallback as SafeFallback } from './safe-routes'
export function Shell() { return <Routes><Route path="/known/*" element={<ImportedFallback />} /></Routes> }
`)
        writeFileSync(join(sourceDirectory, 'runtime-routes.tsx'), `import { Route, Routes } from 'react-router-dom'
function RuntimeFallback() {
  const Page = window.routeRegistry.current
  return <Routes><Route path="child" element={<Page />} /></Routes>
}
export { RuntimeFallback as Fallback }
`)
        writeFileSync(join(sourceDirectory, 'safe-routes.tsx'), `import { Route, Routes } from 'react-router-dom'
export function Fallback() { return <Routes><Route path="child" element={<p>Safe</p>} /></Routes> }
`)

        expect(() => resolveRouters(extractRouters(sourceFiles(sourceDirectory, fixtureRoot), fixtureRoot))).toThrow(
          /renders imported component ImportedFallback from local module \.\/runtime-routes export Fallback in wildcard route \/known\/\*/,
        )
      } finally {
        rmSync(fixtureRoot, { recursive: true, force: true })
      }
    })

    it('does not attach a local component without a route table to a same-named table elsewhere', () => {
      const fixtureRoot = mkdtempSync(join(tmpdir(), 'edgewatch-unreadable-component-name-collision-'))
      const sourceDirectory = join(fixtureRoot, 'src')
      mkdirSync(sourceDirectory, { recursive: true })

      try {
        writeFileSync(join(sourceDirectory, 'Shell.tsx'), `import { Route, Routes } from 'react-router-dom'
import { Fallback as ImportedFallback } from './runtime-fallback'
import { Fallback as SafeFallback } from './safe-fallback'
export function Shell() {
  return <Routes>
    <Route path="/known/*" element={<ImportedFallback />} />
    <Route path="/safe/*" element={<SafeFallback />} />
  </Routes>
}
`)
        writeFileSync(join(sourceDirectory, 'runtime-fallback.tsx'), `function Fallback() {
  const Page = window.routeRegistry.current
  return <Page />
}
export { Fallback }
`)
        writeFileSync(join(sourceDirectory, 'safe-fallback.tsx'), `import { Route, Routes } from 'react-router-dom'
export function Fallback() { return <Routes><Route path="child" element={<p>Safe</p>} /></Routes> }
`)

        expect(() => resolveRouters(extractRouters(sourceFiles(sourceDirectory, fixtureRoot), fixtureRoot))).toThrow(
          /wildcard route \/known\/\* renders local component Fallback without a statically named nested <Routes>/,
        )
      } finally {
        rmSync(fixtureRoot, { recursive: true, force: true })
      }
    })

    it('fails closed on local namespace members even when a different export is opaque', () => {
      const fixtureRoot = mkdtempSync(join(tmpdir(), 'edgewatch-local-namespace-opaque-export-'))
      const sourceDirectory = join(fixtureRoot, 'src')
      mkdirSync(sourceDirectory, { recursive: true })

      try {
        writeFileSync(join(sourceDirectory, 'Shell.tsx'), `import { Route, Routes } from 'react-router-dom'
import * as Local from './components'
export function Shell() { return <Routes><Route path="/known/*" element={<Local.Fallback />} /></Routes> }
`)
        writeFileSync(join(sourceDirectory, 'components.tsx'), `import { Route, Routes } from 'react-router-dom'
export function Fallback() { return <Routes><Route path="child" element={<p>Child</p>} /></Routes> }
export { Other } from 'third-party-router'
`)

        expect(() => resolveRouters(extractRouters(sourceFiles(sourceDirectory, fixtureRoot), fixtureRoot))).toThrow(
          /renders imported component Local\.Fallback from .+ in wildcard route \/known\/\*/,
        )
      } finally {
        rmSync(fixtureRoot, { recursive: true, force: true })
      }
    })

    it('rejects imported local route tables with unreadable component render trees', () => {
      const fixtureRoot = mkdtempSync(join(tmpdir(), 'edgewatch-unreadable-local-router-'))
      const sourceDirectory = join(fixtureRoot, 'src')
      mkdirSync(sourceDirectory, { recursive: true })

      try {
        writeFileSync(join(sourceDirectory, 'Shell.tsx'), `import { Route, Routes } from 'react-router-dom'
import { Fallback } from './Fallback'
export function Shell() { return <Routes><Route path="/known/*" element={<Fallback />} /></Routes> }
`)
        writeFileSync(join(sourceDirectory, 'Fallback.tsx'), `import { Route, Routes } from 'react-router-dom'
const Page = window.routeRegistry.current
export function Fallback() { return <><Routes><Route path="child" element={<p>Child</p>} /></Routes><Page /></> }
`)

        expect(() => resolveRouters(extractRouters(sourceFiles(sourceDirectory, fixtureRoot), fixtureRoot))).toThrow(
          /renders imported component Fallback from local module \.\/Fallback export Fallback in wildcard route \/known\/\*/,
        )
      } finally {
        rmSync(fixtureRoot, { recursive: true, force: true })
      }
    })

    it('fails closed when an imported local route component uses an unreadable wrapper', () => {
      const fixtureRoot = mkdtempSync(join(tmpdir(), 'edgewatch-wrapped-local-router-'))
      const sourceDirectory = join(fixtureRoot, 'src')
      mkdirSync(sourceDirectory, { recursive: true })

      try {
        writeFileSync(join(sourceDirectory, 'Shell.tsx'), `import { Route, Routes } from 'react-router-dom'
import { Fallback } from './Fallback'
export function Shell() { return <Routes><Route path="/known/*" element={<Fallback />} /></Routes> }
`)
        writeFileSync(join(sourceDirectory, 'Fallback.tsx'), `import * as React from 'react'
import { Route, Routes } from 'react-router-dom'
export const Fallback = React.memo(function Fallback() {
  const Page = window.routeRegistry.current
  return <><Routes><Route path="child" element={<p>Child</p>} /></Routes><Page /></>
})
`)

        expect(() => resolveRouters(extractRouters(sourceFiles(sourceDirectory, fixtureRoot), fixtureRoot))).toThrow(
          /renders imported component Fallback from local module \.\/Fallback export Fallback in wildcard route \/known\/\*/,
        )
      } finally {
        rmSync(fixtureRoot, { recursive: true, force: true })
      }
    })

    it('fails closed for local namespace member components on wildcard routes', () => {
      const fixtureRoot = mkdtempSync(join(tmpdir(), 'edgewatch-local-wildcard-namespace-'))
      const sourceDirectory = join(fixtureRoot, 'src')
      mkdirSync(sourceDirectory, { recursive: true })

      try {
        writeFileSync(join(sourceDirectory, 'Shell.tsx'), `import { Route, Routes } from 'react-router-dom'
import * as Local from './Fallback'
export function Shell() { return <Routes><Route path="/known/*" element={<Local.Fallback />} /></Routes> }
`)
        writeFileSync(join(sourceDirectory, 'Fallback.tsx'), `export function Fallback() { const Page = window.routeRegistry.current; return <Page /> }
`)

        expect(() => resolveRouters(extractRouters(sourceFiles(sourceDirectory, fixtureRoot), fixtureRoot))).toThrow(
          /renders imported component Local\.Fallback from .+ in wildcard route \/known\/\*/,
        )
      } finally {
        rmSync(fixtureRoot, { recursive: true, force: true })
      }
    })

    it('does not treat local component metadata reads as rendered route aliases', () => {
      const fixtureRoot = mkdtempSync(join(tmpdir(), 'edgewatch-local-component-metadata-'))
      const sourceDirectory = join(fixtureRoot, 'src')
      mkdirSync(sourceDirectory, { recursive: true })

      try {
        writeFileSync(join(sourceDirectory, 'Shell.tsx'), `import { Route, Routes } from 'react-router-dom'
import { Fallback } from './fallback-routes'
function MetadataPanel() { const label = Fallback.displayName; return <main>{label}</main> }
export function Shell() { return <Routes><Route path="/known/*" element={<MetadataPanel />} /></Routes> }
`)
        writeFileSync(join(sourceDirectory, 'fallback-routes.tsx'), `import { Route, Routes } from 'react-router-dom'
export function Fallback() { return <Routes><Route path="child" element={<p>Child</p>} /></Routes> }
`)
        const routers = resolveRouters(extractRouters(sourceFiles(sourceDirectory, fixtureRoot), fixtureRoot))
        expect(routers.find(router => router.name === 'Shell')!.handles.map(label)).toEqual(['Shell /known/*'])
      } finally {
        rmSync(fixtureRoot, { recursive: true, force: true })
      }
    })

    it('rejects unresolved local imports forwarded through JSX expression children', () => {
      const source = {
        file: 'src/unresolved-import-jsx-child.tsx',
        code: `import { Route, Routes } from 'react-router-dom'
import HiddenRoutes from './unreadable-router.js'
function Fallback() { return <div>{HiddenRoutes}</div> }
export function Shell() { return <Routes><Route path="/known/*" element={<Fallback />} /></Routes> }`,
      }
      expect(() => extractRouters([source])).toThrow(/forwards values from unresolved local module \.\/unreadable-router\.js/)
    })

    it('rejects trailing-star paths that React Router normalizes to a splat', () => {
      expect(matchRoutes([{ path: '/known*' }], '/known/child')).not.toBeNull()
      const source = {
        file: 'src/non-canonical-splat.tsx',
        code: `import { Route, Routes } from 'react-router-dom'
import { NestedRoutes } from 'third-party-router'
export function Shell() { return <Routes><Route path="/known*" element={<NestedRoutes />} /></Routes> }`,
      }
      expect(() => extractRouters([source])).toThrow(/non-canonical wildcard path \/known\*; put the splat '\*' in its own final path segment/)
    })

    it('checks wildcard error and hydration render props for opaque components', () => {
      const routes = [
        {
          label: 'ErrorBoundary',
          prop: 'ErrorBoundary={NestedRoutes}',
        },
        {
          label: 'errorElement',
          prop: 'errorElement={<NestedRoutes />}',
        },
        {
          label: 'HydrateFallback',
          prop: 'HydrateFallback={NestedRoutes}',
        },
        {
          label: 'hydrateFallbackElement',
          prop: 'hydrateFallbackElement={<NestedRoutes />}',
        },
      ]
      for (const { label: prop, prop: value } of routes) {
        const source = {
          file: `src/wildcard-${prop}.tsx`,
          code: `import { Route, Routes } from 'react-router-dom'
import { NestedRoutes } from 'third-party-router'
export function Shell() { return <Routes><Route path="/known/*" ${value} /></Routes> }`,
        }
        expect(() => resolveRouters(extractRouters([source])), prop).toThrow(
          /renders imported component NestedRoutes from third-party-router in wildcard route \/known\/\*/,
        )
      }

      const lazy = {
        file: 'src/wildcard-lazy-route-prop.tsx',
        code: `import { Route, Routes } from 'react-router-dom'
export function Shell() { return <Routes><Route path="/known/*" lazy={loadRoute} /></Routes> }`,
      }
      expect(() => extractRouters([lazy])).toThrow(/uses a lazy prop in wildcard route \/known\/\*/)
    })

    it('rejects runtime values for wildcard element props', () => {
      const source = {
        file: 'src/wildcard-runtime-element.tsx',
        code: `import { Route, Routes } from 'react-router-dom'
export function Shell({ page }: { page: React.ReactNode }) {
  return <Routes><Route path="/known/*" element={page} /></Routes>
}`,
      }
      expect(() => extractRouters([source])).toThrow(/unreadable element prop in wildcard route \/known\/\*/)

      const literal = {
        file: 'src/wildcard-literal-element.tsx',
        code: `import { Route, Routes } from 'react-router-dom'
export function Shell({ visible }: { visible: boolean }) {
  return <Routes><Route path="/known/*" element={visible ? <main /> : null} /></Routes>
}`,
      }
      expect(resolveRouters(extractRouters([literal]))[0].handles.map(label)).toEqual(['Shell /known/*'])

      const parameterComponent = {
        file: 'src/wildcard-parameter-component.tsx',
        code: `import { Route, Routes } from 'react-router-dom'
export function Shell({ Page }: { Page: React.ComponentType }) {
  return <Routes><Route path="/known/*" element={<Page />} /></Routes>
}`,
      }
      expect(() => extractRouters([parameterComponent])).toThrow(/unreadable element prop in wildcard route \/known\/\*/)

      const forwardedParameter = {
        file: 'src/wildcard-parameter-component-prop.tsx',
        code: `import { Route, Routes } from 'react-router-dom'
function RouteHost({ view }: { view: React.ComponentType }) { return <main /> }
export function Shell({ Page }: { Page: React.ComponentType }) {
  const selectedPage = Page
  return <Routes><Route path="/known/*" element={<RouteHost view={selectedPage} />} /></Routes>
}`,
      }
      expect(() => extractRouters([forwardedParameter])).toThrow(/unreadable element prop in wildcard route \/known\/\*/)

      const opaqueCallResult = {
        file: 'src/wildcard-opaque-call-result.tsx',
        code: `import { Route, Routes } from 'react-router-dom'
function RouteHost({ view }: { view: React.ComponentType }) { return React.createElement(view) }
function getRuntimePage(): React.ComponentType { return window.routeRegistry.current }
export function Shell() {
  return <Routes><Route path="/known/*" element={<RouteHost view={getRuntimePage()} />} /></Routes>
}`,
      }
      expect(() => extractRouters([opaqueCallResult])).toThrow(/unreadable element prop in wildcard route \/known\/\*/)

      const eventCallback = {
        file: 'src/wildcard-event-callback.tsx',
        code: `import { Route, Routes } from 'react-router-dom'
function RouteHost({ onClick }: { onClick: (event: Event) => void }) { return <button onClick={onClick} /> }
function handleClick(event: Event) { void event }
export function Shell() {
  return <Routes><Route path="/known/*" element={<RouteHost onClick={(event) => handleClick(event)} />} /></Routes>
}`,
      }
      expect(resolveRouters(extractRouters([eventCallback]))[0].handles.map(label)).toEqual(['Shell /known/*'])
    })

    it('fails the full inventory check when a factory-created package component could own wildcard routes', () => {
      const exactInventory: Inventory = {
        consoleRoutes: [{ path: '/known/child', scope: 'unit' }],
        surfaces: [],
        scopeRouters: { unit: ['Shell'], platform: [], shared: [] },
        exclusions: [],
        tabKeys: [],
      }
      const sources = [
        {
          file: 'src/external-factory-routes.tsx',
          code: `import { createElement } from 'react'
import { Route, Routes } from 'react-router-dom'
import { NestedRoutes } from 'third-party-router'
export function Shell() {
  return <Routes><Route path="/known/*" element={createElement(NestedRoutes)} /></Routes>
}`,
        },
        {
          file: 'src/external-factory-route-aliases.tsx',
          code: `import * as React from 'react'
import { Route, Routes } from 'react-router-dom'
import { NestedRoutes as PackageNestedRoutes } from 'third-party-router'
const create = React.createElement
const NestedRoutes = PackageNestedRoutes
export function Shell() {
  return <Routes><Route path="/known/*" element={create(NestedRoutes)} /></Routes>
}`,
        },
        {
          file: 'src/external-factory-route-import-aliases.tsx',
          code: `import { createElement as makeElement } from 'react'
import { Route, Routes } from 'react-router-dom'
import { NestedRoutes } from 'third-party-router'
const make = makeElement
const Routed = NestedRoutes
export function Shell() {
  return <Routes><Route path="/known/*" element={make(Routed)} /></Routes>
}`,
        },
        {
          file: 'src/external-factory-lowercase-component-alias.tsx',
          code: `import { createElement as makeElement } from 'react'
import { Route, Routes } from 'react-router-dom'
import { NestedRoutes as nestedRoutes } from 'third-party-router'
const make = makeElement
const localRoutes = nestedRoutes
export function Shell() {
  return <Routes><Route path="/known/*" element={make(localRoutes)} /></Routes>
}`,
        },
        {
          file: 'src/external-factory-component-prop.tsx',
          code: `import { Route, Routes } from 'react-router-dom'
import { createElement as make } from 'react'
import { NestedRoutes as nestedRoutes } from 'third-party-router'
function RouteHost({ Component }: { Component: React.ComponentType }) {
  return <Component />
}
export function Shell() {
  return <Routes>
    <Route path="/known/*" element={make(RouteHost, { Component: nestedRoutes })} />
  </Routes>
}`,
        },
        {
          file: 'src/external-factory-component-prop-alias.tsx',
          code: `import { Route, Routes } from 'react-router-dom'
import { createElement as make } from 'react'
import { NestedRoutes as nestedRoutes } from 'third-party-router'
const nestedRoutesAlias = nestedRoutes
function RouteHost({ Component }: { Component: React.ComponentType }) {
  return <Component />
}
export function Shell() {
  return <Routes>
    <Route path="/known/*" element={make(RouteHost, { Component: nestedRoutesAlias as React.ComponentType })} />
  </Routes>
}`,
        },
      ]

      // A direct child entry can match the catch-all path while the third-party
      // component hides still deeper nested routes from the inventory.
      for (const source of sources) {
        expect(
          () => inventoryProblems(resolveRouters(extractRouters([source])), exactInventory),
          source.file,
        ).toThrow(/(?:renders imported component (?:NestedRoutes|PackageNestedRoutes|Routed|localRoutes|nestedRoutes|nestedRoutesAlias) from third-party-router in wildcard route \/known\/\*; the console route inventory cannot inspect whether it owns nested <Routes>|unreadable element prop in wildcard route \/known\/\*)/)
      }
    })

    it('tracks lowercase opaque package components forwarded through JSX props', () => {
      const exactInventory: Inventory = {
        consoleRoutes: [{ path: '/known/child', scope: 'unit' }],
        surfaces: [],
        scopeRouters: { unit: ['Shell'], platform: [], shared: [] },
        exclusions: [],
        tabKeys: [],
      }
      const source = {
        file: 'src/external-jsx-component-prop.tsx',
        code: `import { Route, Routes } from 'react-router-dom'
import { NestedRoutes as nestedRoutes } from 'third-party-router'
function RouteHost({ Component }: { Component: React.ComponentType }) { return <Component /> }
export function Shell() {
  return <Routes><Route path="/known/*" element={<RouteHost Component={nestedRoutes} />} /></Routes>
}`,
      }

      expect(() => inventoryProblems(resolveRouters(extractRouters([source])), exactInventory)).toThrow(
        /(?:renders imported component nestedRoutes from third-party-router in wildcard route \/known\/\*|unreadable element prop in wildcard route \/known\/\*)/,
      )
    })

    it('tracks opaque package components in arbitrary JSX props and spread values', () => {
      const exactInventory: Inventory = {
        consoleRoutes: [{ path: '/known/child', scope: 'unit' }],
        surfaces: [],
        scopeRouters: { unit: ['Shell'], platform: [], shared: [] },
        exclusions: [],
        tabKeys: [],
      }
      const sources = [
        {
          file: 'src/external-arbitrary-jsx-prop.tsx',
          code: `import * as React from 'react'
import { Route, Routes } from 'react-router-dom'
import { NestedRoutes as nestedRoutes } from 'third-party-router'
function RouteHost({ view }: { view: React.ComponentType }) { return React.createElement(view) }
export function Shell() {
  return <Routes><Route path="/known/*" element={<RouteHost view={nestedRoutes} />} /></Routes>
}`,
        },
        {
          file: 'src/external-jsx-spread-prop.tsx',
          code: `import * as React from 'react'
import { Route, Routes } from 'react-router-dom'
import { NestedRoutes as nestedRoutes } from 'third-party-router'
function RouteHost({ view }: { view: React.ComponentType }) { return React.createElement(view) }
export function Shell() {
  return <Routes><Route path="/known/*" element={<RouteHost {...{ view: nestedRoutes }} />} /></Routes>
}`,
        },
        {
          file: 'src/external-call-argument.tsx',
          code: `import { Route, Routes } from 'react-router-dom'
import { NestedRoutes as nestedRoutes } from 'third-party-router'
function forward(component: React.ComponentType) { return component }
export function Shell() {
  return <Routes><Route path="/known/*" element={forward(nestedRoutes)} /></Routes>
}`,
        },
      ]

      for (const source of sources) {
        const expected = /(?:unreadable element prop in wildcard route \/known\/\*|renders imported component nestedRoutes from third-party-router in wildcard route \/known\/\*)/
        expect(() => inventoryProblems(resolveRouters(extractRouters([source])), exactInventory), source.file).toThrow(expected)
      }
    })

    it('preserves opaque package provenance from both logical expression operands', () => {
      const exactInventory: Inventory = {
        consoleRoutes: [{ path: '/known/child', scope: 'unit' }],
        surfaces: [],
        scopeRouters: { unit: ['Shell'], platform: [], shared: [] },
        exclusions: [],
        tabKeys: [],
      }
      const source = {
        file: 'src/external-logical-component-prop.tsx',
        code: `import { createElement as make } from 'react'
import { Route, Routes } from 'react-router-dom'
import { NestedRoutes as nestedRoutes } from 'third-party-router'
const target = nestedRoutes || null
function RouteHost({ Component }: { Component: React.ComponentType }) { return <Component /> }
export function Shell() {
  return <Routes><Route path="/known/*" element={make(RouteHost, { Component: target })} /></Routes>
}`,
      }

      expect(() => inventoryProblems(resolveRouters(extractRouters([source])), exactInventory)).toThrow(
        /(?:renders imported component target from third-party-router in wildcard route \/known\/\*|unreadable element prop in wildcard route \/known\/\*)/,
      )
    })

    it('tracks opaque dynamic package components produced by React.lazy', () => {
      const exactInventory: Inventory = {
        consoleRoutes: [{ path: '/known/child', scope: 'unit' }],
        surfaces: [],
        scopeRouters: { unit: ['Shell'], platform: [], shared: [] },
        exclusions: [],
        tabKeys: [],
      }
      const sources = [
        {
          file: 'src/dynamic-external-route-component.tsx',
          code: `import * as React from 'react'
import { Route, Routes } from 'react-router-dom'
const NestedRoutes = React.lazy(() => import('third-party-router'))
export function Shell() {
  return <Routes><Route path="/known/*" element={<NestedRoutes />} /></Routes>
}`,
        },
        {
          file: 'src/dynamic-external-route-lazy-alias.tsx',
          code: `import { lazy as defer } from 'react'
import { Route, Routes } from 'react-router-dom'
const NestedRoutes = defer(() => import('third-party-router'))
export function Shell() {
  return <Routes><Route path="/known/*" element={<NestedRoutes />} /></Routes>
}`,
        },
        {
          file: 'src/dynamic-external-inline-route-component.tsx',
          code: `import * as React from 'react'
import { Route, Routes } from 'react-router-dom'
export function Shell() {
  return <Routes><Route path="/known/*" element={React.createElement(React.lazy(() => import('third-party-router')))} /></Routes>
}`,
        },
        {
          file: 'src/dynamic-external-named-loader.tsx',
          code: `import * as React from 'react'
import { Route, Routes } from 'react-router-dom'
const load = () => import('third-party-router')
const NestedRoutes = React.lazy(load)
export function Shell() {
  return <Routes><Route path="/known/*" element={<NestedRoutes />} /></Routes>
}`,
        },
        {
          file: 'src/dynamic-external-loader-alias.tsx',
          code: `import * as React from 'react'
import { Route, Routes } from 'react-router-dom'
function loadRoutes() { return import('third-party-router') }
const load = loadRoutes
const NestedRoutes = React.lazy(load)
export function Shell() {
  return <Routes><Route path="/known/*" element={<NestedRoutes />} /></Routes>
}`,
        },
      ]

      for (const source of sources) {
        expect(() => inventoryProblems(resolveRouters(extractRouters([source])), exactInventory), source.file).toThrow(
          /renders imported component (?:NestedRoutes|React\.lazy) from third-party-router in wildcard route \/known\/\*/,
        )
      }
    })

    it('fails closed when local export-barrel provenance exceeds its work budget', () => {
      const fixtureRoot = mkdtempSync(join(tmpdir(), 'edgewatch-route-export-provenance-budget-'))
      const sourceDirectory = join(fixtureRoot, 'src')
      mkdirSync(sourceDirectory, { recursive: true })
      writeFileSync(join(sourceDirectory, 'Shell.tsx'), `import { Route, Routes } from 'react-router-dom'
import { NestedRoutes0 as Fallback } from './barrel'
export function Shell() { return <Routes><Route path="*" element={<Fallback />} /></Routes> }
`)
      writeFileSync(join(sourceDirectory, 'base.ts'), `export { ${Array.from({ length: 100 }, (_unused, index) => `NestedRoutes as NestedRoutes${index}`).join(', ')} } from 'third-party-router'\n`)
      writeFileSync(join(sourceDirectory, 'barrel.ts'), `${Array.from({ length: 510 }, () => "export * from './base'").join('\n')}\n`)

      try {
        const sources = sourceFiles(sourceDirectory, fixtureRoot)
        expect(() => extractRouters(sources, fixtureRoot)).toThrow(
          /local component export provenance exceeded 50000 propagation steps/,
        )
      } finally {
        rmSync(fixtureRoot, { recursive: true, force: true })
      }
    })

    it('tracks opaque component provenance from runtime package loads and lazy promise aliases', () => {
      const exactInventory: Inventory = {
        consoleRoutes: [{ path: '/known/child', scope: 'unit' }],
        surfaces: [],
        scopeRouters: { unit: ['Shell'], platform: [], shared: [] },
        exclusions: [],
        tabKeys: [],
      }
      const sources = [
        {
          file: 'src/runtime-import-default-component.tsx',
          code: `import { Route, Routes } from 'react-router-dom'
const { default: NestedRoutes } = await import('third-party-router')
export function Shell() { return <Routes><Route path="/known/*" element={<NestedRoutes />} /></Routes> }`,
        },
        {
          file: 'src/runtime-require-component.tsx',
          code: `import { Route, Routes } from 'react-router-dom'
const NestedRoutes = require('third-party-router')
export function Shell() { return <Routes><Route path="/known/*" element={<NestedRoutes />} /></Routes> }`,
        },
        {
          file: 'src/runtime-require-destructure-component.tsx',
          code: `import { Route, Routes } from 'react-router-dom'
const { NestedRoutes: routes } = require('third-party-router')
export function Shell() { return <Routes><Route path="/known/*" element={<RouteHost Component={routes} />} /></Routes> }
function RouteHost({ Component }: { Component: React.ComponentType }) { return <Component /> }`,
        },
        {
          file: 'src/runtime-lazy-promise-alias.tsx',
          code: `import * as React from 'react'
import { Route, Routes } from 'react-router-dom'
const routes = import('third-party-router')
const load = () => routes
const NestedRoutes = React.lazy(load)
export function Shell() { return <Routes><Route path="/known/*" element={<NestedRoutes />} /></Routes> }`,
        },
        {
          file: 'src/runtime-lazy-url-import.tsx',
          code: `import * as React from 'react'
import { Route, Routes } from 'react-router-dom'
const NestedRoutes = React.lazy(() => import('https://routes.example/router.js'))
export function Shell() { return <Routes><Route path="/known/*" element={<NestedRoutes />} /></Routes> }`,
        },
      ]

      for (const source of sources) {
        expect(() => inventoryProblems(resolveRouters(extractRouters([source])), exactInventory), source.file).toThrow(
          /(?:renders imported component (?:NestedRoutes|routes) from .* in wildcard route \/known\/\*|unreadable element prop in wildcard route \/known\/\*)/,
        )
      }
    })

    it('treats package import-map loads as opaque in wildcard lazy routes', () => {
      const source = {
        file: 'src/package-import-map-route.tsx',
        code: `import * as React from 'react'
import { Route, Routes } from 'react-router-dom'
const NestedRoutes = React.lazy(() => import('#route-tree'))
export function Shell() { return <Routes><Route path="/known/*" element={<NestedRoutes />} /></Routes> }`,
      }
      const inventory: Inventory = {
        consoleRoutes: [{ path: '/known/child', scope: 'unit' }],
        surfaces: [],
        scopeRouters: { unit: ['Shell'], platform: [], shared: [] },
        exclusions: [],
        tabKeys: [],
      }

      expect(() => inventoryProblems(resolveRouters(extractRouters([source])), inventory)).toThrow(
        /renders imported component NestedRoutes from #route-tree in wildcard route \/known\/\*/,
      )
    })

    it('fails closed on JSX components from unresolved package import-map routes', () => {
      const fixtureRoot = mkdtempSync(join(tmpdir(), 'edgewatch-package-import-map-router-'))
      const sourceDirectory = join(fixtureRoot, 'src')
      mkdirSync(sourceDirectory, { recursive: true })
      writeFileSync(join(fixtureRoot, 'package.json'), JSON.stringify({
        imports: { '#routes': './src/router-bindings.ts' },
      }))
      writeFileSync(join(sourceDirectory, 'router-bindings.ts'), `export { Route as Page, Routes as Pages } from 'react-router-dom'
`)
      writeFileSync(join(sourceDirectory, 'HiddenRoutes.tsx'), `import { Page, Pages } from '#routes'
export function HiddenRoutes() {
  return <Pages><Page path="/hidden" /></Pages>
}
`)

      try {
        const sources = sourceFiles(sourceDirectory, fixtureRoot)
        expect(() => extractRouters(sources, fixtureRoot)).toThrow(
          /uses JSX component (?:Page|Pages) from package import-map specifier #routes/,
        )
      } finally {
        rmSync(fixtureRoot, { recursive: true, force: true })
      }
    })

    it('rejects a runtime component alias that shadows a statically declared wildcard component', () => {
      const source = {
        file: 'src/shadowed-wildcard-component.tsx',
        code: `import { Route, Routes } from 'react-router-dom'
function Page() { return <main /> }
export function Shell({ runtimePage }: { runtimePage: React.ComponentType }) {
  const Page = runtimePage
  return <Routes><Route path="/known/*" Component={Page} /></Routes>
}`,
      }

      expect(() => extractRouters([source])).toThrow(/has a Component prop the route inventory cannot read in wildcard route \/known\/\*/)
    })

    it('mounts a local nested router passed to a wildcard through createElement', () => {
      const exactInventory: Inventory = {
        consoleRoutes: [{ path: '/known/child', scope: 'unit' }],
        surfaces: [
          { path: '/public', router: 'public', state: 'public', heading: '' },
          { path: '/public/unit', router: 'public', state: 'public', heading: '' },
        ],
        scopeRouters: { unit: ['Shell'], platform: [], shared: [] },
        exclusions: [],
        tabKeys: [],
      }
      const source = {
        file: 'src/create-element-local-router.tsx',
        code: `import * as React from 'react'
import { Route, Routes } from 'react-router-dom'
function NestedRoutes() { return <Routes><Route path="child" element={<main />} /></Routes> }
export function Shell() { return <Routes><Route path="/known/*" element={React.createElement(NestedRoutes)} /></Routes> }`,
      }

      expect(inventoryProblems(resolveRouters(extractRouters([source])), exactInventory)).toEqual([])
    })

    it('fails closed when a React.lazy loader callback cannot be resolved statically', () => {
      const source = {
        file: 'src/unreadable-lazy-loader.tsx',
        code: `import * as React from 'react'
import { Route, Routes } from 'react-router-dom'
const NestedRoutes = React.lazy(resolveRoutes)
export function Shell() {
  return <Routes><Route path="/known/*" element={<NestedRoutes />} /></Routes>
}`,
      }

      expect(() => extractRouters([source])).toThrow(/React\.lazy callback the route inventory cannot read/)
    })

    it('rejects a readable React.lazy callback that returns a runtime component value', () => {
      const source = {
        file: 'src/runtime-lazy-route-component.tsx',
        code: `import * as React from 'react'
import { Route, Routes } from 'react-router-dom'
const NestedRoutes = React.lazy(() => Promise.resolve({ default: window.routeRegistry.current }))
export function Shell() { return <Routes><Route path="/known/*" element={<NestedRoutes />} /></Routes> }`,
      }

      expect(() => extractRouters([source])).toThrow(/unreadable element prop in wildcard route \/known\/\*/)
    })

    it('keeps route-irrelevant package loads and readable local lazy imports allowed', () => {
      const source = {
        file: 'src/safe-dynamic-component-loads.tsx',
        code: `import * as React from 'react'
import { Route, Routes } from 'react-router-dom'
const unusedPackage = import('third-party-utility')
const LocalPage = React.lazy(() => {
  void import('third-party-utility')
  return import('./local-page')
})
export function Shell() {
  return <Routes><Route path="/known/*" element={<LocalPage />} /></Routes>
}`,
      }

      expect(resolveRouters(extractRouters([source]))[0].handles.map(label)).toEqual(['Shell /known/*'])
    })

    it('does not treat a self-mapped allowedPath as a redirect', () => {
      const inventory: Inventory = {
        consoleRoutes: [{ path: '/known', scope: 'unit', allowedPath: '/known' }],
        surfaces: [
          { path: '/public', router: 'public', state: 'public', heading: '' },
          { path: '/public/unit', router: 'public', state: 'public', heading: '' },
        ],
        scopeRouters: { unit: ['Shell'], platform: [], shared: [] },
        exclusions: [{ router: 'Shell', path: '*', reason: 'The shell fallback has no page of its own.' }],
        tabKeys: [],
      }
      const source = {
        file: 'src/self-mapped-allowed-path.tsx',
        code: `import { Navigate, Route, Routes } from 'react-router-dom'
function KnownPage() { return <main /> }
export function Shell() {
  return <Routes><Route path="/known/*" element={<KnownPage />} /><Route path="*" element={<Navigate to="/" />} /></Routes>
}`,
      }

      expect(inventoryProblems(resolveRouters(extractRouters([source])), inventory)).toEqual([
        'inventory entry unit /known reaches only the catch-all Shell /known/*; remove it, restore its route, or mark the redirect',
      ])
    })

    it('keeps external page elements on static paths and router redirects on wildcard paths', () => {
      const source = {
        file: 'src/external-presentational-page.tsx',
        code: `import { Route, Routes, Navigate } from 'react-router-dom'
import { Panel } from 'third-party-ui'
export function Shell() {
  return <Routes><Route path="/known" element={<Panel />} /><Route path="*" element={<Navigate to="/known" />} /></Routes>
}`,
      }

      expect(resolveRouters(extractRouters([source]))[0].handles.map(label)).toEqual(['Shell /known', 'Shell *'])
    })

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
      const deeplyNestedNamespaceSource = {
        file: 'src/HiddenRoutes.tsx',
        code: `import * as Router from '../router-bindings'\nexport function HiddenRoutes() { return <Router.Components.Pages><Router.Components.Page path="/hidden" /></Router.Components.Pages> }`,
      }
      expect(() => extractRouters([deeplyNestedNamespaceSource])).toThrow(/uses JSX component Router from unresolved local module \.\.\/router-bindings/)

      const unresolvedDefaultMemberSource = {
        file: 'src/HiddenRoutes.tsx',
        code: `import { Route, Routes } from 'react-router-dom'
import Router from '../unreadable-router'
export function HiddenRoutes() {
  return <Routes><Route path="/excluded/*" element={<Router.Components.Pages><Router.Components.Page path="child" /></Router.Components.Pages>} /></Routes>
}`,
      }
      expect(() => extractRouters([unresolvedDefaultMemberSource])).toThrow(/uses JSX component Router from unresolved local module \.\.\/unreadable-router/)
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

      const dynamicIndex = {
        file: 'src/dynamic-index.tsx',
        code: `import { Route, Routes } from 'react-router-dom'
export function DynamicIndex({ isIndex }: { isIndex: boolean }) { return <Routes><Route index={isIndex} path="/dynamic" /></Routes> }`,
      }
      expect(() => extractRouters([dynamicIndex])).toThrow(/non-literal index prop/)
    })

    it('preserves case-sensitive route matching and rejects Routes location overrides', () => {
      const source = {
        file: 'src/case-sensitive-routes.tsx',
        code: `import { Route, Routes } from 'react-router-dom'
export function Shell() { return <Routes><Route path="/Admin/*" caseSensitive element={<p />} /><Route path="/Reports/*" caseSensitive={false} element={<p />} /></Routes> }`,
      }
      const router = resolveRouters(extractRouters([source]))[0]
      expect(matchRoutes(router.objects, '/Admin/users')).not.toBeNull()
      expect(matchRoutes(router.objects, '/admin/users')).toBeNull()
      expect(router.objects[1].caseSensitive).toBe(false)

      const dynamicCase = {
        file: 'src/dynamic-case-sensitive.tsx',
        code: `import { Route, Routes } from 'react-router-dom'
export function Shell({ strict }: { strict: boolean }) { return <Routes><Route path="/Admin" caseSensitive={strict} /></Routes> }`,
      }
      expect(() => extractRouters([dynamicCase])).toThrow(/non-literal caseSensitive prop/)

      const overriddenLocation = {
        file: 'src/routes-location-override.tsx',
        code: `import { Route, Routes } from 'react-router-dom'
export function Shell() { return <Routes location="/other"><Route path="/known" /></Routes> }`,
      }
      expect(() => extractRouters([overriddenLocation])).toThrow(/uses a location prop; the route inventory must audit the browser location/)
    })

    it('accepts default component imports when their local TypeScript module is readable', () => {
      const fixtureRoot = mkdtempSync(join(tmpdir(), 'edgewatch-readable-router-import-'))
      const sourceDirectory = join(fixtureRoot, 'src')
      mkdirSync(sourceDirectory, { recursive: true })
      writeFileSync(join(sourceDirectory, 'Shell.tsx'), `import { Route, Routes } from 'react-router-dom'
import Router from './ReadableRouter'
export function Shell() { return <Routes><Route path="/safe" element={<Router />} /></Routes> }
`)
      writeFileSync(join(sourceDirectory, 'ReadableRouter.tsx'), `import { Route, Routes } from 'react-router-dom'
export default function Router() { return <Routes><Route path="/safe/child" element={<p />} /></Routes> }
`)

      try {
        const sources = sourceFiles(sourceDirectory, fixtureRoot)
        expect(extractRouters(sources, fixtureRoot).map(router => router.name)).toEqual(expect.arrayContaining(['Shell', 'Router']))
      } finally {
        rmSync(fixtureRoot, { recursive: true, force: true })
      }
    })

    it('does not substitute a TypeScript sibling for an explicitly imported JSX module', () => {
      const fixtureRoot = mkdtempSync(join(tmpdir(), 'edgewatch-explicit-jsx-router-import-'))
      const sourceDirectory = join(fixtureRoot, 'src')
      mkdirSync(sourceDirectory, { recursive: true })
      writeFileSync(join(sourceDirectory, 'Shell.tsx'), `import { Route, Routes } from 'react-router-dom'
import Fallback from './Fallback.jsx'
export function Shell() { return <Routes><Route path="*" element={<Fallback />} /></Routes> }
`)
      writeFileSync(join(sourceDirectory, 'Fallback.jsx'), `export default function Fallback() { return null }
`)
      writeFileSync(join(sourceDirectory, 'Fallback.tsx'), `import { Route, Routes } from 'react-router-dom'
export default function Fallback() { return <Routes><Route path="child" /></Routes> }
`)

      try {
        expect(() => sourceFiles(sourceDirectory, fixtureRoot)).toThrow(
          /loads local module \.\/Fallback\.jsx that the console route inventory cannot inspect as TypeScript/,
        )
      } finally {
        rmSync(fixtureRoot, { recursive: true, force: true })
      }
    })

    it('fails closed when Vite resolves an extensionless local route import to JavaScript before TypeScript', () => {
      const fixtureRoot = mkdtempSync(join(tmpdir(), 'edgewatch-extension-order-router-import-'))
      const sourceDirectory = join(fixtureRoot, 'src')
      mkdirSync(sourceDirectory, { recursive: true })
      writeFileSync(join(sourceDirectory, 'Shell.tsx'), `import { Route, Routes } from 'react-router-dom'
import Fallback from './Fallback'
export function Shell() { return <Routes><Route path="*" element={<Fallback />} /></Routes> }
`)
      writeFileSync(join(sourceDirectory, 'Fallback.js'), `export default function Fallback() { return null }
`)
      writeFileSync(join(sourceDirectory, 'Fallback.tsx'), `import { Route, Routes } from 'react-router-dom'
export default function Fallback() { return <Routes><Route path="child" /></Routes> }
`)

      try {
        expect(() => sourceFiles(sourceDirectory, fixtureRoot)).toThrow(
          /local module \.\/Fallback resolves first to src\/Fallback\.js under Vite's extension order, which the console route inventory cannot inspect as TypeScript/,
        )
      } finally {
        rmSync(fixtureRoot, { recursive: true, force: true })
      }
    })

    it('does not read local TypeScript modules that escape their canonical fixture root', () => {
      const fixtureRoot = mkdtempSync(join(tmpdir(), 'edgewatch-router-root-'))
      const outsideRoot = mkdtempSync(join(tmpdir(), 'edgewatch-router-outside-'))
      const sourceDirectory = join(fixtureRoot, 'src')
      const outsideModule = join(outsideRoot, 'OutsideRouter.tsx')
      mkdirSync(sourceDirectory, { recursive: true })
      mkdirSync(join(fixtureRoot, 'linked'), { recursive: true })
      writeFileSync(outsideModule, `export default function OutsideRouter() { return null }\n`)
      writeFileSync(join(sourceDirectory, 'Traversal.tsx'), `import OutsideRouter from '${relative(sourceDirectory, outsideModule).split(/[\\/]/).join('/')}'
export function Shell() { return <Routes><Route path="/outside" element={<OutsideRouter />} /></Routes> }
`)
      symlinkSync(outsideModule, join(fixtureRoot, 'linked', 'LinkedRouter.tsx'))
      writeFileSync(join(sourceDirectory, 'Symlink.tsx'), `import LinkedRouter from '../linked/LinkedRouter'
export function LinkedShell() { return <Routes><Route path="/linked" element={<LinkedRouter />} /></Routes> }
`)

      try {
        expect(() => sourceFiles(outsideRoot, fixtureRoot)).toThrow(/source directory .* resolves outside allowed root/)
        const linkedDirectory = join(fixtureRoot, 'src', 'linked-outside')
        symlinkSync(outsideRoot, linkedDirectory, 'dir')
        expect(() => sourceFiles(linkedDirectory, fixtureRoot)).toThrow(/source directory .* resolves outside allowed root/)

        expect(() => sourceFiles(sourceDirectory, fixtureRoot)).toThrow(/local module .* resolves outside allowed root/)
        rmSync(join(sourceDirectory, 'Traversal.tsx'))
        expect(() => sourceFiles(sourceDirectory, fixtureRoot)).toThrow(/local module .* resolves outside allowed root/)
      } finally {
        rmSync(fixtureRoot, { recursive: true, force: true })
        rmSync(outsideRoot, { recursive: true, force: true })
      }
    })

    it('refuses router components destructured from an unresolved local import', () => {
      const source = {
        file: 'src/destructured-unresolved-router.tsx',
        code: `import Router from './router-bindings.js'
const { Route, Routes } = Router
export function Shell() { return <Routes><Route path='/hidden' /></Routes> }`,
      }

      expect(() => extractRouters([source])).toThrow(/forwards values from unresolved local module \.\/router-bindings\.js/)
    })

    it('refuses unresolved local router imports forwarded through JSX spreads', () => {
      const source = {
        file: 'src/spread-unresolved-router.tsx',
        code: `import { Route, Routes } from 'react-router-dom'
import * as UnreadableRouter from './router-runtime.js'
function Wrapper({ Route: RouteComponent, Routes: RoutesComponent }) {
  return <RoutesComponent><RouteComponent path="/hidden" /></RoutesComponent>
}
export function Shell() {
  return <Routes><Route path="/outer" element={<Wrapper {...UnreadableRouter} />} /></Routes>
}`,
      }

      expect(() => extractRouters([source])).toThrow(/forwards values from unresolved local module \.\/router-runtime\.js/)
    })

    it('refuses router components forwarded through local property aliases', () => {
      const propertyAlias = {
        file: 'src/property-alias-unresolved-router.tsx',
        code: `import Router from './router-bindings.js'
const Route = Router.Route
const Routes = Router.Routes
export function Shell() { return <Routes><Route path='/hidden' /></Routes> }`,
      }
      const objectPropertyAlias = {
        file: 'src/object-property-alias-unresolved-router.tsx',
        code: `import Router from './router-bindings.js'
const Components = { Route: Router.Route, Routes: Router.Routes }
export function Shell() { return <Components.Routes><Components.Route path='/hidden' /></Components.Routes> }`,
      }

      for (const source of [propertyAlias, objectPropertyAlias]) {
        expect(() => extractRouters([source]), source.file).toThrow(/forwards values from unresolved local module \.\/router-bindings\.js/)
      }
    })

    it('fails closed when renamed Route and Routes re-exports pass through root-level helpers', () => {
      const fixtureRoot = mkdtempSync(join(tmpdir(), 'edgewatch-route-inventory-'))
      const sourceDirectory = join(fixtureRoot, 'src')
      const helperPath = join(fixtureRoot, 'router-bindings.ts')
      const bridgePath = join(sourceDirectory, 'router-bridge.ts')
      const routePath = join(sourceDirectory, 'HiddenRoutes.tsx')

      mkdirSync(sourceDirectory, { recursive: true })
      writeFileSync(helperPath, `export { Route as Page, Routes as Pages } from 'react-router-dom'\n`)
      writeFileSync(routePath, `import { Page, Pages } from '../router-bindings'\nexport function HiddenRoutes() { return <Pages><Page path="/hidden" /></Pages> }\n`)

      try {
        const directSources = sourceFiles(sourceDirectory, fixtureRoot)
        expect(directSources.some(source => source.file.endsWith('/router-bindings.ts'))).toBe(true)
        expect(() => extractRouters(directSources, fixtureRoot)).toThrow(/re-exports router APIs from react-router-dom/)

        writeFileSync(bridgePath, `export { Page, Pages } from '../router-bindings'\n`)
        writeFileSync(routePath, `import { Page, Pages } from './router-bridge'\nexport function HiddenRoutes() { return <Pages><Page path="/hidden" /></Pages> }\n`)
        const chainedSources = sourceFiles(sourceDirectory, fixtureRoot)
        expect(chainedSources.some(source => source.file.endsWith('/router-bridge.ts'))).toBe(true)
        expect(chainedSources.some(source => source.file.endsWith('/router-bindings.ts'))).toBe(true)
        expect(() => extractRouters(chainedSources, fixtureRoot)).toThrow(/re-exports router APIs from react-router-dom/)

        const aliasedRouteSource = {
          file: 'src/HiddenRoutes.tsx',
          code: `import { Route as Page, Routes as Pages } from '../router-bindings'\nexport function HiddenRoutes() { return <Pages><Page path="/hidden" /></Pages> }`,
        }
        expect(() => extractRouters([aliasedRouteSource])).toThrow(/imports Route from \.\.\/router-bindings/)
        const unresolvedAliasSource = {
          file: 'src/HiddenRoutes.tsx',
          code: `import { Page, Pages } from '../router-bindings'\nexport function HiddenRoutes() { return <Pages><Page path="/hidden" /></Pages> }`,
        }
        expect(() => extractRouters([unresolvedAliasSource])).toThrow(/uses JSX component Page from unresolved local module \.\.\/router-bindings/)
        const unresolvedNamespaceSource = {
          file: 'src/HiddenRoutes.tsx',
          code: `import * as Router from '../router-bindings'\nexport function HiddenRoutes() { return <Router.Pages><Router.Page path="/hidden" /></Router.Pages> }`,
        }
        expect(() => extractRouters([unresolvedNamespaceSource])).toThrow(/uses JSX component Router from unresolved local module \.\.\/router-bindings/)

        writeFileSync(routePath, `export async function HiddenRoutes() {\n  const { Page, Pages } = await import('../router-bindings')\n  return <Pages><Page path="/hidden" /></Pages>\n}\n`)
        const dynamicSources = sourceFiles(sourceDirectory, fixtureRoot)
        expect(dynamicSources.some(source => source.file.endsWith('/router-bindings.ts'))).toBe(true)
        expect(() => extractRouters(dynamicSources, fixtureRoot)).toThrow(/re-exports router APIs from react-router-dom/)

        writeFileSync(join(fixtureRoot, 'tsconfig.json'), JSON.stringify({
          compilerOptions: {
            module: 'ESNext',
            moduleResolution: 'Bundler',
            target: 'ES2022',
            baseUrl: '.',
            paths: { '@edgewatch/*': ['*'] },
          },
        }))
        writeFileSync(routePath, `import { Page, Pages } from '@edgewatch/router-bindings'\nexport function HiddenRoutes() { return <Pages><Page path="/hidden" /></Pages> }\n`)
        const aliasSources = sourceFiles(sourceDirectory, fixtureRoot)
        expect(aliasSources.some(source => source.file.endsWith('/router-bindings.ts'))).toBe(true)
        expect(() => extractRouters(aliasSources, fixtureRoot)).toThrow(/re-exports router APIs from react-router-dom/)

        const wildcardHelperName = 'router+bindings[1]$&'
        mkdirSync(join(fixtureRoot, 'helpers'), { recursive: true })
        writeFileSync(join(fixtureRoot, 'helpers', `${wildcardHelperName}.ts`), `export { Route as Page, Routes as Pages } from 'react-router-dom'\n`)
        writeFileSync(join(fixtureRoot, 'tsconfig.json'), JSON.stringify({
          compilerOptions: {
            module: 'ESNext',
            moduleResolution: 'Bundler',
            target: 'ES2022',
            baseUrl: '.',
            paths: { '@edgewatch/*': ['helpers/*'] },
          },
        }))
        writeFileSync(routePath, `import { Page, Pages } from '@edgewatch/${wildcardHelperName}'\nexport function HiddenRoutes() { return <Pages><Page path="/hidden" /></Pages> }\n`)
        const wildcardSources = sourceFiles(sourceDirectory, fixtureRoot)
        expect(wildcardSources.some(source => source.file.endsWith(`/helpers/${wildcardHelperName}.ts`))).toBe(true)
        expect(() => extractRouters(wildcardSources, fixtureRoot)).toThrow(/re-exports router APIs from react-router-dom/)

        writeFileSync(join(fixtureRoot, 'router-runtime.js'), `export { Route, Routes } from 'react-router-dom'\n`)
        writeFileSync(helperPath, `export { Route as Page, Routes as Pages } from './router-runtime.js'\n`)
        writeFileSync(routePath, `import { Page, Pages } from '../router-bindings'\nexport function HiddenRoutes() { return <Pages><Page path="/hidden" /></Pages> }\n`)
        expect(() => sourceFiles(sourceDirectory, fixtureRoot)).toThrow(
          /loads local module \.\/router-runtime\.js that the console route inventory cannot inspect as TypeScript/,
        )
      } finally {
        rmSync(fixtureRoot, { recursive: true, force: true })
      }
    })

    it('fails closed on path aliases with multiple wildcards', () => {
      const fixtureRoot = mkdtempSync(join(tmpdir(), 'edgewatch-route-alias-wildcard-'))
      const sourceDirectory = join(fixtureRoot, 'src')
      mkdirSync(sourceDirectory, { recursive: true })
      writeFileSync(join(sourceDirectory, 'HiddenRoutes.tsx'), `import { Page, Pages } from '@edgewatch/router-bindings'\nexport function HiddenRoutes() { return <Pages><Page path="/hidden" /></Pages> }\n`)

      try {
        writeFileSync(join(fixtureRoot, 'tsconfig.json'), JSON.stringify({
          compilerOptions: { baseUrl: '.', paths: { '@edgewatch/**': ['helpers/*'] } },
        }))
        expect(() => sourceFiles(sourceDirectory, fixtureRoot)).toThrow(/path pattern @edgewatch\/\*\* contains more than one/)

        writeFileSync(join(fixtureRoot, 'tsconfig.json'), JSON.stringify({
          compilerOptions: { baseUrl: '.', paths: { '@edgewatch/*': ['helpers/**'] } },
        }))
        expect(() => sourceFiles(sourceDirectory, fixtureRoot)).toThrow(/path target helpers\/\*\* contains more than one/)
      } finally {
        rmSync(fixtureRoot, { recursive: true, force: true })
      }
    })

    it('does not fall back to a different TypeScript path alias target after an out-of-root match', () => {
      const fixtureRoot = mkdtempSync(join(tmpdir(), 'edgewatch-route-alias-root-'))
      const outsideRoot = mkdtempSync(join(tmpdir(), 'edgewatch-route-alias-outside-'))
      const sourceDirectory = join(fixtureRoot, 'src')
      const fallbackDirectory = join(sourceDirectory, 'routes')
      mkdirSync(fallbackDirectory, { recursive: true })
      writeFileSync(join(outsideRoot, 'router-bindings.ts'), `export { Route as Page, Routes as Pages } from 'react-router-dom'\n`)
      writeFileSync(join(fallbackDirectory, 'router-bindings.tsx'), `export function Page() { return <main /> }\nexport function Pages({ children }) { return <>{children}</> }\n`)
      writeFileSync(join(sourceDirectory, 'HiddenRoutes.tsx'), `import { Page, Pages } from '@edgewatch/router-bindings'
export function HiddenRoutes() { return <Pages><Page path="/hidden" /></Pages> }
`)

      try {
        const outsideTarget = `${relative(fixtureRoot, outsideRoot).split(/[\\/]/).join('/')}/*`
        writeFileSync(join(fixtureRoot, 'tsconfig.json'), JSON.stringify({
          compilerOptions: {
            baseUrl: '.',
            paths: { '@edgewatch/*': [outsideTarget, 'src/routes/*'] },
          },
        }))

        expect(() => sourceFiles(sourceDirectory, fixtureRoot)).toThrow(/local module .*resolves outside allowed root/)
      } finally {
        rmSync(fixtureRoot, { recursive: true, force: true })
        rmSync(outsideRoot, { recursive: true, force: true })
      }
    })

    it('refuses dynamic router module loads before checking for static router imports', () => {
      const cases = [
        {
          file: 'src/dynamic-a.tsx',
          code: `export async function HiddenRouter() {
  const { Route, Routes } = await import('react-router-dom')
  return <Routes><Route path="/hidden" /></Routes>
}`,
          error: /dynamically loads router module react-router-dom/,
        },
        {
          file: 'src/dynamic-b.tsx',
          code: `export async function HiddenRouter() {
  const router = await import(\`react-router\`)
  const { Route: Page, Routes: Pages } = router
  return <Pages><Page path="/hidden" /></Pages>
}`,
          error: /dynamically loads router module react-router/,
        },
        {
          file: 'src/dynamic-c.tsx',
          code: `const routerModule = 'react-router-dom'
export async function HiddenRouter() {
  const { Route, Routes } = await import(routerModule)
  return <Routes><Route path="/hidden" /></Routes>
}`,
          error: /dynamic import with a non-static module specifier/,
        },
        {
          file: 'src/dynamic-d.tsx',
          code: `export async function HiddenRouter() {
  const { Route, Routes } = await import('react-router-' + 'dom')
  return <Routes><Route path="/hidden" /></Routes>
}`,
          error: /dynamically loads router module react-router-dom/,
        },
        {
          file: 'src/dynamic-e.tsx',
          code: `export function HiddenRouter() {
  const { Route, Routes } = require('react-router-dom')
  return <Routes><Route path="/hidden" /></Routes>
}`,
          error: /dynamically loads router module react-router-dom/,
        },
        {
          file: 'src/dynamic-router-adapter.tsx',
          code: `export async function HiddenRouter() {
  const { Route: Page, Routes: Pages } = await import('router-adapter')
  return <Pages><Page path="/hidden" /></Pages>
}`,
          error: /uses <(?:Pages|Page)> from unresolved router import router-adapter/,
        },
        {
          file: 'src/dynamic-create-require-loader.tsx',
          code: `const { createRequire } = await import('node:module')
const loadRouter = createRequire(import.meta.url)
const { Route, Routes } = loadRouter('react-router-dom')
export function HiddenRouter() { return <Routes><Route path="/hidden" /></Routes> }`,
          error: /loads the CommonJS module factory node:module/,
        },
        {
          file: 'src/dynamic-f.tsx',
          code: `const loadModule = require
export function HiddenRouter() {
  const { Route, Routes } = loadModule('react-router-dom')
  return <Routes><Route path="/hidden" /></Routes>
}`,
          error: /dynamically loads router module react-router-dom/,
        },
        {
          file: 'src/dynamic-g.tsx',
          code: `export function HiddenRouter() {
  const { Route, Routes } = module.require('react-router-dom')
  return <Routes><Route path="/hidden" /></Routes>
}`,
          error: /dynamically loads router module react-router-dom/,
        },
        {
          file: 'src/dynamic-h.tsx',
          code: `const loadModule = module['require']
export function HiddenRouter() {
  const { Route, Routes } = loadModule('react-router-dom')
  return <Routes><Route path="/hidden" /></Routes>
}`,
          error: /dynamically loads router module react-router-dom/,
        },
        {
          file: 'src/create-require-loader.tsx',
          code: `import { createRequire } from 'node:module'
const loadRouter = createRequire(import.meta.url)
const { Route, Routes } = loadRouter('react-router-dom')
export function HiddenRouter() { return <Routes><Route path="/hidden" /></Routes> }`,
          error: /dynamically loads router module react-router-dom/,
        },
        {
          file: 'src/aliased-create-require-loader.tsx',
          code: `import { createRequire as makeRequire } from 'node:module'
const createLoader = makeRequire
const loadRouter = createLoader(import.meta.url)
const { Route, Routes } = loadRouter('react-router-dom')
export function HiddenRouter() { return <Routes><Route path="/hidden" /></Routes> }`,
          error: /dynamically loads router module react-router-dom/,
        },
        {
          file: 'src/destructured-create-require-loader.tsx',
          code: `import * as nodeModule from 'node:module'
const moduleAlias = nodeModule
const { createRequire: makeRequire } = moduleAlias
const loadRouter = makeRequire(import.meta.url)
const { Route, Routes } = loadRouter('react-router-dom')
export function HiddenRouter() { return <Routes><Route path="/hidden" /></Routes> }`,
          error: /dynamically loads router module react-router-dom/,
        },
        {
          file: 'src/commonjs-created-create-require-loader.tsx',
          code: `const { createRequire: makeRequire } = require('node:module')
const loadRouter = makeRequire(import.meta.url)
const { Route, Routes } = loadRouter('react-router-dom')
export function HiddenRouter() { return <Routes><Route path="/hidden" /></Routes> }`,
          error: /loads the CommonJS module factory node:module/,
        },
        {
          file: 'src/reflective-create-require-loader.tsx',
          code: `import { Route, Routes } from 'react-router-dom'
const router = Reflect.apply(module.require, module, ['react-router-dom'])
const { Route: Page, Routes: Pages } = router
export function HiddenRouter() { return <Pages><Page path="/hidden" /></Pages> }`,
          error: /uses a CommonJS module loader as a value outside a direct module load/,
        },
        {
          file: 'src/dynamic-i.tsx',
          code: `export function HiddenRouter(moduleName: string) {
  const { Route, Routes } = require(moduleName)
  return <Routes><Route path="/hidden" /></Routes>
}`,
          error: /CommonJS module load with a non-static module specifier/,
        },
        {
          file: 'src/optional-loader.tsx',
          code: `export function HiddenRouter() {
  const { Route, Routes } = module.require?.('react-router-dom')
  return <Routes><Route path="/hidden" /></Routes>
}`,
          error: /optional CommonJS module load/,
        },
        {
          file: 'src/optional-module-member-loader.tsx',
          code: `export function HiddenRouter() {
  const { Route, Routes } = module?.require('react-router-dom')
  return <Routes><Route path="/hidden" /></Routes>
}`,
          error: /optional CommonJS module load/,
        },
        {
          file: 'src/optional-aliased-loader.tsx',
          code: `const loadRouter = (module?.require as typeof require)
export function HiddenRouter() {
  const { Route, Routes } = loadRouter?.('react-router-dom')
  return <Routes><Route path="/hidden" /></Routes>
}`,
          error: /optional CommonJS module load/,
        },
      ]

      for (const fixture of cases) {
        expect(() => extractRouters([fixture]), fixture.file).toThrow(fixture.error)
      }
    })

    it('fails closed on aliased or destructured Route bindings from unrecognized modules', () => {
      const cases = [
        {
          file: 'src/aliased-external-router.tsx',
          code: `import { Route as ImportedRoute, Routes as ImportedRoutes } from 'router-adapter'
const Route = ImportedRoute
const Routes = ImportedRoutes
export function HiddenRouter() { return <Routes><Route path="/hidden" /></Routes> }`,
        },
        {
          file: 'src/destructured-external-router.tsx',
          code: `import * as RouterAdapter from 'router-adapter'
const { Route, Routes } = RouterAdapter
export function HiddenRouter() { return <Routes><Route path="/hidden" /></Routes> }`,
        },
        {
          file: 'src/namespace-alias-destructured-external-router.tsx',
          code: `import * as RouterAdapter from 'router-adapter'
const adapter = RouterAdapter
const { Route: ImportedRoute, Routes: ImportedRoutes } = adapter
const Route = ImportedRoute
const Routes = ImportedRoutes
export function HiddenRouter() { return <Routes><Route path="/hidden" /></Routes> }`,
        },
      ]

      for (const fixture of cases) {
        expect(() => extractRouters([fixture]), fixture.file).toThrow(/from unresolved router import router-adapter/)
      }
    })

    it('preserves Route and Routes identity through renamed local re-export barrels', () => {
      const fixtureRoot = mkdtempSync(join(tmpdir(), 'edgewatch-renamed-router-api-barrel-'))
      const sourceDirectory = join(fixtureRoot, 'src')
      mkdirSync(sourceDirectory, { recursive: true })
      writeFileSync(join(fixtureRoot, 'tsconfig.json'), JSON.stringify({ compilerOptions: { baseUrl: '.' } }))
      writeFileSync(join(sourceDirectory, 'router-bindings.ts'), `import { Route as ImportedRoute, Routes as ImportedRoutes } from 'router-adapter'
export { ImportedRoute as Page, ImportedRoutes as Pages }
`)
      writeFileSync(join(sourceDirectory, 'HiddenRoutes.tsx'), `import { Page, Pages } from './router-bindings'
export function HiddenRoutes() { return <Pages><Page path="/hidden" /></Pages> }
`)

      try {
        const sources = sourceFiles(sourceDirectory, fixtureRoot)
        expect(() => extractRouters(sources, fixtureRoot)).toThrow(/imports Route from router-adapter and uses it as JSX/)
      } finally {
        rmSync(fixtureRoot, { recursive: true, force: true })
      }
    })

    it('resolves reverse-ordered CommonJS loader aliases with linear work', () => {
      const aliasCount = 10_000
      const aliases = Array.from({ length: aliasCount }, (_, index) =>
        `const loader${index} = ${index + 1 === aliasCount ? 'require' : `loader${index + 1}`}`,
      ).join('\n')
      const program = parseSync('src/long-loader-chain.ts', aliases, { lang: 'ts' }).program as unknown as Node
      const discovered = discoverCommonJSAliases(program)

      expect(discovered.loaderAliases.has('loader0')).toBe(true)
      expect(discovered.workItems).toBeLessThan(aliasCount * 8)

      const source = {
        file: 'src/long-loader-chain.tsx',
        code: `${aliases}\nconst { Route, Routes } = loader0('react-router-dom')\nexport function Shell() { return <Routes><Route path="/hidden" /></Routes> }`,
      }
      expect(() => extractRouters([source])).toThrow(/dynamically loads router module react-router-dom/)
    })

    it('refuses bound and destructured CommonJS loaders before skipping files without router imports', () => {
      const cases = [
        {
          file: 'src/bound-loader.tsx',
          code: `const loadRouter = module.require.bind(module)
const { Route, Routes } = loadRouter('react-router-dom')
export function HiddenRouter() {
  return <Routes><Route path="/hidden" /></Routes>
}`,
          error: /binds or rebinds a CommonJS module loader/,
        },
        {
          file: 'src/destructured-loader-alias.tsx',
          code: `const { require: loadRouter } = module
const { Route, Routes } = loadRouter('react-router-dom')
export function HiddenRouter() {
  return <Routes><Route path="/hidden" /></Routes>
}`,
          error: /destructures a CommonJS module loader/,
        },
        {
          file: 'src/destructured-loader-shorthand.tsx',
          code: `const { require } = module
const { Route, Routes } = require('react-router-dom')
export function HiddenRouter() {
  return <Routes><Route path="/hidden" /></Routes>
}`,
          error: /destructures a CommonJS module loader/,
        },
        {
          file: 'src/destructured-loader-module-alias.tsx',
          code: `const nodeModule = module
const { ['require']: loadRouter } = nodeModule
const { Route, Routes } = loadRouter('react-router-dom')
export function HiddenRouter() {
  return <Routes><Route path="/hidden" /></Routes>
}`,
          error: /destructures a CommonJS module loader/,
        },
        {
          file: 'src/destructured-loader-assignment.tsx',
          code: `let loadRouter
({ require: loadRouter } = module)
const { Route, Routes } = loadRouter('react-router-dom')
export function HiddenRouter() {
  return <Routes><Route path="/hidden" /></Routes>
}`,
          error: /destructures a CommonJS module loader/,
        },
      ]

      for (const fixture of cases) {
        expect(() => extractRouters([fixture])).toThrow(fixture.error)
      }
    })

    it('recognizes CommonJS loaders through transparent TypeScript and parenthesized wrappers', () => {
      const cases = [
        {
          file: 'src/asserted-loader.tsx',
          code: `const loadRouter = module.require as typeof require
const { Route, Routes } = loadRouter('react-router-dom')
export function HiddenRouter() {
  return <Routes><Route path="/hidden" /></Routes>
}`,
        },
        {
          file: 'src/non-null-parenthesized-loader.tsx',
          code: `const loadRouter = ((module.require))!
const { Route, Routes } = loadRouter('react-router-dom')
export function HiddenRouter() {
  return <Routes><Route path="/hidden" /></Routes>
}`,
        },
        {
          file: 'src/satisfies-loader.tsx',
          code: `const loadRouter = module.require satisfies typeof require
const { Route, Routes } = loadRouter('react-router-dom')
export function HiddenRouter() {
  return <Routes><Route path="/hidden" /></Routes>
}`,
        },
        {
          file: 'src/instantiated-loader.tsx',
          code: `const loadRouter = module.require<typeof require>
const { Route, Routes } = loadRouter('react-router-dom')
export function HiddenRouter() {
  return <Routes><Route path="/hidden" /></Routes>
}`,
        },
        {
          file: 'src/type-asserted-loader.ts',
          code: `const { Route, Routes } = (<typeof require>module.require)('react-router-dom')`,
        },
        {
          file: 'src/asserted-module-object.tsx',
          code: `const nodeModule = module as NodeModule
const loadRouter = nodeModule.require as typeof require
const { Route, Routes } = loadRouter('react-router-dom')
export function HiddenRouter() {
  return <Routes><Route path="/hidden" /></Routes>
}`,
        },
      ]

      for (const fixture of cases) {
        expect(() => extractRouters([fixture]), fixture.file).toThrow(/dynamically loads router module react-router-dom/)
      }
    })

    it('refuses local aliases that could hide routes inside a readable router', () => {
      expect(() => extractRouters([{ file: 'src/i.tsx', code: `import { Route, Routes } from 'react-router-dom'\nconst HiddenRoute = Route\nexport function I() { return <Routes><Route path="/visible" /><HiddenRoute path="/hidden" /></Routes> }` }])).toThrow(/aliases imported Route as HiddenRoute/)
      expect(() => extractRouters([{ file: 'src/j.tsx', code: `import { Route, Routes } from 'react-router-dom'\nconst HiddenRoutes = Routes\nexport function J() { return <HiddenRoutes><Route path="/visible" /></HiddenRoutes> }` }])).toThrow(/aliases imported Routes as HiddenRoutes/)
    })

    it('refuses imported router components passed as values to wrappers', () => {
      const imports = `import { Route as RouterRoute, Routes as RouterRoutes } from 'react-router-dom'`
      const cases = [
        {
          file: 'src/wrapper-props.tsx',
          code: `${imports}
function HiddenRouter({ Route: RouteComponent, Routes: RoutesComponent }) {
  return <RoutesComponent><RouteComponent path="/hidden" element={<HiddenPage />} /></RoutesComponent>
}
function App() {
  return <HiddenRouter Route={RouterRoute} Routes={RouterRoutes} />
}`,
        },
        {
          file: 'src/wrapper-object-props.tsx',
          code: `${imports}
function HiddenRouter({ Route: RouteComponent, Routes: RoutesComponent }) {
  return <RoutesComponent><RouteComponent path="/hidden" /></RoutesComponent>
}
function App() {
  return <HiddenRouter {...{ Route: RouterRoute, Routes: RouterRoutes }} />
}`,
        },
        {
          file: 'src/wrapper-call-args.tsx',
          code: `${imports}
function makeRouter(RouteComponent, RoutesComponent) {
  return { Route: RouteComponent, Routes: RoutesComponent }
}
function App() {
  return makeRouter(RouterRoute, RouterRoutes)
}`,
        },
      ]

      for (const fixture of cases) {
        expect(() => extractRouters([fixture])).toThrow(/uses imported (Route|Routes) as a value outside a JSX tag/)
      }
    })

    it('refuses Route prop spreads that could override the inventoried path', () => {
      const source = (declarations: string, route: string) => `import { Route, Routes } from 'react-router-dom'
${declarations}
export function K() { return <Routes><Route path="/visible" element={<Visible />} />${route}</Routes> }`
      const spreads = [
        {
          file: 'src/k.tsx',
          code: source('', `<Route path="/known" {...{ path: "/hidden", element: <HiddenPage /> }} />`),
        },
        {
          file: 'src/l.tsx',
          code: source('', `<Route {...{ path: "/hidden", element: <HiddenPage /> }} path="/known" />`),
        },
        {
          file: 'src/m.tsx',
          code: source(`const hiddenProps = { path: '/hidden', element: <HiddenPage /> }`, `<Route path="/known" {...hiddenProps} />`),
        },
        {
          file: 'src/n.tsx',
          code: source(`const hiddenProps = { path: '/hidden', element: <HiddenPage /> }`, `<Route {...(showHidden ? hiddenProps : {})} path="/known" />`),
        },
      ]

      for (const fixture of spreads) {
        expect(() => extractRouters([fixture])).toThrow(/JSX prop spread; the console route inventory requires explicit props/)
      }
    })

    it('refuses Route children props that could hide nested routes', () => {
      const header = `import { Route, Routes } from 'react-router-dom'`
      const route = (attribute: string, declarations = '') => `${header}
${declarations}
export function ParentRouter() {
  return <Routes><Route path="/parent" ${attribute} /></Routes>
}`
      const cases = [
        {
          file: 'src/route-children-a.tsx',
          code: route(`children={<Route path="hidden" element={<HiddenPage />} />}`),
        },
        {
          file: 'src/route-children-b.tsx',
          code: route(`children={hiddenRoutes}`, `const hiddenRoutes = getHiddenRoutes()`),
        },
        {
          file: 'src/route-children-c.tsx',
          code: route(`children={showHidden ? getHiddenRoutes() : null}`),
        },
      ]

      for (const fixture of cases) {
        expect(() => extractRouters([fixture])).toThrow(/uses a children attribute; nested routes must be declared as direct JSX children/)
      }
    })

    it('refuses non-JSX route children that could hide routes from the inventory', () => {
      const visible = `<Route path="/visible" element={<Visible />} />`
      const source = (imports: string, child: string) => `${imports}\nexport function K() { return <Routes>${visible}{${child}}</Routes> }`
      const reactRouterImports = `import { Route, Routes } from 'react-router-dom'`

      expect(() => extractRouters([{ file: 'src/k.tsx', code: source(`${reactRouterImports}\nimport { createElement } from 'react'`, `createElement(Route, { path: '/hidden', element: <Hidden /> })`) }])).toThrow(/unsupported non-JSX child \(CallExpression\)/)
      expect(() => extractRouters([{ file: 'src/l.tsx', code: source(`${reactRouterImports}\nimport * as React from 'react'`, `React.createElement(Route, { path: '/hidden', element: <Hidden /> })`) }])).toThrow(/unsupported non-JSX child \(CallExpression\)/)
      expect(() => extractRouters([{ file: 'src/m.tsx', code: source(`${reactRouterImports}\nimport { createElement as makeElement } from 'react'`, `makeElement(Route, { path: '/hidden', element: <Hidden /> })`) }])).toThrow(/unsupported non-JSX child \(CallExpression\)/)
      expect(() => extractRouters([{ file: 'src/n.tsx', code: source(`${reactRouterImports}\nimport { createElement } from 'react'\nconst makeElement = createElement`, `makeElement(Route, { path: '/hidden', element: <Hidden /> })`) }])).toThrow(/unsupported non-JSX child \(CallExpression\)/)
    })

    it('refuses Routes children props and spreads that bypass JSX child inspection', () => {
      const header = `import { createElement } from 'react'
import { Route, Routes } from 'react-router-dom'`
      const routes = (attribute: string, declarations = '') => `${header}
${declarations}
export function HiddenRouter() { return <Routes ${attribute} /> }`
      const cases = [
        {
          file: 'src/children-a.tsx',
          code: routes(`children={createElement(Route, { ...hiddenProps, path: '/hidden' })}`),
        },
        {
          file: 'src/children-b.tsx',
          code: routes(`children={<Route path="/hidden" />}`),
        },
        {
          file: 'src/children-c.tsx',
          code: routes(`{...routerProps}`),
        },
      ]

      for (const fixture of cases) {
        expect(() => extractRouters([fixture])).toThrow(/must declare route children as direct JSX children/)
      }
    })

    it('keeps shorthand and imported React fragments readable as route children', () => {
      const source = `import React, { Fragment as Group } from 'react'
import { Route, Routes } from 'react-router-dom'
export function O() { return <Routes><><Route path="/short" /></><React.Fragment><Route path="/qualified" /></React.Fragment><Group><Route path="/named" /></Group></Routes> }`
      expect(extractRouters([{ file: 'src/o.tsx', code: source }]).map(router => router.routes.map(route => route.path))).toEqual([['/short', '/qualified', '/named']])
    })
  })
})
