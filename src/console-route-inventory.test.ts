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
  /** The components that its element renders, such as a descendant router. */
  renders: string[]
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

function rejectUninspectableRouterLoads(program: Node, file: string): string[] {
  const { loaderAliases, moduleAliases } = discoverCommonJSAliases(program)
  const moduleLoads: string[] = []

  const isRouterModule = (specifier: string) => [...routerModules].some(module => specifier === module || specifier.startsWith(`${module}/`))
  const inspect = (node: Node) => {
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
      if (isRouterModule(specifier)) {
        throw new Error(`${file} dynamically loads router module ${specifier}; the console route inventory requires static named router imports`)
      }
      moduleLoads.push(specifier)
    }
    childNodes(node).forEach(inspect)
  }
  inspect(program)
  return moduleLoads
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

function readableComponentExpression(node: Node | undefined, readableLazyCalls: Set<Node>, reactNamespaces: Set<string>): boolean {
  const expression = unwrapTransparentExpression(node)
  if (!expression) return false
  if (expression.type === 'Identifier' || readableLazyCalls.has(expression)) return true
  if (expression.type === 'Literal' && expression.value === null) return true
  if (expression.type === 'MemberExpression' || expression.type === 'OptionalMemberExpression') {
    const property = expression.property as Node
    const object = unwrapTransparentExpression(expression.object as Node)
    return (!expression.computed || staticStringValue(property) !== undefined)
      && object?.type === 'Identifier'
      && reactNamespaces.has(String(object.name))
  }
  if (expression.type === 'ConditionalExpression') {
    return readableComponentExpression(expression.consequent as Node, readableLazyCalls, reactNamespaces)
      && readableComponentExpression(expression.alternate as Node, readableLazyCalls, reactNamespaces)
  }
  if (expression.type === 'LogicalExpression') {
    return readableComponentExpression(expression.left as Node, readableLazyCalls, reactNamespaces)
      && readableComponentExpression(expression.right as Node, readableLazyCalls, reactNamespaces)
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
  file: string,
): { bindings: Map<string, { source: string }>; calls: Map<Node, { component: string; source: string }>; readableCalls: Set<Node> } {
  const imports = new Map<string, { source: string }>()
  const calls = new Map<Node, { component: string; source: string }>()
  const readableCalls = new Set<Node>()
  const isOpaquePackage = (specifier: string) => !isLocalSpecifier(specifier)
    && !specifier.startsWith('node:')
    && !specifier.startsWith('#')
    && !/^[a-z][a-z\d+.-]*:/i.test(specifier)
    && specifier !== 'react'
    && !specifier.startsWith('react/')
    && specifier !== 'react-dom'
    && !specifier.startsWith('react-dom/')
    && ![...routerModules].some(module => specifier === module || specifier.startsWith(`${module}/`))
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
    readableCalls.add(node)
    const source = loader.values.flatMap(opaqueImportsIn)[0]
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
): { component: string; source: string; file: string }[] {
  if (!node) return []
  const rendered = new Map<string, { component: string; source: string; file: string }>()
  const add = (binding: string | undefined) => {
    const source = binding ? imports.get(binding)?.source : undefined
    if (binding && source) rendered.set(binding, { component: binding, source, file })
  }
  const addImportedValues = (value: Node) => {
    const visitValues = (current: Node, parent?: Node, field?: string) => {
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
      const binding = name.type === 'JSXIdentifier'
        ? String(name.name)
        : name.type === 'JSXMemberExpression'
          ? jsxMemberRootIdentifier(name)
          : undefined
      add(binding)
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
function importedComponentAliases(program: Node, imports: Map<string, { source: string }>): Map<string, { source: string }> {
  const dependents = new Map<string, Set<string>>()
  const addBindingNames = (pattern: Node | undefined, names: Set<string>) => {
    if (!pattern) return
    if (pattern.type === 'Identifier') {
      names.add(String(pattern.name))
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
        visitReferences(node.object as Node | undefined, node, 'object')
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

function componentBindingsUsedInJSX(program: Node): Set<string> {
  const bindings = new Set<string>()
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

function namespacesDestructuredIntoJSXBindings(program: Node, jsxBindings: Set<string>): Set<string> {
  const namespaceAliases = new Map<string, Set<string>>()
  const destructuredValues = new Set<string>()
  const addNamespaceAlias = (source: string, alias: string) => {
    const aliases = namespaceAliases.get(source) ?? new Set<string>()
    aliases.add(alias)
    namespaceAliases.set(source, aliases)
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
  let changed = true
  while (changed) {
    changed = false
    for (const [source, aliases] of namespaceAliases) {
      if (!required.has(source) && [...aliases].some(alias => required.has(alias))) {
        required.add(source)
        changed = true
      }
    }
  }
  return required
}

/** Carries opaque package-component provenance through statically read local modules. */
function localComponentOrigins(sources: SourceFile[], configRoot: string): Map<string, Map<string, { source: string }>> {
  const moduleResolver = localModuleResolver(configRoot)
  const programs = sources.map(source => {
    const parsed = parseSync(source.file, source.code, { lang: source.file.endsWith('.tsx') ? 'tsx' : 'ts' })
    if (parsed.errors.length) throw new Error(`${source.file}: ${parsed.errors.map(error => error.message).join('; ')}`)
    return { ...source, absolutePath: resolve(repositoryRoot, source.file), program: parsed.program as unknown as Node }
  })
  const byPath = new Map(programs.map(source => [source.absolutePath, source]))
  const exportsByPath = new Map<string, Map<string, { source: string }>>()
  const isOpaquePackage = (specifier: string) => !moduleResolver.isLocalSpecifier(specifier)
    && !specifier.startsWith('node:')
    && !specifier.startsWith('#')
    && !/^[a-z][a-z\d+.-]*:/i.test(specifier)
    && specifier !== 'react'
    && !specifier.startsWith('react/')
    && specifier !== 'react-dom'
    && !specifier.startsWith('react-dom/')
    && ![...routerModules].some(module => specifier === module || specifier.startsWith(`${module}/`))
    && specifier !== 'lucide-react'
  const nameOf = (node: Node | undefined) => node?.type === 'Identifier' ? String(node.name) : undefined
  const addExport = (target: Map<string, { source: string }>, name: string, origin: { source: string } | undefined) => {
    if (origin) target.set(name, origin)
  }

  for (let pass = 0; pass <= programs.length; pass += 1) {
    let changed = false
    for (const source of programs) {
      const importedOrigins = new Map<string, { source: string }>()
      const jsxBindings = componentBindingsUsedInJSX(source.program)
      const jsxNamespaceBindings = namespacesDestructuredIntoJSXBindings(source.program, jsxBindings)
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
              if (/^[A-Z]/.test(localName) || jsxBindings.has(localName) || jsxNamespaceBindings.has(localName)) {
                importedOrigins.set(localName, { source: moduleSource })
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
            const importedName = specifier.type === 'ImportSpecifier' ? nameOf(specifier.imported as Node) : 'default'
            const origin = importedName ? targetExports.get(importedName) : undefined
            if (origin) importedOrigins.set(String((specifier.local as Node).name), origin)
          }
        }
      }

      const aliases = importedComponentAliases(source.program, importedOrigins)
      const nextExports = new Map<string, { source: string }>()
      for (const statement of source.program.body as Node[]) {
        if (statement.type === 'ExportDefaultDeclaration') {
          const declaration = statement.declaration as Node
          const localName = nameOf(declaration.type === 'FunctionDeclaration' || declaration.type === 'ClassDeclaration'
            ? declaration.id as Node | undefined
            : declaration)
          addExport(nextExports, 'default', localName ? aliases.get(localName) : undefined)
          if (!localName) {
            for (const rendered of renderedImportedComponents(declaration, aliases, source.file, new Set(), new Set(), new Map(), true)) {
              addExport(nextExports, 'default', aliases.get(rendered.component))
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
              const exportedName = nameOf(exportSpecifier.exported as Node)
              if (exportedName) addExport(nextExports, exportedName, { source: specifier })
            }
          }
          continue
        }

        const declaration = statement.declaration as Node | undefined
        if (declaration) {
          if ((declaration.type === 'FunctionDeclaration' || declaration.type === 'ClassDeclaration') && isNode(declaration.id)) {
            const name = String((declaration.id as Node).name)
            addExport(nextExports, name, aliases.get(name))
          } else if (declaration.type === 'VariableDeclaration') {
            for (const declarator of declaration.declarations as Node[]) {
              const name = nameOf(declarator.id as Node)
              if (name) addExport(nextExports, name, aliases.get(name))
            }
          }
        }
        for (const specifier of (statement.specifiers as Node[] | undefined) ?? []) {
          const localName = nameOf(specifier.local as Node)
          const exportedName = nameOf(specifier.exported as Node)
          if (localName && exportedName) addExport(nextExports, exportedName, aliases.get(localName))
        }
      }

      const current = exportsByPath.get(source.absolutePath) ?? new Map<string, { source: string }>()
      for (const [name, origin] of nextExports) {
        if (current.get(name)?.source === origin.source) continue
        current.set(name, origin)
        changed = true
      }
      exportsByPath.set(source.absolutePath, current)
    }
    if (!changed) break
  }
  return exportsByPath
}

/**
 * Reads every `<Routes>` of the given sources, named by the component that
 * renders it, with its `<Route>` tree.
 */
function extractRouters(sources: SourceFile[], configRoot = repositoryRoot): SourceRouter[] {
  const routers: SourceRouter[] = []
  const sourcePaths = new Set(sources.map(source => resolve(repositoryRoot, source.file)))
  const moduleResolver = localModuleResolver(configRoot)
  const crossModuleComponentOrigins = localComponentOrigins(sources, configRoot)
  for (const { file, code } of sources) {
    const parsed = parseSync(file, code, { lang: file.endsWith('.tsx') ? 'tsx' : 'ts' })
    if (parsed.errors.length) throw new Error(`${file}: ${parsed.errors.map(error => error.message).join('; ')}`)
    const program = parsed.program as unknown as Node
    rejectUninspectableRouterLoads(program, file)

    const local = { Route: new Set<string>(), Routes: new Set<string>() }
    const unresolvedRouterImports = new Map<string, { api: 'Route' | 'Routes'; source: string }>()
    const unresolvedRouterBindings = new Map<string, { source: string }>()
    const unresolvedLocalComponentImports = new Map<string, { source: string }>()
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
            && source !== 'react' && source !== 'react/jsx-runtime' && source !== 'lucide-react') {
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
            const importedName = specifier.type === 'ImportSpecifier' ? String((specifier.imported as Node).name) : 'default'
            const origin = moduleOrigins?.get(importedName)
            if (origin) uninspectableExternalComponentImports.set(String((specifier.local as Node).name), origin)
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
        if (imported === 'Route' || imported === 'Routes') local[imported].add(localName)
        if (unreadRouterAPIs.has(imported)) throw new Error(`${file} imports ${imported}; the console route inventory check reads only <Routes> and <Route> elements, so declare routes as JSX or teach src/console-route-inventory.test.ts the new API`)
      }
    }

    const reactFactories = reactCreateElementAliases(program, reactCreateElementImports, reactNamespaces)
    const reactLazies = reactLazyAliases(program, reactLazyImports, reactFactories.namespaces)
    const dynamicComponents = dynamicLazyComponentImports(program, reactLazies, reactFactories.namespaces, moduleResolver.isLocalSpecifier, file)
    const opaqueComponentImports = new Map(uninspectableExternalComponentImports)
    for (const [binding, origin] of dynamicComponents.bindings) {
      if (!opaqueComponentImports.has(binding)) opaqueComponentImports.set(binding, origin)
    }
    const importedExternalComponentBindings = importedComponentAliases(program, opaqueComponentImports)

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
        if (name.type === 'JSXIdentifier' && (name.name === 'Route' || name.name === 'Routes')) {
          const alias = String(name.name)
          if (unresolvedRouterAliases.has(alias)) return alias
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
    const collect = (nodes: Node[], where: string): SourceRoute[] => {
      const routes: SourceRoute[] = []
      nodes.forEach(node => assertReadableRouteChild(node, where))
      const visit = (node: Node) => {
        const name = jsxName(node)
        if (name && local.Route.has(name)) {
          collectedRoutes += 1
          const index = routeIndexAttribute(node, file, where)
          const pathAttribute = jsxAttribute(node, 'path')
          const path = pathAttribute ? stringValue(pathAttribute.value as Node, `A <Route> path in ${where} in ${file}`) : undefined
          const elementValue = jsxAttribute(node, 'element')?.value as Node | undefined
          const componentAttribute = jsxAttribute(node, 'Component')
          const componentExpression = jsxExpressionAttribute(componentAttribute)
          const wildcard = path === '*' || !!path?.endsWith('/*')
          if (componentAttribute && wildcard && !readableComponentExpression(componentExpression, dynamicComponents.readableCalls, reactNamespaces)) {
            throw new Error(`${file}: <Route> in ${where} has a Component prop the route inventory cannot read in wildcard route ${path}; use a statically readable component value so it can check for nested routes`)
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
            return renderedComponents(expression)
          }
          const uninspectableRenders = [
            ...renderedImportedComponents(elementValue, importedExternalComponentBindings, file, reactFactories.factories, reactFactories.namespaces, dynamicComponents.calls),
            ...renderedImportedComponents(componentAttribute?.value as Node | undefined, importedExternalComponentBindings, file, reactFactories.factories, reactFactories.namespaces, dynamicComponents.calls, true),
          ]
          routes.push({
            path,
            index,
            renders: [...renderedComponents(elementValue), ...componentReferences(componentExpression)],
            uninspectableRenders,
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
        const attributes = (node.openingElement as Node).attributes as Node[]
        if (attributes.some(attribute => attribute.type === 'JSXSpreadAttribute') || jsxAttribute(node, 'children')) {
          throw new Error(`${file}: <Routes> in ${current} must declare route children as direct JSX children, not a children prop or prop spread`)
        }
        const count = routers.filter(router => router.name === current || router.name.startsWith(`${current}#`)).length
        routers.push({ name: count ? `${current}#${count + 1}` : current, routes: collect(node.children as Node[], current) })
      }
      childNodes(node).forEach(child => walk(child, current))
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
  const byName = new Map(routers.map(router => [router.name, router]))
  const mounted = new Set<string>()

  const build = (declaring: string, routes: SourceRoute[], parent: string, handles: RouteHandle[], seen: Set<string>): RouteObject[] => routes.map(route => {
    const pattern = joinPattern(parent, route.path)
    const base = pattern.replace(/\/\*$/, '') || '/'
    if (route.path === '*' || route.path?.endsWith('/*')) {
      const uninspectable = route.uninspectableRenders[0]
      if (uninspectable) {
        throw new Error(`${uninspectable.file} renders imported component ${uninspectable.component} from ${uninspectable.source} in wildcard route ${pattern}; the console route inventory cannot inspect whether it owns nested <Routes>. Import a readable local TypeScript component or declare the nested routes directly in the audited JSX tree`)
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
    const base = jsExtensions.has(extension) ? path.slice(0, -extension.length) : path
    const candidates = tsExtensions.has(extension)
      ? [path]
      : [
          `${base}.ts`,
          `${base}.tsx`,
          `${base}.mts`,
          `${base}.cts`,
          join(base, 'index.ts'),
          join(base, 'index.tsx'),
          join(base, 'index.mts'),
          join(base, 'index.cts'),
        ]
    for (const candidate of candidates) {
      if (!existsSync(candidate) || !statSync(candidate).isFile() || candidate.endsWith('.d.ts') || /\.test\.(?:ts|tsx)$/.test(candidate)) continue
      const canonical = isAllowedPath(candidate)
      if (canonical) return canonical
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
    for (const entry of readdirSync(canonicalPath, { withFileTypes: true })) {
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
    const moduleSpecifiers = new Set(runtimeModuleLoads)
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
      if (!path && runtimeModuleLoads.includes(specifier)) {
        throw new Error(`${source.file} loads local module ${specifier} that the console route inventory cannot inspect as TypeScript`)
      }
      if (path) addFile(path)
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
        expect(() => resolveRouters(extractRouters([source])), source.file).toThrow(/renders imported component NestedRoutes from third-party-router in wildcard route \/known\/\*; the console route inventory cannot inspect whether it owns nested <Routes>/)
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

        writeFileSync(wrapperPath, `import { useTitle } from 'third-party-router'
export function Fallback() { useTitle('safe'); return <main /> }
`)
        const safeSources = sourceFiles(sourceDirectory, fixtureRoot)
        expect(resolveRouters(extractRouters(safeSources, fixtureRoot))[0].handles.map(label)).toEqual(['Shell *'])
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
        ).toThrow(/renders imported component (?:NestedRoutes|PackageNestedRoutes|Routed|localRoutes|nestedRoutes|nestedRoutesAlias) from third-party-router in wildcard route \/known\/\*; the console route inventory cannot inspect whether it owns nested <Routes>/)
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
        /renders imported component nestedRoutes from third-party-router in wildcard route \/known\/\*/,
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
        expect(() => inventoryProblems(resolveRouters(extractRouters([source])), exactInventory), source.file).toThrow(
          /renders imported component nestedRoutes from third-party-router in wildcard route \/known\/\*/,
        )
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
        /renders imported component target from third-party-router in wildcard route \/known\/\*/,
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

        const sources = sourceFiles(sourceDirectory, fixtureRoot)
        expect(sources.some(source => source.file.includes('OutsideRouter.tsx'))).toBe(false)
        expect(() => extractRouters(sources, fixtureRoot)).toThrow(/uses JSX component (?:OutsideRouter|LinkedRouter) from unresolved local module/)
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
        const unreadableReexportSources = sourceFiles(sourceDirectory, fixtureRoot)
        expect(unreadableReexportSources.some(source => source.file.endsWith('/router-bindings.ts'))).toBe(true)
        expect(() => extractRouters(unreadableReexportSources, fixtureRoot)).toThrow(/re-exports from unreadable local module \.\/router-runtime\.js/)
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
