package web

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// The route drift test parses the routing functions of this package and
// collects the conditions that select a handler. The routing functions are
// Server.api, Server.publicAPI, Server.Handler, and every sub-router: a Server
// method that routes on len(parts) or parts[i] and is handed the rest of the
// path with strings.TrimPrefix(path, "/prefix/"). Each condition is reduced
// to atoms:
//
//   - path == "/lit", or a comparison on r.URL.Path;
//   - strings.HasPrefix/HasSuffix(path, "/lit") and strings.Contains(..., "/lit");
//   - len(parts) == N and parts[i] == "lit" in sub-routers that split the
//     remaining path into parts;
//   - r.Method == http.MethodX, including switch r.Method cases;
//   - r.URL.Query().Get("key") == "value".
//
// Conditions nest: a handler inside if len(parts) == 2 inherits that
// constraint. A guard such as if len(parts) != 1 { return } narrows the
// statements after it. Every condition that carries a routing atom must match
// an inventory entry, and every inventory entry must be dispatched by a
// method-specific condition, unless it is marked NoHandler. Slash-prefixed
// literals elsewhere in the routing functions must be part of an inventory
// template, or be documented in routeDriftAllowlist.

// routeDriftPathRouters are the functions that route on literal paths, and
// the path form (relative to the API base, or absolute) that they compare.
var routeDriftPathRouters = map[string]func(apiRoute) (string, bool){
	"api": func(route apiRoute) (string, bool) {
		return route.Template, route.Access != routePublic
	},
	"publicAPI": func(route apiRoute) (string, bool) {
		return publicAPIBase + route.Template, route.Access == routePublic
	},
	"Handler": func(route apiRoute) (string, bool) {
		if route.Access == routePublic {
			return publicAPIBase + route.Template, true
		}
		return consoleAPIBase + route.Template, true
	},
}

// routeDriftAllowlist documents slash-prefixed string literals in routing
// functions that are not API routes, keyed by function and then literal.
var routeDriftAllowlist = map[string]map[string]string{
	"api": {
		consoleAPIBase: "the console API base that api strips from r.URL.Path; inventory templates are relative to it",
	},
	"Handler": {
		"/assets/": "embedded console assets served by asset, not an API route",
	},
}

// routeDriftNonAPIPathFunctions are Server methods that compare request paths
// but do not serve API routes. Any other method that compares a path against
// a slash-prefixed literal must be listed in routeDriftPathRouters.
var routeDriftNonAPIPathFunctions = map[string]string{
	"spa": "serves the console shell and static files, and rejects every /api/ path",
}

type routeAtoms struct {
	method   string
	exact    []string
	prefix   []string
	suffix   []string
	contains []string
	query    string
	// length is len(parts), or -1 when the condition does not fix it.
	length   int
	segments map[int]string
	// route reports whether the condition itself carried a routing atom.
	route    bool
	conflict bool
}

func newRouteAtoms() routeAtoms { return routeAtoms{length: -1} }

func (a routeAtoms) merge(b routeAtoms) routeAtoms {
	out := routeAtoms{
		method:   a.method,
		exact:    append(slices.Clone(a.exact), b.exact...),
		prefix:   append(slices.Clone(a.prefix), b.prefix...),
		suffix:   append(slices.Clone(a.suffix), b.suffix...),
		contains: append(slices.Clone(a.contains), b.contains...),
		query:    a.query,
		length:   a.length,
		segments: map[int]string{},
		route:    a.route || b.route,
		conflict: a.conflict || b.conflict,
	}
	for index, value := range a.segments {
		out.segments[index] = value
	}
	if b.method != "" {
		out.conflict = out.conflict || (out.method != "" && out.method != b.method)
		out.method = b.method
	}
	if b.query != "" {
		out.conflict = out.conflict || (out.query != "" && out.query != b.query)
		out.query = b.query
	}
	if b.length >= 0 {
		out.conflict = out.conflict || (out.length >= 0 && out.length != b.length)
		out.length = b.length
	}
	for index, value := range b.segments {
		if old, ok := out.segments[index]; ok && old != value {
			out.conflict = true
		}
		out.segments[index] = value
	}
	return out
}

// partsShape normalizes a sub-router condition. strings.Split of an empty
// rest yields one empty part, so parts[0] == "" selects the router root.
func (a routeAtoms) partsShape() (length int, segments map[int]string, root bool) {
	if value, ok := a.segments[0]; ok && value == "" {
		return 0, nil, true
	}
	if a.length == 0 {
		return 0, nil, true
	}
	return a.length, a.segments, false
}

func (a routeAtoms) hasParts() bool { return a.length >= 0 || len(a.segments) > 0 }

func (a routeAtoms) hasPath() bool {
	return len(a.exact)+len(a.prefix)+len(a.suffix)+len(a.contains) > 0
}

type routeObservation struct {
	function string
	pos      token.Position
	atoms    routeAtoms
	// prefixes are the console paths a sub-router receives its rest from.
	prefixes []string
	parts    bool
	view     func(apiRoute) (string, bool)
}

func (o routeObservation) method() string {
	if o.atoms.method == "" {
		return "ANY"
	}
	return o.atoms.method
}

func (o routeObservation) describe() string {
	var pattern string
	if o.parts {
		length, segments, root := o.atoms.partsShape()
		prefix := strings.Join(o.prefixes, " and ")
		switch {
		case root:
			pattern = prefix
		case length < 0:
			keys := make([]int, 0, len(segments))
			for index := range segments {
				keys = append(keys, index)
			}
			sort.Ints(keys)
			parts := make([]string, 0, len(keys))
			for _, index := range keys {
				parts = append(parts, fmt.Sprintf("parts[%d]==%q", index, segments[index]))
			}
			pattern = prefix + "/... (" + strings.Join(parts, ", ") + ")"
		default:
			parts := make([]string, length)
			for index := range parts {
				parts[index] = "{*}"
				if value, ok := segments[index]; ok {
					parts[index] = value
				}
			}
			pattern = prefix + "/" + strings.Join(parts, "/")
		}
	} else {
		var pieces []string
		pieces = append(pieces, o.atoms.exact...)
		for _, value := range o.atoms.prefix {
			pieces = append(pieces, value+"...")
		}
		for _, value := range o.atoms.contains {
			pieces = append(pieces, "..."+value+"...")
		}
		for _, value := range o.atoms.suffix {
			pieces = append(pieces, "..."+value)
		}
		pattern = strings.Join(pieces, " & ")
	}
	if o.atoms.query != "" {
		pattern += "?" + o.atoms.query
	}
	return o.method() + " " + pattern
}

// matches reports whether an observed routing condition selects an
// inventory route. Sub-router conditions are strict: a segment that the
// condition does not fix must be a placeholder in the template.
func (o routeObservation) matches(route apiRoute) bool {
	view, ok := o.view(route)
	if !ok {
		return false
	}
	if o.atoms.method != "" && o.atoms.method != route.Method {
		return false
	}
	if o.atoms.query != "" && o.atoms.query != route.Query {
		return false
	}
	for _, value := range o.atoms.exact {
		if view != value {
			return false
		}
	}
	for _, value := range o.atoms.prefix {
		if !strings.HasPrefix(view, value) {
			return false
		}
	}
	for _, value := range o.atoms.suffix {
		if !strings.HasSuffix(view, value) {
			return false
		}
	}
	for _, value := range o.atoms.contains {
		if !strings.Contains(view, value) {
			return false
		}
	}
	if !o.parts {
		return true
	}
	length, segments, root := o.atoms.partsShape()
	for _, prefix := range o.prefixes {
		if root {
			if view == prefix {
				return true
			}
			continue
		}
		if !strings.HasPrefix(view, prefix+"/") {
			continue
		}
		parts := strings.Split(strings.TrimPrefix(view, prefix+"/"), "/")
		if length >= 0 && len(parts) != length {
			continue
		}
		matched := true
		for index, value := range segments {
			if index >= len(parts) || parts[index] != value {
				matched = false
			}
		}
		if length >= 0 {
			for index, part := range parts {
				if _, fixed := segments[index]; !fixed && !isRoutePlaceholder(part) {
					matched = false
				}
			}
		}
		if matched {
			return true
		}
	}
	return false
}

type routeDriftFindingKind string

const (
	routeDriftUnlistedRoute   routeDriftFindingKind = "unlisted route"
	routeDriftUnlistedLiteral routeDriftFindingKind = "unlisted path literal"
	routeDriftUnknownRouter   routeDriftFindingKind = "unknown router"
	routeDriftStaleEntry      routeDriftFindingKind = "stale inventory entry"
)

type routeDriftFinding struct {
	kind    routeDriftFindingKind
	message string
}

type routeDriftAnalyzer struct {
	fset         *token.FileSet
	observations []routeObservation
	findings     []routeDriftFinding
	consumed     map[token.Pos]bool
	current      routeObservation
}

var httpMethodConstants = map[string]string{
	"MethodGet": http.MethodGet, "MethodHead": http.MethodHead, "MethodPost": http.MethodPost,
	"MethodPut": http.MethodPut, "MethodPatch": http.MethodPatch, "MethodDelete": http.MethodDelete,
	"MethodConnect": http.MethodConnect, "MethodOptions": http.MethodOptions, "MethodTrace": http.MethodTrace,
}

func unparen(expr ast.Expr) ast.Expr {
	for {
		paren, ok := expr.(*ast.ParenExpr)
		if !ok {
			return expr
		}
		expr = paren.X
	}
}

func stringLiteral(expr ast.Expr) (*ast.BasicLit, string, bool) {
	literal, ok := unparen(expr).(*ast.BasicLit)
	if !ok || literal.Kind != token.STRING {
		return nil, "", false
	}
	value, err := strconv.Unquote(literal.Value)
	if err != nil {
		return nil, "", false
	}
	return literal, value, true
}

func isIdent(expr ast.Expr, name string) bool {
	ident, ok := unparen(expr).(*ast.Ident)
	return ok && ident.Name == name
}

func isRequestMethod(expr ast.Expr) bool {
	selector, ok := unparen(expr).(*ast.SelectorExpr)
	return ok && selector.Sel.Name == "Method"
}

func httpMethodValue(expr ast.Expr) (string, bool) {
	if selector, ok := unparen(expr).(*ast.SelectorExpr); ok && isIdent(selector.X, "http") {
		method, known := httpMethodConstants[selector.Sel.Name]
		return method, known
	}
	if _, value, ok := stringLiteral(expr); ok {
		for _, method := range httpMethodConstants {
			if value == method {
				return method, true
			}
		}
	}
	return "", false
}

// mentionsRequestPath reports whether an expression reads the routed path:
// the local path variable or r.URL.Path.
func mentionsRequestPath(expr ast.Expr) bool {
	found := false
	ast.Inspect(expr, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.Ident:
			if value.Name == "path" {
				found = true
			}
		case *ast.SelectorExpr:
			if inner, ok := value.X.(*ast.SelectorExpr); ok && value.Sel.Name == "Path" && inner.Sel.Name == "URL" {
				found = true
			}
		}
		return !found
	})
	return found
}

func isPartsLength(expr ast.Expr) bool {
	call, ok := unparen(expr).(*ast.CallExpr)
	return ok && isIdent(call.Fun, "len") && len(call.Args) == 1 && isIdent(call.Args[0], "parts")
}

func partsIndex(expr ast.Expr) (int, bool) {
	index, ok := unparen(expr).(*ast.IndexExpr)
	if !ok || !isIdent(index.X, "parts") {
		return 0, false
	}
	literal, ok := unparen(index.Index).(*ast.BasicLit)
	if !ok || literal.Kind != token.INT {
		return 0, false
	}
	value, err := strconv.Atoi(literal.Value)
	return value, err == nil
}

func queryKey(expr ast.Expr) (string, bool) {
	call, ok := unparen(expr).(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return "", false
	}
	get, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || get.Sel.Name != "Get" {
		return "", false
	}
	inner, ok := unparen(get.X).(*ast.CallExpr)
	if !ok {
		return "", false
	}
	query, ok := inner.Fun.(*ast.SelectorExpr)
	if !ok || query.Sel.Name != "Query" {
		return "", false
	}
	_, key, ok := stringLiteral(call.Args[0])
	return key, ok
}

// comparisonAtom recognizes an equality between a routing input and a
// constant, in either order.
func (a *routeDriftAnalyzer) comparisonAtom(left, right ast.Expr) (routeAtoms, bool) {
	for _, pair := range [][2]ast.Expr{{left, right}, {right, left}} {
		subject, value := pair[0], pair[1]
		atoms := newRouteAtoms()
		atoms.route = true
		switch {
		case isRequestMethod(subject):
			if method, ok := httpMethodValue(value); ok {
				atoms.method = method
				return atoms, true
			}
		case isPartsLength(subject):
			if literal, ok := unparen(value).(*ast.BasicLit); ok && literal.Kind == token.INT {
				if length, err := strconv.Atoi(literal.Value); err == nil {
					atoms.length = length
					return atoms, true
				}
			}
		}
		if index, ok := partsIndex(subject); ok {
			if _, literal, ok := stringLiteral(value); ok {
				atoms.segments = map[int]string{index: literal}
				return atoms, true
			}
		}
		if key, ok := queryKey(subject); ok {
			if _, literal, ok := stringLiteral(value); ok {
				atoms.query = key + "=" + literal
				return atoms, true
			}
		}
		if mentionsRequestPath(subject) {
			if node, literal, ok := stringLiteral(value); ok && strings.HasPrefix(literal, "/") {
				a.consumed[node.Pos()] = true
				atoms.exact = []string{literal}
				return atoms, true
			}
		}
	}
	return routeAtoms{}, false
}

func (a *routeDriftAnalyzer) callAtom(call *ast.CallExpr) (routeAtoms, bool) {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !isIdent(selector.X, "strings") || len(call.Args) != 2 || !mentionsRequestPath(call.Args[0]) {
		return routeAtoms{}, false
	}
	node, literal, ok := stringLiteral(call.Args[1])
	if !ok || !strings.HasPrefix(literal, "/") {
		return routeAtoms{}, false
	}
	atoms := newRouteAtoms()
	atoms.route = true
	switch selector.Sel.Name {
	case "HasPrefix":
		atoms.prefix = []string{literal}
	case "HasSuffix":
		atoms.suffix = []string{literal}
	case "Contains":
		atoms.contains = []string{literal}
	default:
		return routeAtoms{}, false
	}
	a.consumed[node.Pos()] = true
	return atoms, true
}

// alternatives converts a condition into disjunctive normal form over
// routing atoms. Sub-expressions that are not routing atoms are ignored.
func (a *routeDriftAnalyzer) alternatives(expr ast.Expr) []routeAtoms {
	switch value := unparen(expr).(type) {
	case *ast.BinaryExpr:
		switch value.Op {
		case token.LOR:
			return append(a.alternatives(value.X), a.alternatives(value.Y)...)
		case token.LAND:
			var out []routeAtoms
			for _, left := range a.alternatives(value.X) {
				for _, right := range a.alternatives(value.Y) {
					if merged := left.merge(right); !merged.conflict {
						out = append(out, merged)
					}
				}
			}
			return out
		case token.EQL:
			if atoms, ok := a.comparisonAtom(value.X, value.Y); ok {
				return []routeAtoms{atoms}
			}
		}
	case *ast.CallExpr:
		if atoms, ok := a.callAtom(value); ok {
			return []routeAtoms{atoms}
		}
	}
	return []routeAtoms{newRouteAtoms()}
}

// negatedGuard recognizes a condition such as
// r.Method != http.MethodGet || path != "/x", whose body rejects everything
// except the route formed by the equal atoms.
func (a *routeDriftAnalyzer) negatedGuard(expr ast.Expr) (routeAtoms, bool) {
	var leaves []ast.Expr
	var collect func(ast.Expr)
	collect = func(node ast.Expr) {
		if binary, ok := unparen(node).(*ast.BinaryExpr); ok && binary.Op == token.LOR {
			collect(binary.X)
			collect(binary.Y)
			return
		}
		leaves = append(leaves, unparen(node))
	}
	collect(expr)
	guard := newRouteAtoms()
	for _, leaf := range leaves {
		binary, ok := leaf.(*ast.BinaryExpr)
		if !ok || binary.Op != token.NEQ {
			return routeAtoms{}, false
		}
		atoms, ok := a.comparisonAtom(binary.X, binary.Y)
		if !ok {
			return routeAtoms{}, false
		}
		guard = guard.merge(atoms)
	}
	return guard, !guard.conflict
}

func (a *routeDriftAnalyzer) branch(context []routeAtoms, alternatives []routeAtoms, pos token.Pos) []routeAtoms {
	var merged []routeAtoms
	for _, inherited := range context {
		for _, alternative := range alternatives {
			combined := inherited.merge(alternative)
			if combined.conflict {
				continue
			}
			merged = append(merged, combined)
			if !alternative.route {
				continue
			}
			observation := a.current
			observation.pos = a.fset.Position(pos)
			observation.atoms = combined
			if !observation.parts {
				a.observations = append(a.observations, observation)
				continue
			}
			// A sub-router served under several prefixes must have the
			// route listed under each of them.
			for _, prefix := range a.current.prefixes {
				observation.prefixes = []string{prefix}
				a.observations = append(a.observations, observation)
			}
		}
	}
	return merged
}

func terminates(block *ast.BlockStmt) bool {
	if block == nil || len(block.List) == 0 {
		return false
	}
	_, ok := block.List[len(block.List)-1].(*ast.ReturnStmt)
	return ok
}

func (a *routeDriftAnalyzer) walk(statements []ast.Stmt, context []routeAtoms) {
	for _, statement := range statements {
		switch value := statement.(type) {
		case *ast.IfStmt:
			if guard, ok := a.negatedGuard(value.Cond); ok {
				merged := a.branch(context, []routeAtoms{guard}, value.Cond.Pos())
				a.walk(value.Body.List, context)
				if value.Else != nil {
					a.walk([]ast.Stmt{value.Else}, merged)
				}
				if terminates(value.Body) {
					context = merged
				}
				continue
			}
			merged := a.branch(context, a.alternatives(value.Cond), value.Cond.Pos())
			a.walk(value.Body.List, merged)
			if value.Else != nil {
				a.walk([]ast.Stmt{value.Else}, context)
			}
		case *ast.SwitchStmt:
			for _, clauseStatement := range value.Body.List {
				clause := clauseStatement.(*ast.CaseClause)
				if clause.List == nil {
					a.walk(clause.Body, context)
					continue
				}
				var alternatives []routeAtoms
				for _, expr := range clause.List {
					if value.Tag == nil {
						alternatives = append(alternatives, a.alternatives(expr)...)
						continue
					}
					if atoms, ok := a.comparisonAtom(value.Tag, expr); ok {
						alternatives = append(alternatives, atoms)
					} else {
						alternatives = append(alternatives, newRouteAtoms())
					}
				}
				a.walk(clause.Body, a.branch(context, alternatives, clause.Pos()))
			}
		case *ast.BlockStmt:
			a.walk(value.List, context)
		case *ast.ForStmt:
			a.walk(value.Body.List, context)
		case *ast.RangeStmt:
			a.walk(value.Body.List, context)
		case *ast.LabeledStmt:
			a.walk([]ast.Stmt{value.Stmt}, context)
		default:
			// Handlers defined inline, such as the Host guard in Handler,
			// route in the context of the statement that defines them.
			ast.Inspect(statement, func(node ast.Node) bool {
				if literal, ok := node.(*ast.FuncLit); ok {
					a.walk(literal.Body.List, context)
					return false
				}
				return true
			})
		}
	}
}

func serverMethods(files []*ast.File) map[string]*ast.FuncDecl {
	methods := map[string]*ast.FuncDecl{}
	for _, file := range files {
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Recv == nil || len(function.Recv.List) != 1 || function.Body == nil {
				continue
			}
			star, ok := function.Recv.List[0].Type.(*ast.StarExpr)
			if ok && isIdent(star.X, "Server") {
				methods[function.Name.Name] = function
			}
		}
	}
	return methods
}

// conditionAtoms lists the routing atoms used in the if and switch
// conditions of a function, including those in function literals.
func (a *routeDriftAnalyzer) conditionAtoms(body *ast.BlockStmt) []routeAtoms {
	var out []routeAtoms
	collect := func(expr ast.Expr) {
		ast.Inspect(expr, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.BinaryExpr:
				if value.Op == token.EQL || value.Op == token.NEQ {
					if atoms, ok := a.comparisonAtom(value.X, value.Y); ok {
						out = append(out, atoms)
					}
				}
			case *ast.CallExpr:
				if atoms, ok := a.callAtom(value); ok {
					out = append(out, atoms)
				}
			}
			return true
		})
	}
	ast.Inspect(body, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.IfStmt:
			collect(value.Cond)
		case *ast.SwitchStmt:
			if value.Tag != nil {
				for _, clause := range value.Body.List {
					for _, expr := range clause.(*ast.CaseClause).List {
						if atoms, ok := a.comparisonAtom(value.Tag, expr); ok {
							out = append(out, atoms)
						}
					}
				}
			}
		case *ast.CaseClause:
			for _, expr := range value.List {
				collect(expr)
			}
		}
		return true
	})
	return out
}

// subRouterPrefixes finds where api hands the rest of a path to a
// sub-router: s.name(..., strings.TrimPrefix(path, "/prefix/")).
func subRouterPrefixes(methods map[string]*ast.FuncDecl, name string) []string {
	var prefixes []string
	for _, function := range methods {
		ast.Inspect(function.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || selector.Sel.Name != name {
				return true
			}
			for _, argument := range call.Args {
				trim, ok := unparen(argument).(*ast.CallExpr)
				if !ok || len(trim.Args) != 2 || !mentionsRequestPath(trim.Args[0]) {
					continue
				}
				trimSelector, ok := trim.Fun.(*ast.SelectorExpr)
				if !ok || !isIdent(trimSelector.X, "strings") || trimSelector.Sel.Name != "TrimPrefix" {
					continue
				}
				if _, prefix, ok := stringLiteral(trim.Args[1]); ok {
					prefix = strings.TrimSuffix(prefix, "/")
					if !slices.Contains(prefixes, prefix) {
						prefixes = append(prefixes, prefix)
					}
				}
			}
			return true
		})
	}
	sort.Strings(prefixes)
	return prefixes
}

// analyzeRouteDrift compares routing source files with a route inventory.
func analyzeRouteDrift(fset *token.FileSet, files []*ast.File, routes []apiRoute) []routeDriftFinding {
	analyzer := &routeDriftAnalyzer{fset: fset, consumed: map[token.Pos]bool{}}
	// Discovery uses its own analyzer so that it does not mark literals as
	// consumed by conditions the walk below never reaches.
	discovery := &routeDriftAnalyzer{fset: fset, consumed: map[token.Pos]bool{}}
	methods := serverMethods(files)
	names := make([]string, 0, len(methods))
	for name := range methods {
		names = append(names, name)
	}
	sort.Strings(names)

	type target struct {
		name     string
		parts    bool
		prefixes []string
		view     func(apiRoute) (string, bool)
	}
	var targets []target
	for _, name := range names {
		var partsRouter, pathRouter bool
		for _, atoms := range discovery.conditionAtoms(methods[name].Body) {
			partsRouter = partsRouter || atoms.hasParts()
			pathRouter = pathRouter || atoms.hasPath()
		}
		if view, ok := routeDriftPathRouters[name]; ok {
			targets = append(targets, target{name: name, view: view})
			continue
		}
		if partsRouter {
			prefixes := subRouterPrefixes(methods, name)
			if len(prefixes) == 0 {
				analyzer.findings = append(analyzer.findings, routeDriftFinding{routeDriftUnknownRouter, fmt.Sprintf("%s routes on len(parts) or parts[i], but no call hands it strings.TrimPrefix(path, prefix); dispatch it that way or teach the route drift test its prefix", name)})
				continue
			}
			targets = append(targets, target{name: name, parts: true, prefixes: prefixes, view: routeDriftPathRouters["api"]})
			continue
		}
		if pathRouter {
			if _, ok := routeDriftNonAPIPathFunctions[name]; !ok {
				analyzer.findings = append(analyzer.findings, routeDriftFinding{routeDriftUnknownRouter, fmt.Sprintf("%s compares the request path with a slash-prefixed literal but is not a known router; add it to routeDriftPathRouters or document it in routeDriftNonAPIPathFunctions", name)})
			}
		}
	}

	for _, target := range targets {
		function := methods[target.name]
		analyzer.current = routeObservation{function: target.name, parts: target.parts, prefixes: target.prefixes, view: target.view}
		analyzer.walk(function.Body.List, []routeAtoms{newRouteAtoms()})
		// Every other slash-prefixed literal must be part of a template.
		ast.Inspect(function.Body, func(node ast.Node) bool {
			literal, ok := node.(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING || analyzer.consumed[literal.Pos()] {
				return true
			}
			value, err := strconv.Unquote(literal.Value)
			if err != nil || !strings.HasPrefix(value, "/") {
				return true
			}
			if _, allowed := routeDriftAllowlist[target.name][value]; allowed {
				return true
			}
			for _, route := range routes {
				if view, ok := target.view(route); ok && strings.Contains(view, value) {
					return true
				}
			}
			analyzer.findings = append(analyzer.findings, routeDriftFinding{routeDriftUnlistedLiteral, fmt.Sprintf("%s: %s uses path literal %q, which is not part of any route inventory template; add the route to apiRoutes in permissions.go, or document a non-route literal in routeDriftAllowlist", fset.Position(literal.Pos()), target.name, value)})
			return true
		})
	}

	for _, observation := range analyzer.observations {
		matched := false
		for _, route := range routes {
			if observation.matches(route) {
				matched = true
				break
			}
		}
		if !matched {
			analyzer.findings = append(analyzer.findings, routeDriftFinding{routeDriftUnlistedRoute, fmt.Sprintf("%s: %s routes %s, but no route inventory entry matches it; add the route and its permission to apiRoutes in permissions.go", observation.pos, observation.function, observation.describe())})
		}
	}

	for _, route := range routes {
		var dispatchedAt []string
		for _, observation := range analyzer.observations {
			if observation.atoms.method == route.Method && observation.atoms.query == route.Query && observation.matches(route) {
				dispatchedAt = append(dispatchedAt, fmt.Sprintf("%s (%s)", observation.pos, observation.function))
			}
		}
		switch {
		case route.NoHandler && len(dispatchedAt) > 0:
			analyzer.findings = append(analyzer.findings, routeDriftFinding{routeDriftStaleEntry, fmt.Sprintf("%s is marked NoHandler but is dispatched at %s; clear NoHandler", routeInventoryName(route), strings.Join(dispatchedAt, ", "))})
		case !route.NoHandler && len(dispatchedAt) == 0:
			analyzer.findings = append(analyzer.findings, routeDriftFinding{routeDriftStaleEntry, fmt.Sprintf("%s is in the route inventory, but no method-specific routing condition dispatches it; remove the entry or mark it NoHandler (a route moved to a new sub-router is found when that router compares len(parts) or parts[i] and is called with strings.TrimPrefix(path, prefix))", routeInventoryName(route))})
		}
	}
	return analyzer.findings
}

func parseWebPackageSource(t *testing.T) (*token.FileSet, []*ast.File) {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || filepath.Ext(name) != ".go" || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, file)
	}
	if len(files) == 0 {
		t.Fatal("no package source files were parsed")
	}
	return fset, files
}

func TestRouteInventoryCoversRoutingSource(t *testing.T) {
	fset, files := parseWebPackageSource(t)
	for _, finding := range analyzeRouteDrift(fset, files, apiRoutes) {
		t.Errorf("%s: %s", finding.kind, finding.message)
	}
	// Guard the analyzer itself: it must have found the routers it is meant
	// to cover, or an empty result would prove nothing.
	analyzer := &routeDriftAnalyzer{fset: fset, consumed: map[token.Pos]bool{}}
	methods := serverMethods(files)
	for _, name := range []string{"api", "publicAPI", "jobRoute", "usersRoute", "scannerProfilesRoute", "notificationDestinationRoute"} {
		function, ok := methods[name]
		if !ok {
			t.Errorf("routing function %s was not found", name)
			continue
		}
		if len(analyzer.conditionAtoms(function.Body)) == 0 {
			t.Errorf("routing function %s has no recognized routing conditions", name)
		}
	}
	for name, want := range map[string][]string{
		"jobRoute":                     {"/jobs"},
		"usersRoute":                   {"/users"},
		"scannerProfilesRoute":         {"/scanner-profiles", "/scanner/profiles"},
		"notificationDestinationRoute": {"/notifications/destinations"},
	} {
		if got := subRouterPrefixes(methods, name); !slices.Equal(got, want) {
			t.Errorf("%s prefixes = %v, want %v", name, got, want)
		}
	}
}

func TestRouteInventoryDriftDetectsUnlistedRoutes(t *testing.T) {
	// A synthetic router with one route that is in the inventory and several
	// that are not. The analyzer must report each unlisted one.
	const source = `package web

import (
	"net/http"
	"strings"
)

func (s *Server) api(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1")
	switch {
	case path == "/status" && r.Method == http.MethodGet:
		s.adminStatus(w, r)
	case path == "/debug/vars" && r.Method == http.MethodGet:
		s.debugVars(w, r)
	case path == "/hosts" && r.Method == http.MethodDelete:
		s.clearHosts(w, r)
	case strings.HasPrefix(path, "/scans/") && strings.HasSuffix(path, "/retry") && r.Method == http.MethodPost:
		s.retryScan(w, r)
	case strings.HasPrefix(path, "/jobs/"):
		s.jobRoute(w, r, strings.TrimPrefix(path, "/jobs/"))
	case strings.HasPrefix(path, "/exports/"):
		s.exportRoute(w, r)
	}
	s.redirect(w, r, "/legacy/console")
}

func (s *Server) jobRoute(w http.ResponseWriter, r *http.Request, rest string) {
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	id := parts[0]
	if len(parts) == 1 && r.Method == http.MethodGet {
		s.getJob(w, r, id)
		return
	}
	if len(parts) == 2 && parts[1] == "clone" && r.Method == http.MethodPost {
		s.cloneJob(w, r, id)
		return
	}
	if len(parts) == 1 && r.Method == http.MethodPatch {
		s.patchJob(w, r, id)
		return
	}
	if len(parts) == 1 && r.Method == http.MethodDelete {
		if r.URL.Query().Get("force") == "true" {
			s.forceDeleteJob(w, r, id)
		}
		return
	}
	if len(parts) != 3 {
		return
	}
	switch r.Method {
	case http.MethodGet:
		s.jobThing(w, r, id, parts[1], parts[2])
	}
}

func (s *Server) exportRoute(w http.ResponseWriter, r *http.Request, rest string) {
	parts := strings.Split(rest, "/")
	if len(parts) == 1 && r.Method == http.MethodGet {
		s.export(w, r, parts[0])
	}
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "synthetic.go", source, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	findings := analyzeRouteDrift(fset, []*ast.File{file}, apiRoutes)
	for _, want := range []struct {
		kind routeDriftFindingKind
		text string
	}{
		{routeDriftUnlistedRoute, "routes GET /debug/vars"},
		{routeDriftUnlistedRoute, "routes DELETE /hosts"},
		{routeDriftUnlistedRoute, "routes POST /scans/... & .../retry"},
		{routeDriftUnlistedRoute, "routes POST /jobs/{*}/clone"},
		{routeDriftUnlistedRoute, "routes PATCH /jobs/{*}"},
		{routeDriftUnlistedRoute, "routes DELETE /jobs/{*}?force=true"},
		{routeDriftUnlistedRoute, "routes GET /jobs/{*}/{*}/{*}"},
		{routeDriftUnlistedRoute, "routes ANY /exports/..."},
		{routeDriftUnlistedLiteral, `path literal "/legacy/console"`},
		{routeDriftUnknownRouter, "exportRoute routes on len(parts)"},
	} {
		found := false
		for _, finding := range findings {
			if finding.kind == want.kind && strings.Contains(finding.message, want.text) {
				found = true
			}
		}
		if !found {
			t.Errorf("synthetic drift was not reported: %s containing %q; findings:\n%s", want.kind, want.text, formatRouteDriftFindings(findings))
		}
	}
	// The listed routes in the snippet must not be reported as unlisted.
	for _, finding := range findings {
		if finding.kind == routeDriftUnlistedRoute && (strings.Contains(finding.message, "routes GET /status,") || strings.Contains(finding.message, "routes GET /jobs/{*},")) {
			t.Errorf("listed route reported as drift: %s", finding.message)
		}
	}
}

func TestRouteInventoryDriftDetectsRemovedEntries(t *testing.T) {
	fset, files := parseWebPackageSource(t)
	for _, removed := range []string{
		"GET /setup/status (unauthenticated)",
		"GET /status",
		"GET /scans/{id}/summary",
		"POST /scans/{id}/cancel",
		"GET /scans/{id}/hosts/{address}/rdap",
		"POST /jobs/{id}/run",
		"DELETE /jobs/{id}?permanent=true",
		"GET /jobs/{id}/baseline/hosts/{address}/rdap",
		"PATCH /users/{id}",
		"POST /scanner/profiles/{id}/restore",
		"DELETE /notifications/destinations/{id}",
		"GET " + publicAPIBase + "/dashboard",
	} {
		t.Run(removed, func(t *testing.T) {
			var reduced []apiRoute
			for _, route := range apiRoutes {
				if routeInventoryName(route) != removed {
					reduced = append(reduced, route)
				}
			}
			if len(reduced) != len(apiRoutes)-1 {
				t.Fatalf("inventory has no entry %q", removed)
			}
			findings := analyzeRouteDrift(fset, files, reduced)
			reported := false
			for _, finding := range findings {
				reported = reported || finding.kind == routeDriftUnlistedRoute
			}
			if !reported {
				t.Fatalf("removing %s from the inventory was not reported; findings:\n%s", removed, formatRouteDriftFindings(findings))
			}
		})
	}
	// Flipping NoHandler on a dispatched route, or clearing it on an
	// undispatched one, is reported as a stale entry.
	flipped := slices.Clone(apiRoutes)
	var flips int
	for index, route := range flipped {
		switch routeInventoryName(route) {
		case "GET /scans", "POST /scans":
			flipped[index].NoHandler = !route.NoHandler
			flips++
		}
	}
	if flips != 2 {
		t.Fatalf("flipped %d scan list entries, want 2", flips)
	}
	var stale []string
	for _, finding := range analyzeRouteDrift(fset, files, flipped) {
		if finding.kind == routeDriftStaleEntry {
			stale = append(stale, finding.message)
		}
	}
	if len(stale) != 2 || !strings.Contains(strings.Join(stale, "\n"), "GET /scans is marked NoHandler") || !strings.Contains(strings.Join(stale, "\n"), "POST /scans is in the route inventory") {
		t.Fatalf("stale NoHandler findings = %q", stale)
	}
}

func formatRouteDriftFindings(findings []routeDriftFinding) string {
	var lines []string
	for _, finding := range findings {
		lines = append(lines, "  "+string(finding.kind)+": "+finding.message)
	}
	return strings.Join(lines, "\n")
}
