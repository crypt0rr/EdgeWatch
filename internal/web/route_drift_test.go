package web

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// apiRoutes is the only router of the APIs. These checks parse the
// package's source and keep it that way: only the functions below read the
// request path, only Handler and the route tables register ServeMux
// patterns, and the handler of a route reads only the path values of its
// template. route_table_test.go checks the table itself.

// routePathReaders are the functions that may read the request path, and
// why. Any other function that reads it would be routing outside apiRoutes.
var routePathReaders = map[string]string{
	"match":          "the route tables match the request path against apiRoutes",
	"Handler":        "the host guard checks every /api/v1 request before routing",
	"asset":          "serves the embedded console assets",
	"spa":            "serves the console shell and static files, and rejects every /api/ path",
	"requestLogging": "logs the path of each request",
}

// handlerPatterns are the patterns that Handler registers on the outer
// ServeMux. Only the two API bases reach apiRoutes; /healthz and /metrics
// are served outside the versioned APIs, each by one handler that reads no
// path.
var handlerPatterns = map[string]bool{
	publicAPIBase + "/":  true,
	consoleAPIBase + "/": true,
	"/assets/":           true,
	"/source":            true,
	"/healthz":           true,
	"/metrics":           true,
	"/":                  true,
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

// routingSourceFindings reports routing outside apiRoutes: a function that
// reads the request path but is not in routePathReaders, a reader that no
// longer reads it, and a ServeMux registration outside Handler and
// registerRouteGroup, or of a pattern that Handler should not register.
func routingSourceFindings(fset *token.FileSet, files []*ast.File) []string {
	var findings []string
	reads := map[string]bool{}
	for _, file := range files {
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil {
				continue
			}
			name := function.Name.Name
			ast.Inspect(function.Body, func(node ast.Node) bool {
				switch node := node.(type) {
				case *ast.SelectorExpr:
					inner, ok := node.X.(*ast.SelectorExpr)
					if !ok || inner.Sel.Name != "URL" {
						return true
					}
					switch node.Sel.Name {
					case "Path", "RawPath", "EscapedPath":
						reads[name] = true
						if _, allowed := routePathReaders[name]; !allowed {
							findings = append(findings, fmt.Sprintf("%s: %s reads the request path; serve the route from apiRoutes, or document a function that is not a router in routePathReaders", fset.Position(node.Pos()), name))
						}
					}
				case *ast.CallExpr:
					selector, ok := node.Fun.(*ast.SelectorExpr)
					// ServeMux.Handle and HandleFunc take two arguments; a
					// route's Handle field takes four.
					if !ok || (selector.Sel.Name != "Handle" && selector.Sel.Name != "HandleFunc") || len(node.Args) != 2 {
						return true
					}
					pattern := ""
					if literal, ok := node.Args[0].(*ast.BasicLit); ok && literal.Kind == token.STRING {
						pattern, _ = strconv.Unquote(literal.Value)
					}
					switch {
					case name == "registerRouteGroup":
					case name == "Handler" && handlerPatterns[pattern]:
					default:
						findings = append(findings, fmt.Sprintf("%s: %s registers the ServeMux pattern %s outside the route table; add the route to apiRoutes", fset.Position(node.Pos()), name, describeExpr(node.Args[0])))
					}
				}
				return true
			})
		}
	}
	for name, reason := range routePathReaders {
		if !reads[name] {
			findings = append(findings, fmt.Sprintf("%s is in routePathReaders (%s) but no longer reads the request path; remove it", name, reason))
		}
	}
	sort.Strings(findings)
	return findings
}

// describeExpr describes an expression for a finding.
func describeExpr(expr ast.Expr) string {
	if literal, ok := expr.(*ast.BasicLit); ok {
		return literal.Value
	}
	return fmt.Sprintf("%T", expr)
}

// routeTableLiteral returns the composite literal that lists the entries
// of apiRoutes: the value itself, or the literal that withPathAlias takes.
// A copy that withPathAlias makes keeps its entry's handler, and the
// prefixes it swaps have no placeholder, so checking the entry checks the
// copy.
func routeTableLiteral(value ast.Expr) *ast.CompositeLit {
	if call, ok := value.(*ast.CallExpr); ok && len(call.Args) > 0 {
		value = call.Args[len(call.Args)-1]
	}
	literal, _ := value.(*ast.CompositeLit)
	return literal
}

// routePathValueFindings reports a route whose handler reads a path value
// that its template does not define, which would always read "". It reads
// the r.PathValue calls in each entry's Handle expression and in the
// functions and methods that the expression names or calls.
func routePathValueFindings(fset *token.FileSet, files []*ast.File) (findings []string, reads int) {
	functions := map[string]*ast.FuncDecl{}
	var table *ast.CompositeLit
	for _, file := range files {
		for _, declaration := range file.Decls {
			switch declaration := declaration.(type) {
			case *ast.FuncDecl:
				functions[declaration.Name.Name] = declaration
			case *ast.GenDecl:
				for _, spec := range declaration.Specs {
					value, ok := spec.(*ast.ValueSpec)
					if !ok || len(value.Names) != 1 || value.Names[0].Name != "apiRoutes" || len(value.Values) != 1 {
						continue
					}
					table = routeTableLiteral(value.Values[0])
				}
			}
		}
	}
	if table == nil {
		return []string{"the apiRoutes table was not found"}, 0
	}
	pathValues := func(node ast.Node) map[string]token.Pos {
		names := map[string]token.Pos{}
		ast.Inspect(node, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok || len(call.Args) != 1 {
				return true
			}
			if selector, ok := call.Fun.(*ast.SelectorExpr); ok && selector.Sel.Name == "PathValue" {
				if literal, ok := call.Args[0].(*ast.BasicLit); ok && literal.Kind == token.STRING {
					name, _ := strconv.Unquote(literal.Value)
					names[name] = call.Pos()
				}
			}
			return true
		})
		return names
	}
	for _, element := range table.Elts {
		entry, ok := element.(*ast.CompositeLit)
		if !ok {
			continue
		}
		var template string
		var handle ast.Expr
		for _, field := range entry.Elts {
			pair, ok := field.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			switch key, _ := pair.Key.(*ast.Ident); key.Name {
			case "Template":
				if literal, ok := pair.Value.(*ast.BasicLit); ok {
					template, _ = strconv.Unquote(literal.Value)
				}
			case "Handle":
				handle = pair.Value
			}
		}
		if handle == nil {
			continue
		}
		defined := map[string]bool{}
		for _, segment := range strings.Split(template, "/") {
			if name, _, ok := routePlaceholder(segment); ok {
				defined[name] = true
			}
		}
		// The handler reads the path values in its own expression and in
		// the functions it names: method expressions such as
		// (*Server).getJobRoute, adapters such as jobHandler, and the
		// methods its function literals call.
		scopes := []ast.Node{handle}
		ast.Inspect(handle, func(node ast.Node) bool {
			switch node := node.(type) {
			case *ast.SelectorExpr:
				if function := functions[node.Sel.Name]; function != nil && function.Recv != nil {
					scopes = append(scopes, function.Body)
				}
			case *ast.CallExpr:
				if ident, ok := node.Fun.(*ast.Ident); ok && functions[ident.Name] != nil {
					scopes = append(scopes, functions[ident.Name].Body)
				}
			}
			return true
		})
		for _, scope := range scopes {
			for name, pos := range pathValues(scope) {
				reads++
				if !defined[name] {
					findings = append(findings, fmt.Sprintf("%s: the handler of %s reads the path value %q, which its template does not define", fset.Position(pos), template, name))
				}
			}
		}
	}
	sort.Strings(findings)
	return findings, reads
}

func TestRoutingStaysInTheRouteTable(t *testing.T) {
	t.Parallel()
	fset, files := parseWebPackageSource(t)
	for _, finding := range routingSourceFindings(fset, files) {
		t.Error(finding)
	}
	findings, reads := routePathValueFindings(fset, files)
	for _, finding := range findings {
		t.Error(finding)
	}
	// Guard the check itself: the handlers read path values, so finding
	// none would prove nothing.
	if reads < 50 {
		t.Fatalf("found %d path value reads in the route handlers, want the handlers' own", reads)
	}
}

// The checks report a synthetic router outside the table, a stray ServeMux
// registration, and a handler that reads a path value its template lacks.
func TestRoutingSourceChecksReportDrift(t *testing.T) {
	t.Parallel()
	const source = `package web

import "net/http"

var apiRoutes = []apiRoute{
	{Method: http.MethodGet, Template: "/jobs/{id}", Handle: func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) { s.getJobRoute(w, r, c) }},
	{Method: http.MethodGet, Template: "/jobs/{id}/scans/{scan}", Handle: jobScanAdapter(func(s *Server, w http.ResponseWriter, r *http.Request) { _ = r.PathValue("scan") })},
	{Method: http.MethodGet, Template: "/scans/{id}", Handle: (*Server).getScanRoute},
}

func (s *Server) getJobRoute(w http.ResponseWriter, r *http.Request, c routeCall) { _ = r.PathValue("job") }

func jobScanAdapter(handle func(*Server, http.ResponseWriter, *http.Request)) routeHandler {
	return func(s *Server, w http.ResponseWriter, r *http.Request, c routeCall) { _ = r.PathValue("id"); handle(s, w, r) }
}

func (s *Server) getScanRoute(w http.ResponseWriter, r *http.Request, c routeCall) { _ = r.PathValue("address") }

func (s *Server) debugRoute(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api/v1/debug" {
		return
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/", s.api)
	mux.HandleFunc("/api/v1/debug", s.debugRoute)
	return mux
}

func (s *Server) extra(mux *http.ServeMux) {
	mux.Handle("/metrics", nil)
}
`
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "synthetic.go", source, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	routing := strings.Join(routingSourceFindings(fset, []*ast.File{file}), "\n")
	for _, want := range []string{
		"debugRoute reads the request path",
		`Handler registers the ServeMux pattern "/api/v1/debug"`,
		`extra registers the ServeMux pattern "/metrics"`,
		"spa is in routePathReaders",
	} {
		if !strings.Contains(routing, want) {
			t.Errorf("routing findings lack %q:\n%s", want, routing)
		}
	}
	if strings.Contains(routing, `pattern "/api/v1/"`) {
		t.Errorf("the console API base was reported:\n%s", routing)
	}
	findings, _ := routePathValueFindings(fset, []*ast.File{file})
	values := strings.Join(findings, "\n")
	for _, want := range []string{
		`the handler of /jobs/{id} reads the path value "job"`,
		`the handler of /scans/{id} reads the path value "address"`,
	} {
		if !strings.Contains(values, want) {
			t.Errorf("path value findings lack %q:\n%s", want, values)
		}
	}
	if len(findings) != 2 {
		t.Errorf("path value findings = %q, want the two above", findings)
	}
}
