package store

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// tenantSQLLintEnforceUnscoped turns the report of Store methods whose SQL
// touches tenant data without the tenant predicate into failures. It was
// false while the store's methods moved to TenantStore in slices, each
// behind a deprecated Store wrapper bound to DefaultTenantScope. The
// wrappers are gone, so a Store method must not read or write tenant data
// without the tenant predicate: that work belongs to TenantStore, or to
// SystemStore for the daemon. Only the account and legacy administrator
// methods of globalStoreMethods are exempt, because they run before a scope
// exists; see storeMethodMayBeUnscoped.
const tenantSQLLintEnforceUnscoped = true

// tenantInsertExemptions lists the functions that may insert into a direct
// table without naming tenant_id, keyed by function and table, with the
// exact number of such statements and the reason. Any other insert into a
// direct table must name tenant_id, because the column defaults attribute a
// row to the default tenant when a writer forgets it.
var tenantInsertExemptions = map[string]struct {
	count  int
	reason string
}{
	"migrateContextWithLogger:users":                            {1, "a migration step that runs before schema 52 adds users.tenant_id"},
	"migrateContextWithLogger:latest_scan_hosts":                {1, "a migration step that runs before schema 54 adds latest_scan_hosts.tenant_id"},
	"migrateContextWithLogger:security_audit":                   {1, "a migration step that runs before schema 51 adds security_audit.tenant_id"},
	"migration52Statements:users":                               {1, "copies the legacy administrator before the rebuild adds users.tenant_id"},
	"insertAuditEntryExec:security_audit":                       {1, "the fallback for a database before schema 51, whose table has no tenant_id"},
	"applyRestoreDeliveryPolicy:restore_quarantined_deliveries": {1, "the column list names tenant_id at run time when the restored outbox has the column"},
	"insertRestoreAuditTx:security_audit":                       {1, "the column list names tenant_id at run time when the restored table has the column"},
}

// sqlStatement is a string expression from the store's source that may hold
// SQL: a literal, or a concatenation in which operands that are not
// constants are replaced by sqlUnknown.
type sqlStatement struct {
	position string
	function string
	receiver string
	text     string
}

// sqlUnknown stands for an operand whose value the lint cannot see.
const sqlUnknown = "\x00"

// The patterns match SQL keywords in upper case, as the store writes them,
// so English text in error messages is not mistaken for SQL.
var (
	sqlTableKeyword = regexp.MustCompile(`\b(FROM|JOIN|INTO|UPDATE)\s+`)
	sqlInsertInto   = regexp.MustCompile(`\b(?:INSERT(?:\s+OR\s+[A-Z]+)?|REPLACE)\s+INTO\s+["` + "`" + `]?([A-Za-z_][A-Za-z0-9_]*)["` + "`" + `]?\s*`)
	sqlTenantColumn = regexp.MustCompile(`\btenant_id\b`)
	sqlDDL          = regexp.MustCompile(`^(?:CREATE|DROP|ALTER|PRAGMA)\b`)
	sqlIdentifier   = regexp.MustCompile(`^["` + "`" + `]?([A-Za-z_][A-Za-z0-9_]*)["` + "`" + `]?`)
	sqlAlias        = regexp.MustCompile(`^\s+(?:AS\s+)?([A-Za-z_][A-Za-z0-9_]*)`)
	sqlAliasStop    = map[string]bool{"WHERE": true, "JOIN": true, "LEFT": true, "INNER": true, "CROSS": true, "ON": true, "ORDER": true, "GROUP": true, "LIMIT": true, "SET": true, "VALUES": true, "SELECT": true, "USING": true, "UNION": true, "EXCEPT": true, "INTERSECT": true, "INDEXED": true, "NOT": true, "RETURNING": true, "DEFAULT": true}
)

// sqlTables returns the tables a statement reads or writes, in order.
func sqlTables(statement string) []string {
	var tables []string
	for _, match := range sqlTableKeyword.FindAllStringSubmatchIndex(statement, -1) {
		keyword := statement[match[2]:match[3]]
		rest := statement[match[1]:]
		for {
			name := sqlIdentifier.FindStringSubmatch(rest)
			if name == nil {
				break
			}
			tables = append(tables, name[1])
			rest = rest[len(name[0]):]
			if keyword != "FROM" {
				break
			}
			// A FROM clause may list more tables: "FROM a AS x, b".
			if alias := sqlAlias.FindStringSubmatch(rest); alias != nil && !sqlAliasStop[alias[1]] {
				rest = rest[len(alias[0]):]
			}
			trimmed := strings.TrimLeft(rest, " \t\r\n")
			if !strings.HasPrefix(trimmed, ",") {
				break
			}
			rest = strings.TrimLeft(trimmed[1:], " \t\r\n")
		}
	}
	return tables
}

// sqlInsertColumns returns each INSERT target of a statement with its
// column list. A statement without a column list yields "".
func sqlInsertColumns(statement string) [][2]string {
	var inserts [][2]string
	for _, match := range sqlInsertInto.FindAllStringSubmatchIndex(statement, -1) {
		table := statement[match[2]:match[3]]
		rest := statement[match[1]:]
		columns := ""
		if strings.HasPrefix(rest, "(") {
			depth := 0
			for i, r := range rest {
				if r == '(' {
					depth++
				} else if r == ')' {
					depth--
					if depth == 0 {
						columns = rest[1:i]
						break
					}
				}
			}
			if columns == "" {
				columns = rest[1:]
			}
		}
		inserts = append(inserts, [2]string{table, columns})
	}
	return inserts
}

// sqlClauseKeywords start a clause of a statement. The last one before a
// tenant_id, at the same depth of parentheses or an enclosing one, is the
// clause the column is in.
var sqlClauseKeywords = map[string]bool{
	"SELECT": true, "FROM": true, "JOIN": true, "ON": true, "USING": true, "WHERE": true,
	"GROUP": true, "HAVING": true, "WINDOW": true, "PARTITION": true, "ORDER": true, "LIMIT": true, "OFFSET": true,
	"INSERT": true, "INTO": true, "VALUES": true, "UPDATE": true, "SET": true, "DELETE": true, "RETURNING": true,
	"CONFLICT": true, "DO": true, "WITH": true, "UNION": true, "EXCEPT": true, "INTERSECT": true,
}

// sqlPredicateClauses are the clauses whose conditions choose the rows that
// a statement reads, joins, or writes.
var sqlPredicateClauses = map[string]bool{"WHERE": true, "ON": true, "HAVING": true}

// sqlColumnClauses are the clauses in which tenant_id is a value that the
// statement returns, writes, or orders by, so even a comparison there, such
// as a flag in the select list or an assignment, restricts no row.
var sqlColumnClauses = map[string]bool{"SELECT": true, "SET": true, "VALUES": true, "INTO": true, "CONFLICT": true, "ORDER": true, "GROUP": true, "PARTITION": true, "RETURNING": true}

// sqlBoundTenant matches the comparison of tenant_id with a bound value.
var sqlBoundTenant = regexp.MustCompile(`^\s*(?:=|IS)\s*\?`)

// sqlTenantPredicate reports whether a statement restricts its rows by
// tenant: tenant_id is in a WHERE, ON or HAVING clause, in a subquery or a
// function call there too, or is compared with a bound value as tenant_id=?
// or tenant_id IS ? outside the clauses of sqlColumnClauses, as in a
// fragment that a statement appends to its WHERE clause. A tenant_id that a
// statement only selects, inserts, assigns, sorts, groups, or names as a
// conflict target restricts nothing, so it does not count.
func sqlTenantPredicate(statement string) bool {
	// clauses holds the current clause at each depth of parentheses. A
	// parenthesis starts in the clause around it, so a function call or a
	// subquery in a WHERE clause is part of the predicate until a keyword of
	// its own, such as the subquery's SELECT, starts another clause.
	clauses := []string{""}
	isWord := func(c byte) bool {
		return c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
	}
	for i := 0; i < len(statement); {
		c := statement[i]
		switch {
		case c == '\'' || c == '"' || c == '`':
			// Skip a quoted string or identifier; a doubled quote escapes
			// itself.
			j := i + 1
			for j < len(statement) && (statement[j] != c || j+1 < len(statement) && statement[j+1] == c) {
				if statement[j] == c {
					j++
				}
				j++
			}
			i = j + 1
		case c == '(':
			clauses = append(clauses, clauses[len(clauses)-1])
			i++
		case c == ')':
			if len(clauses) > 1 {
				clauses = clauses[:len(clauses)-1]
			}
			i++
		case isWord(c):
			j := i
			for j < len(statement) && isWord(statement[j]) {
				j++
			}
			word, current := statement[i:j], &clauses[len(clauses)-1]
			switch {
			case word == "tenant_id":
				if sqlPredicateClauses[*current] || !sqlColumnClauses[*current] && sqlBoundTenant.MatchString(statement[j:]) {
					return true
				}
			case word == "CONFLICT" && *current != "ON":
				// Only ON CONFLICT starts the conflict clause.
			case sqlClauseKeywords[word]:
				*current = word
			}
			i = j
		default:
			i++
		}
	}
	return false
}

// packageStringConstants returns the value of every package-level string
// constant that the lint can evaluate, so a statement built from a constant
// such as jobTenantSQL is checked with its text.
func packageStringConstants(files []*ast.File) map[string]string {
	constants := map[string]string{}
	var pending []*ast.ValueSpec
	for _, file := range files {
		for _, decl := range file.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				pending = append(pending, spec.(*ast.ValueSpec))
			}
		}
	}
	// Constants may refer to each other; evaluate until nothing changes.
	for changed := true; changed; {
		changed = false
		for _, spec := range pending {
			for i, name := range spec.Names {
				if _, done := constants[name.Name]; done || i >= len(spec.Values) {
					continue
				}
				if value, known := evaluateString(spec.Values[i], constants); known {
					constants[name.Name] = value
					changed = true
				}
			}
		}
	}
	return constants
}

// evaluateString returns the value of a constant string expression.
func evaluateString(expr ast.Expr, constants map[string]string) (string, bool) {
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			return "", false
		}
		value, err := strconv.Unquote(e.Value)
		return value, err == nil
	case *ast.Ident:
		value, ok := constants[e.Name]
		return value, ok
	case *ast.ParenExpr:
		return evaluateString(e.X, constants)
	case *ast.BinaryExpr:
		if e.Op != token.ADD {
			return "", false
		}
		left, ok := evaluateString(e.X, constants)
		if !ok {
			return "", false
		}
		right, ok := evaluateString(e.Y, constants)
		return left + right, ok
	}
	return "", false
}

// flattenString returns the text of a string expression, with sqlUnknown
// for each operand the lint cannot evaluate, and whether it contains a
// string literal at all.
func flattenString(expr ast.Expr, constants map[string]string) (string, bool) {
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			return sqlUnknown, false
		}
		value, err := strconv.Unquote(e.Value)
		if err != nil {
			return sqlUnknown, false
		}
		return value, true
	case *ast.Ident:
		if value, ok := constants[e.Name]; ok {
			return value, false
		}
	case *ast.ParenExpr:
		return flattenString(e.X, constants)
	case *ast.BinaryExpr:
		if e.Op == token.ADD {
			left, leftLiteral := flattenString(e.X, constants)
			right, rightLiteral := flattenString(e.Y, constants)
			return left + right, leftLiteral || rightLiteral
		}
	}
	return sqlUnknown, false
}

// receiverName returns the receiver type of a method, or "" for a function.
func receiverName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return ""
	}
	expr := fn.Recv.List[0].Type
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	if ident, ok := expr.(*ast.Ident); ok {
		return ident.Name
	}
	return ""
}

// localStringConstants returns the string constants that a function body
// can use: the package's, and those it declares itself, so a statement
// built from a local constant is checked with its text. A local constant
// replaces a package constant of the same name; the lint does not track the
// scope of a block. It also returns the value expressions of the local
// constants, which are checked where the constants are used rather than
// where they are declared, as a fragment of SQL means nothing on its own.
func localStringConstants(body *ast.BlockStmt, constants map[string]string) (map[string]string, map[ast.Node]bool) {
	var specs []*ast.ValueSpec
	ast.Inspect(body, func(node ast.Node) bool {
		if decl, ok := node.(*ast.GenDecl); ok && decl.Tok == token.CONST {
			for _, spec := range decl.Specs {
				specs = append(specs, spec.(*ast.ValueSpec))
			}
		}
		return true
	})
	if len(specs) == 0 {
		return constants, nil
	}
	local := make(map[string]string, len(constants)+len(specs))
	for name, value := range constants {
		local[name] = value
	}
	values := map[ast.Node]bool{}
	for _, spec := range specs {
		for _, name := range spec.Names {
			delete(local, name.Name)
		}
		for _, value := range spec.Values {
			values[value] = true
		}
	}
	for changed := true; changed; {
		changed = false
		for _, spec := range specs {
			for i, name := range spec.Names {
				if _, done := local[name.Name]; done || i >= len(spec.Values) {
					continue
				}
				if value, known := evaluateString(spec.Values[i], local); known {
					local[name.Name] = value
					changed = true
				}
			}
		}
	}
	return local, values
}

// collectSQLStatements returns every string expression in the files: those
// in function bodies attributed to their function, and package-level ones
// to "(package)". In a function body it also returns each string constant
// passed by name to a call, which may hold a whole statement, and it reads
// local constants where they are used.
func collectSQLStatements(fset *token.FileSet, files []*ast.File) []sqlStatement {
	packageConstants := packageStringConstants(files)
	var statements []sqlStatement
	collect := func(root ast.Node, function, receiver string, constants map[string]string, localValues map[ast.Node]bool) {
		add := func(expr ast.Expr, text string) {
			statements = append(statements, sqlStatement{position: fset.Position(expr.Pos()).String(), function: function, receiver: receiver, text: text})
		}
		ast.Inspect(root, func(node ast.Node) bool {
			if localValues[node] {
				return false
			}
			expr, ok := node.(ast.Expr)
			if !ok {
				return true
			}
			switch e := expr.(type) {
			case *ast.CallExpr:
				if function == "(package)" {
					return true
				}
				for _, arg := range e.Args {
					if ident, ok := arg.(*ast.Ident); ok {
						if value, ok := constants[ident.Name]; ok {
							add(arg, value)
						}
					}
				}
				return true
			case *ast.BinaryExpr:
				if e.Op != token.ADD {
					return true
				}
			case *ast.BasicLit:
				if e.Kind != token.STRING {
					return true
				}
			default:
				return true
			}
			text, literal := flattenString(expr, constants)
			if !literal {
				return true
			}
			add(expr, text)
			return false
		})
	}
	for _, file := range files {
		for _, decl := range file.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if d.Body == nil {
					continue
				}
				receiver := receiverName(d)
				function := d.Name.Name
				if receiver != "" {
					function = receiver + "." + function
				}
				constants, localValues := localStringConstants(d.Body, packageConstants)
				collect(d.Body, function, receiver, constants, localValues)
			case *ast.GenDecl:
				collect(d, "(package)", "", packageConstants, nil)
			}
		}
	}
	return statements
}

// tenantSQLLintResult holds the findings of lintTenantSQL. violations fail
// the lint. unscopedStore lists Store methods whose SQL touches tenant data
// without the tenant predicate; it fails the lint only when enforcement is
// on. globalStore lists the same for the account and legacy administrator
// methods of globalStoreMethods, which are global by design. unscopedOther
// lists the same for functions and the methods of other types, and
// crossTenant for the SystemStore and PlatformStore methods that may span
// tenants; these three are informational.
type tenantSQLLintResult struct {
	violations    []string
	unscopedStore []string
	globalStore   []string
	unscopedOther []string
	crossTenant   []string
	exemptInserts map[string]int
}

// storeMethodMayBeUnscoped reports whether a Store method may touch tenant
// data without the tenant predicate. Only the account and legacy
// administrator methods of globalStoreMethods may: they run before any
// tenant scope exists and act on one account, whatever its tenant, or on
// every account at once.
func storeMethodMayBeUnscoped(method string) bool {
	switch globalStoreMethods[method] {
	case globalAccount, globalLegacyAdmin:
		return true
	}
	return false
}

// lintTenantSQL checks each statement. A statement touches tenant data when
// it names a direct or via table, apart from the target of an INSERT that
// names tenant_id, which writes its row with a tenant. It is scoped when
// sqlTenantPredicate finds the tenant predicate in it.
func lintTenantSQL(statements []sqlStatement, tables map[string]tableTenancy) tenantSQLLintResult {
	result := tenantSQLLintResult{exemptInserts: map[string]int{}}
	for _, statement := range statements {
		text := strings.TrimSpace(statement.text)
		if sqlDDL.MatchString(strings.TrimLeft(text, "(")) {
			continue
		}
		uses := map[string]int{}
		var order []string
		for _, table := range sqlTables(text) {
			if tenancy, ok := tables[table]; ok && tenancy.tenantData() {
				if uses[table] == 0 {
					order = append(order, table)
				}
				uses[table]++
			}
		}
		for _, insert := range sqlInsertColumns(text) {
			table, columns := insert[0], insert[1]
			if tables[table].class != tenancyDirect {
				continue
			}
			if sqlTenantColumn.MatchString(columns) {
				// The insert writes its row with a tenant; the statement's
				// other uses of the table, if any, still need the predicate.
				uses[table]--
				continue
			}
			key := strings.TrimPrefix(statement.function, statement.receiver+".") + ":" + table
			if _, exempt := tenantInsertExemptions[key]; exempt {
				result.exemptInserts[key]++
				continue
			}
			problem := "names no tenant_id column"
			switch {
			case columns == "":
				problem = "has no column list, so it cannot name tenant_id"
			case strings.Contains(columns, sqlUnknown):
				problem = "builds its column list at run time without a visible tenant_id"
			}
			result.violations = append(result.violations, fmt.Sprintf("%s: %s: INSERT INTO %s %s; name tenant_id and derive it from the owning row, or add a reasoned entry to tenantInsertExemptions", statement.position, statement.function, table, problem))
		}
		var touched []string
		for _, table := range order {
			if uses[table] > 0 {
				touched = append(touched, table)
			}
		}
		if len(touched) == 0 || sqlTenantPredicate(text) {
			continue
		}
		finding := fmt.Sprintf("%s: %s: %s", statement.position, statement.function, strings.Join(touched, ", "))
		switch statement.receiver {
		case "TenantStore", "PublicStore":
			result.violations = append(result.violations, finding+": a "+statement.receiver+" statement must carry the tenant predicate (tenant_id in WHERE or ON, or tenant_id=?) in the same SQL")
		case "Store":
			if method := strings.TrimPrefix(statement.function, "Store."); storeMethodMayBeUnscoped(method) {
				result.globalStore = append(result.globalStore, finding+" ("+globalStoreMethods[method]+")")
			} else {
				result.unscopedStore = append(result.unscopedStore, finding)
			}
		case "SystemStore", "PlatformStore":
			result.crossTenant = append(result.crossTenant, finding)
		default:
			result.unscopedOther = append(result.unscopedOther, finding)
		}
	}
	return result
}

// parseStoreSources parses the store package's non-test Go files.
func parseStoreSources(t *testing.T) (*token.FileSet, []*ast.File) {
	t.Helper()
	paths, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, path := range paths {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, file)
	}
	if len(files) == 0 {
		t.Fatal("no store source files were parsed")
	}
	return fset, files
}

// The store's SQL keeps tenant data behind the tenant predicate:
//
//   - every statement of a TenantStore or PublicStore method that touches a
//     direct or via table carries the tenant predicate: tenant_id in a
//     WHERE or ON clause, or tenant_id=? or tenant_id IS ?. Selecting or
//     writing the tenant_id column does not restrict the rows, so it does
//     not count; an INSERT that names tenant_id writes its own row with a
//     tenant, and needs the predicate only for the other tables it reads;
//   - every INSERT into a direct table names tenant_id, apart from the
//     exemptions listed in tenantInsertExemptions, each with its reason;
//   - a Store method that touches tenant data without the predicate fails,
//     apart from the account and legacy administrator methods of
//     globalStoreMethods, which run before a scope exists and are listed
//     there with the reason they are global.
//
// Run it with -v to see the report of the statements that are global by
// design, the daemon's cross-tenant statements, and the helper functions
// that the scoped methods call after they checked the tenant.
func TestTenantSQLLint(t *testing.T) {
	t.Parallel()
	fset, files := parseStoreSources(t)
	result := lintTenantSQL(collectSQLStatements(fset, files), tenancyTables)
	for _, violation := range result.violations {
		t.Error(violation)
	}
	keys := make([]string, 0, len(tenantInsertExemptions))
	for key := range tenantInsertExemptions {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if got, want := result.exemptInserts[key], tenantInsertExemptions[key].count; got != want {
			t.Errorf("tenantInsertExemptions[%q] allows %d inserts without tenant_id, but the source has %d; update the entry (%s)", key, want, got, tenantInsertExemptions[key].reason)
		}
	}
	report := func(title string, findings []string) {
		t.Logf("%s: %d statements", title, len(findings))
		for _, finding := range findings {
			t.Log("  " + finding)
		}
	}
	report("Store methods that touch tenant data without the tenant predicate (move them to TenantStore or SystemStore)", result.unscopedStore)
	report("global Store methods that act on an account of any tenant (see globalStoreMethods)", result.globalStore)
	report("functions and other methods that touch tenant data without the tenant predicate", result.unscopedOther)
	report("SystemStore and PlatformStore statements that span tenants", result.crossTenant)
	if tenantSQLLintEnforceUnscoped {
		for _, finding := range result.unscopedStore {
			t.Errorf("%s: a Store method must not touch tenant data without the tenant predicate; move it to TenantStore or SystemStore, or list it in globalStoreMethods if it runs before a scope exists", finding)
		}
	}
}

// Store keeps only the global methods that globalStoreMethods lists, each
// with the reason it is global, and the list names only methods that exist.
// A method that works on one tenant's data belongs to TenantStore or
// PublicStore instead, where the leak suite covers it.
func TestStoreKeepsOnlyGlobalMethods(t *testing.T) {
	t.Parallel()
	_, files := parseStoreSources(t)
	methods := map[string]bool{}
	for _, file := range files {
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && receiverName(fn) == "Store" {
				methods[fn.Name.Name] = true
			}
		}
	}
	names := make([]string, 0, len(methods))
	for name := range methods {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if _, listed := globalStoreMethods[name]; !listed && ast.IsExported(name) {
			t.Errorf("Store.%s is not in globalStoreMethods; tenant work belongs to TenantStore, the daemon's to SystemStore, and platform data to PlatformStore", name)
		}
	}
	for name, reason := range globalStoreMethods {
		if !methods[name] {
			t.Errorf("globalStoreMethods lists %s, which is not a Store method", name)
		}
		switch reason {
		case globalLifecycle, globalScopes, globalMaintenance, globalAccount, globalLegacyAdmin, globalShared:
		default:
			t.Errorf("globalStoreMethods gives %s the unknown reason %q", name, reason)
		}
	}
	// The exported methods are the ones that reflection sees, so the check
	// above covers the whole method set.
	store := reflect.TypeOf(&Store{})
	for i := 0; i < store.NumMethod(); i++ {
		if name := store.Method(i).Name; !methods[name] {
			t.Errorf("Store.%s was not found in the parsed sources", name)
		}
	}
}

// tenantSQLLintFixture holds every kind of finding, so the lint is known to
// fire. ColumnOnly is the negative control of the predicate rule: each of
// its statements names tenant_id, but none restricts its rows by tenant.
const tenantSQLLintFixture = `package store

const tenantPredicate = " AND tenant_id=?"

const leakyJobQuery = "SELECT name FROM jobs WHERE id=?"

func (ts *TenantStore) LeakyJob(ctx context.Context, id string) {
	_ = ts.store.DB.QueryRowContext(ctx, "SELECT name FROM jobs WHERE id=?", id)
	_ = ts.store.DB.QueryRowContext(ctx, "SELECT address FROM scan_hosts WHERE scan_id=?", id)
	_ = ts.store.DB.QueryRowContext(ctx, "SELECT j.name FROM rdap_cache AS r, jobs AS j WHERE r.address=?", id)
	_ = ts.store.DB.QueryRowContext(ctx, leakyJobQuery, id)
	const leakyFragment = " FROM scans WHERE job_id=?"
	_ = ts.store.DB.QueryRowContext(ctx, "SELECT id"+leakyFragment, id)
}

func (ts *TenantStore) ColumnOnly(ctx context.Context, id string) {
	_ = ts.store.DB.QueryRowContext(ctx, "SELECT tenant_id FROM jobs WHERE id=?", id)
	_ = ts.store.DB.QueryRowContext(ctx, "SELECT name,tenant_id FROM users WHERE id=? ORDER BY tenant_id", id)
	_ = ts.store.DB.QueryRowContext(ctx, "SELECT CASE WHEN tenant_id=? THEN name END FROM managed_notifications", ts.scope.id)
	_ = ts.store.DB.QueryRowContext(ctx, "SELECT COALESCE((SELECT tenant_id FROM jobs WHERE id=?),'default')=?", id, ts.scope.id)
	_ = ts.store.DB.QueryRowContext(ctx, "SELECT id FROM events WHERE type='tenant_id=?'", id)
	_, _ = ts.store.DB.ExecContext(ctx, "UPDATE scanner_profiles SET tenant_id=? WHERE id=?", ts.scope.id, id)
	_, _ = ts.store.DB.ExecContext(ctx, "INSERT INTO latest_scan_hosts(tenant_id,address,scan_id) SELECT tenant_id,?,id FROM scans WHERE id=? ON CONFLICT(tenant_id,address) DO UPDATE SET scan_id=excluded.scan_id", "a", id)
}

func (ts *TenantStore) ScopedJob(ctx context.Context, id string) {
	const scoped = "SELECT name FROM jobs WHERE id=?" + tenantPredicate
	const tenantFragment = " FROM jobs WHERE tenant_id=?"
	_ = ts.store.DB.QueryRowContext(ctx, "SELECT h.address FROM scan_hosts AS h JOIN scans AS s ON s.id=h.scan_id AND s.tenant_id=? WHERE h.scan_id=?", ts.scope.id, id)
	_ = ts.store.DB.QueryRowContext(ctx, "SELECT name FROM jobs WHERE id=?"+tenantPredicate, id, ts.scope.id)
	_ = ts.store.DB.QueryRowContext(ctx, scoped, id, ts.scope.id)
	_ = ts.store.DB.QueryRowContext(ctx, "SELECT name"+tenantFragment, ts.scope.id)
	_ = ts.store.DB.QueryRowContext(ctx, "SELECT name FROM scanner_profiles WHERE (tenant_id IS NULL OR tenant_id=?) AND id=?", ts.scope.id, id)
	_ = ts.store.DB.QueryRowContext(ctx, "SELECT id FROM scans WHERE job_id IN (SELECT id FROM jobs WHERE tenant_id=?)", ts.scope.id)
	_ = ts.store.DB.QueryRowContext(ctx, "SELECT id FROM events WHERE COALESCE(tenant_id,'default')=? ORDER BY id", ts.scope.id)
	_ = ts.store.DB.QueryRowContext(ctx, "SELECT id FROM outbox WHERE tenant_id IS ?", ts.scope.id)
	_, _ = ts.store.DB.ExecContext(ctx, "INSERT INTO managed_notifications(id,tenant_id,name) VALUES(?,?,?)", id, ts.scope.id, "n")
	_ = ts.store.DB.QueryRowContext(ctx, "SELECT payload_json FROM rdap_cache WHERE address=?", id)
	_ = ts.store.DB.QueryRowContext(ctx, "SELECT name FROM tenants WHERE id=?", id)
}

func (ps *PublicStore) LeakyScans(ctx context.Context, id string) {
	_ = ps.store.DB.QueryRowContext(ctx, "SELECT id FROM scans WHERE job_id=?", id)
	_ = ps.store.DB.QueryRowContext(ctx, "SELECT s.id FROM scans AS s JOIN jobs AS j ON j.id=s.job_id AND j.tenant_id=? WHERE s.job_id=?", ps.scope.tenant.id, id)
}

func (s *Store) UnscopedJobs(ctx context.Context) {
	_, _ = s.DB.QueryContext(ctx, "DELETE FROM job_revisions WHERE job_id NOT IN (SELECT id FROM jobs)")
	_, _ = s.DB.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS jobs_name ON jobs(name)")
	_ = s.DB.QueryRowContext(ctx, "SELECT tenant_id FROM users WHERE id=?", "u")
}

func (s *Store) GetSession(ctx context.Context, idHash string) {
	_ = s.DB.QueryRowContext(ctx, "SELECT s.user_id,u.tenant_id FROM sessions AS s JOIN users AS u ON u.id=s.user_id WHERE s.id_hash=?", idHash)
}

func (ss *SystemStore) AllJobs(ctx context.Context) {
	_, _ = ss.store.DB.QueryContext(ctx, "SELECT id FROM jobs")
}

func insertJobs(ctx context.Context, tx *sql.Tx, columns string) {
	_, _ = tx.ExecContext(ctx, "INSERT INTO jobs(id,name) VALUES(?,?)", "a", "b")
	_, _ = tx.ExecContext(ctx, "INSERT OR IGNORE INTO scans SELECT * FROM staged_scans")
	_, _ = tx.ExecContext(ctx, "INSERT INTO outbox(destination"+columns+") VALUES(?)", "d")
	_, _ = tx.ExecContext(ctx, "INSERT INTO events(type,tenant_id) VALUES(?,?)", "t", "x")
	_, _ = tx.ExecContext(ctx, "INSERT INTO events(type,tenant_id) SELECT type,tenant_id FROM events WHERE id=?", "e")
}
`

// withoutPositions drops the file position from each finding.
func withoutPositions(findings []string) string {
	position := regexp.MustCompile(`^[^:]+:\d+:\d+: `)
	out := make([]string, len(findings))
	for i, finding := range findings {
		out[i] = position.ReplaceAllString(finding, "")
	}
	return strings.Join(out, "\n")
}

// The lint reports each kind of problem in the fixture, and nothing else.
// ColumnOnly's statements all name tenant_id without restricting their rows
// by it, so each is a violation; ScopedJob's all carry the predicate.
func TestTenantSQLLintFindsViolations(t *testing.T) {
	t.Parallel()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "fixture.go", tenantSQLLintFixture, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	result := lintTenantSQL(collectSQLStatements(fset, []*ast.File{file}), tenancyTables)
	const predicate = ": a TenantStore statement must carry the tenant predicate (tenant_id in WHERE or ON, or tenant_id=?) in the same SQL"
	const fix = "; name tenant_id and derive it from the owning row, or add a reasoned entry to tenantInsertExemptions"
	for _, check := range []struct {
		name     string
		findings []string
		want     []string
	}{
		{"violations", result.violations, []string{
			"TenantStore.LeakyJob: jobs" + predicate,
			"TenantStore.LeakyJob: scan_hosts" + predicate,
			"TenantStore.LeakyJob: jobs" + predicate,
			"TenantStore.LeakyJob: jobs" + predicate,
			"TenantStore.LeakyJob: scans" + predicate,
			"TenantStore.ColumnOnly: jobs" + predicate,
			"TenantStore.ColumnOnly: users" + predicate,
			"TenantStore.ColumnOnly: managed_notifications" + predicate,
			"TenantStore.ColumnOnly: jobs" + predicate,
			"TenantStore.ColumnOnly: events" + predicate,
			"TenantStore.ColumnOnly: scanner_profiles" + predicate,
			"TenantStore.ColumnOnly: scans" + predicate,
			"PublicStore.LeakyScans: scans: a PublicStore statement must carry the tenant predicate (tenant_id in WHERE or ON, or tenant_id=?) in the same SQL",
			"insertJobs: INSERT INTO jobs names no tenant_id column" + fix,
			"insertJobs: INSERT INTO scans has no column list, so it cannot name tenant_id" + fix,
			"insertJobs: INSERT INTO outbox builds its column list at run time without a visible tenant_id" + fix,
		}},
		{"unscoped Store statements", result.unscopedStore, []string{"Store.UnscopedJobs: job_revisions, jobs", "Store.UnscopedJobs: users"}},
		{"global Store statements", result.globalStore, []string{"Store.GetSession: sessions, users (account)"}},
		{"cross-tenant statements", result.crossTenant, []string{"SystemStore.AllJobs: jobs"}},
		{"other unscoped statements", result.unscopedOther, []string{"(package): jobs", "insertJobs: jobs", "insertJobs: scans", "insertJobs: outbox", "insertJobs: events"}},
	} {
		if got, want := withoutPositions(check.findings), strings.Join(check.want, "\n"); got != want {
			t.Errorf("%s =\n%s\nwant\n%s", check.name, got, want)
		}
	}
}

// The predicate rule finds tenant_id where it restricts the rows, at any
// depth, and nowhere else.
func TestSQLTenantPredicate(t *testing.T) {
	t.Parallel()
	for statement, want := range map[string]bool{
		"SELECT name FROM jobs WHERE id=? AND tenant_id=?":                                    true,
		"SELECT h.address FROM scan_hosts h JOIN scans s ON s.id=h.scan_id AND s.tenant_id=?": true,
		"DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE tenant_id=?)":      true,
		"SELECT id FROM events WHERE COALESCE(tenant_id,'x')=?":                               true,
		"SELECT id FROM outbox WHERE tenant_id IS ?":                                          true,
		"SELECT id FROM scanner_profiles WHERE tenant_id IS NULL":                             true,
		"SELECT job, COUNT(*) FROM scans GROUP BY job HAVING MIN(tenant_id)=?":                true,
		"SELECT id FROM (SELECT id FROM jobs WHERE tenant_id=?) AS j":                         true,
		" AND j.tenant_id=?": true,
		"UPDATE jobs SET name=? WHERE id=? AND tenant_id=?":                             true,
		"SELECT tenant_id FROM jobs WHERE id=?":                                         false,
		"SELECT id FROM jobs WHERE id=? ORDER BY tenant_id":                             false,
		"SELECT id FROM jobs WHERE id IN (SELECT id FROM jobs) ORDER BY tenant_id=?":    false,
		"SELECT CASE WHEN tenant_id IS ? THEN 1 END FROM jobs":                          false,
		"SELECT COALESCE((SELECT tenant_id FROM jobs WHERE id=?),'x')=?":                false,
		"UPDATE jobs SET tenant_id=? WHERE id=?":                                        false,
		"INSERT INTO jobs(id,tenant_id) VALUES(?,?)":                                    false,
		"INSERT INTO t(a) VALUES(?) ON CONFLICT(tenant_id,a) DO UPDATE SET tenant_id=?": false,
		"SELECT id FROM jobs WHERE name='tenant_id=?'":                                  false,
		"SELECT id FROM jobs WHERE name=\"tenant_id\" AND x=?":                          false,
		"SELECT update_tenant_id FROM jobs WHERE my_tenant_id=?":                        false,
		"SELECT ROW_NUMBER() OVER (PARTITION BY tenant_id) FROM scans":                  false,
	} {
		if got := sqlTenantPredicate(statement); got != want {
			t.Errorf("sqlTenantPredicate(%q) = %v, want %v", statement, got, want)
		}
	}
}

// The table scanner finds every table a statement names, including the
// tables of a FROM list and the targets of writes.
func TestSQLTablesFindsEveryTable(t *testing.T) {
	t.Parallel()
	for statement, want := range map[string]string{
		"SELECT a FROM jobs AS j, json_each(j.x) AS e JOIN scans s ON s.job_id=j.id": "jobs,json_each,scans",
		"SELECT a FROM jobs j, scans WHERE j.id=scans.job_id":                        "jobs,scans",
		"UPDATE jobs SET name=? WHERE id IN (SELECT job_id FROM scan_cycles)":        "jobs,scan_cycles",
		"INSERT INTO outbox(a) SELECT a FROM events ON CONFLICT DO UPDATE SET a=1":   "outbox,events,SET",
		"DELETE FROM \"sessions\" WHERE user_id=?":                                   "sessions",
		"SELECT COUNT(*) FROM (SELECT 1 FROM users)":                                 "users",
	} {
		if got := strings.Join(sqlTables(statement), ","); got != want {
			t.Errorf("sqlTables(%q) = %s, want %s", statement, got, want)
		}
	}
}
