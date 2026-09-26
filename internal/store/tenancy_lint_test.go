package store

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// tenantSQLLintEnforceUnscoped turns the report of Store methods whose SQL
// touches tenant data without naming tenant_id into failures. It stays false
// while the store's methods move to TenantStore in slices, each behind a
// deprecated Store wrapper bound to DefaultTenantScope. The change that
// removes the last wrapper sets it to true, and from then on a Store method
// must not read or write tenant data without the tenant predicate: that work
// belongs to TenantStore, or to SystemStore for the daemon.
const tenantSQLLintEnforceUnscoped = false

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

// collectSQLStatements returns every string expression in the files: those
// in function bodies attributed to their function, and package-level ones
// to "(package)".
func collectSQLStatements(fset *token.FileSet, files []*ast.File) []sqlStatement {
	constants := packageStringConstants(files)
	var statements []sqlStatement
	collect := func(root ast.Node, function, receiver string) {
		ast.Inspect(root, func(node ast.Node) bool {
			expr, ok := node.(ast.Expr)
			if !ok {
				return true
			}
			switch e := expr.(type) {
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
			statements = append(statements, sqlStatement{position: fset.Position(expr.Pos()).String(), function: function, receiver: receiver, text: text})
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
				collect(d.Body, function, receiver)
			case *ast.GenDecl:
				collect(d, "(package)", "")
			}
		}
	}
	return statements
}

// tenantSQLLintResult holds the findings of lintTenantSQL. violations fail
// the lint. unscopedStore lists Store methods whose SQL touches tenant data
// without tenant_id; it fails the lint only when enforcement is on.
// unscopedOther lists the same for functions and the methods of other
// types, and crossTenant for the SystemStore and PlatformStore methods that
// may span tenants; both are informational.
type tenantSQLLintResult struct {
	violations    []string
	unscopedStore []string
	unscopedOther []string
	crossTenant   []string
	exemptInserts map[string]int
}

func lintTenantSQL(statements []sqlStatement, tables map[string]tableTenancy) tenantSQLLintResult {
	result := tenantSQLLintResult{exemptInserts: map[string]int{}}
	for _, statement := range statements {
		text := strings.TrimSpace(statement.text)
		if sqlDDL.MatchString(strings.TrimLeft(text, "(")) {
			continue
		}
		var touched []string
		seen := map[string]bool{}
		for _, table := range sqlTables(text) {
			if tenancy, ok := tables[table]; ok && tenancy.tenantData() && !seen[table] {
				seen[table] = true
				touched = append(touched, table)
			}
		}
		for _, insert := range sqlInsertColumns(text) {
			table, columns := insert[0], insert[1]
			if tables[table].class != tenancyDirect || sqlTenantColumn.MatchString(columns) {
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
		if len(touched) == 0 || sqlTenantColumn.MatchString(text) {
			continue
		}
		finding := fmt.Sprintf("%s: %s: %s", statement.position, statement.function, strings.Join(touched, ", "))
		switch statement.receiver {
		case "TenantStore":
			result.violations = append(result.violations, finding+": a TenantStore statement must carry the tenant predicate (tenant_id) in the same SQL")
		case "Store":
			result.unscopedStore = append(result.unscopedStore, finding)
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
//   - a TenantStore method names tenant_id in every statement that touches
//     a direct or via table;
//   - every INSERT into a direct table names tenant_id, apart from the
//     exemptions listed in tenantInsertExemptions;
//   - Store methods that touch tenant data without tenant_id are reported,
//     and fail once tenantSQLLintEnforceUnscoped is set.
//
// Run it with -v to see the report of statements that still need a scope.
func TestTenantSQLLint(t *testing.T) {
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
	report("Store methods that touch tenant data without tenant_id (move them to TenantStore or SystemStore)", result.unscopedStore)
	report("functions and other methods that touch tenant data without tenant_id", result.unscopedOther)
	report("SystemStore and PlatformStore statements that span tenants", result.crossTenant)
	if tenantSQLLintEnforceUnscoped {
		for _, finding := range result.unscopedStore {
			t.Errorf("%s: a Store method must not touch tenant data without the tenant predicate", finding)
		}
	}
}

// tenantSQLLintFixture holds every kind of finding, so the lint is known to
// fire.
const tenantSQLLintFixture = `package store

const tenantPredicate = " AND tenant_id=?"

func (ts *TenantStore) LeakyJob(ctx context.Context, id string) {
	_ = ts.store.DB.QueryRowContext(ctx, "SELECT name FROM jobs WHERE id=?", id)
	_ = ts.store.DB.QueryRowContext(ctx, "SELECT address FROM scan_hosts WHERE scan_id=?", id)
	_ = ts.store.DB.QueryRowContext(ctx, "SELECT j.name FROM rdap_cache AS r, jobs AS j WHERE r.address=?", id)
}

func (ts *TenantStore) ScopedJob(ctx context.Context, id string) {
	_ = ts.store.DB.QueryRowContext(ctx, "SELECT h.address FROM scan_hosts AS h JOIN scans AS s ON s.id=h.scan_id AND s.tenant_id=? WHERE h.scan_id=?", ts.scope.id, id)
	_ = ts.store.DB.QueryRowContext(ctx, "SELECT name FROM jobs WHERE id=?"+tenantPredicate, id, ts.scope.id)
	_ = ts.store.DB.QueryRowContext(ctx, "SELECT payload_json FROM rdap_cache WHERE address=?", id)
	_ = ts.store.DB.QueryRowContext(ctx, "SELECT name FROM tenants WHERE id=?", id)
}

func (s *Store) UnscopedJobs(ctx context.Context) {
	_, _ = s.DB.QueryContext(ctx, "DELETE FROM job_revisions WHERE job_id NOT IN (SELECT id FROM jobs)")
	_, _ = s.DB.ExecContext(ctx, "CREATE INDEX IF NOT EXISTS jobs_name ON jobs(name)")
}

func (ss *SystemStore) AllJobs(ctx context.Context) {
	_, _ = ss.store.DB.QueryContext(ctx, "SELECT id FROM jobs")
}

func insertJobs(ctx context.Context, tx *sql.Tx, columns string) {
	_, _ = tx.ExecContext(ctx, "INSERT INTO jobs(id,name) VALUES(?,?)", "a", "b")
	_, _ = tx.ExecContext(ctx, "INSERT OR IGNORE INTO scans SELECT * FROM staged_scans")
	_, _ = tx.ExecContext(ctx, "INSERT INTO outbox(destination"+columns+") VALUES(?)", "d")
	_, _ = tx.ExecContext(ctx, "INSERT INTO events(type,tenant_id) VALUES(?,?)", "t", "x")
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
func TestTenantSQLLintFindsViolations(t *testing.T) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "fixture.go", tenantSQLLintFixture, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	result := lintTenantSQL(collectSQLStatements(fset, []*ast.File{file}), tenancyTables)
	const predicate = ": a TenantStore statement must carry the tenant predicate (tenant_id) in the same SQL"
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
			"insertJobs: INSERT INTO jobs names no tenant_id column" + fix,
			"insertJobs: INSERT INTO scans has no column list, so it cannot name tenant_id" + fix,
			"insertJobs: INSERT INTO outbox builds its column list at run time without a visible tenant_id" + fix,
		}},
		{"unscoped Store statements", result.unscopedStore, []string{"Store.UnscopedJobs: job_revisions, jobs"}},
		{"cross-tenant statements", result.crossTenant, []string{"SystemStore.AllJobs: jobs"}},
		{"other unscoped statements", result.unscopedOther, []string{"insertJobs: jobs", "insertJobs: scans", "insertJobs: outbox"}},
	} {
		if got, want := withoutPositions(check.findings), strings.Join(check.want, "\n"); got != want {
			t.Errorf("%s =\n%s\nwant\n%s", check.name, got, want)
		}
	}
}

// The table scanner finds every table a statement names, including the
// tables of a FROM list and the targets of writes.
func TestSQLTablesFindsEveryTable(t *testing.T) {
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
