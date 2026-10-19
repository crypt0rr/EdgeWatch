package store

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"regexp"
	"strings"
	"testing"
)

const (
	sqlWhitespaceOrComment = `(?:\s+|/\*.*?\*/|--[^\r\n]*(?:\r?\n|$))`
	sqlSeparator           = `(?:` + sqlWhitespaceOrComment + `)+`
	sqlOptionalSeparator   = `(?:` + sqlWhitespaceOrComment + `)*`
	outboxSQLIdentifier    = `(?:[A-Za-z_][A-Za-z0-9_]*|"(?:""|[^"])*"|` + "`(?:``|[^`])*`" + `|\[(?:\]\]|[^\]])*\])`
)

var (
	outboxTableName = `(?:outbox|"outbox"|\[outbox\]|` + "`outbox`" + `)`
	outboxSchema    = `(?:` + outboxSQLIdentifier + sqlOptionalSeparator + `\.` + sqlOptionalSeparator + `)?`
	outboxMutation  = regexp.MustCompile(
		`(?is)^\s*UPDATE` + sqlSeparator +
			`(?:OR` + sqlSeparator + `\w+` + sqlSeparator + `)?` + outboxSchema + outboxTableName +
			`(?:` + sqlSeparator + `(?:AS` + sqlSeparator + `)?` + outboxSQLIdentifier + `)?` + sqlSeparator + `SET\b` +
			`|^\s*REPLACE` + sqlSeparator + `INTO` + sqlSeparator + outboxSchema + outboxTableName + `(?:\s|\(|$)` +
			`|^\s*INSERT(?:` + sqlSeparator + `OR` + sqlSeparator + `\w+)?` + sqlSeparator + `INTO` + sqlSeparator + outboxSchema + outboxTableName + `(?:\s|\(|$)[\s\S]*?\bON` + sqlSeparator + `CONFLICT\b[\s\S]*?\bDO` + sqlSeparator + `UPDATE\b`,
	)
)

var migrationStatementFunction = regexp.MustCompile(`^migration[0-9]+(?:Conditional)?Statements$`)

// lintOutboxTransitionUpdates finds runtime SQL literals that update outbox
// without going through applyOutboxTransition. The builder assembles its
// statement from reviewed identifiers, while migration files contain frozen
// schema backfills rather than runtime delivery transitions.
func lintOutboxTransitionUpdates(fset *token.FileSet, files []*ast.File) []string {
	var findings []string
	for _, statement := range collectSQLStatements(fset, files) {
		// The canonical builder is the only runtime path that constructs this
		// statement. Frozen migration statement functions are one-time backfills,
		// and are deliberately scoped by function name rather than filename.
		if statement.function == "buildOutboxTransitionStatement" || migrationStatementFunction.MatchString(statement.function) {
			continue
		}
		if outboxMutation.MatchString(statement.text) {
			findings = append(findings, fmt.Sprintf("%s: runtime outbox mutations must use applyOutboxTransition with a named contract", statement.position))
		}
	}
	return findings
}

func parseOutboxLintSource(t *testing.T, name, source string) (*token.FileSet, *ast.File) {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, name, source, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	return fset, file
}

func TestRuntimeOutboxUpdatesUseNamedTransitions(t *testing.T) {
	t.Parallel()
	fset, files := parseStoreSources(t)
	for _, finding := range lintOutboxTransitionUpdates(fset, files) {
		t.Error(finding)
	}
}

func TestOutboxTransitionUpdateLintFindsHandWrittenSQL(t *testing.T) {
	t.Parallel()
	fset, file := parseOutboxLintSource(t, "fixture.go", `package store

func unsafeRequeue(db DB) {
	_, _ = db.Exec("update outbox set attempts=0")
	_, _ = db.Exec("UP" + "DATE /* comment */ OR REPLACE main.`+"`outbox`"+` SET attempts=0, deferrals=0")
	_, _ = db.Exec("UPDATE outbox AS o SET attempts=0")
	_, _ = db.Exec("INSERT INTO outbox(id) VALUES(?) ON CONFLICT(id) DO UPDATE SET attempts=0")
	_, _ = db.Exec("REPLACE INTO outbox(id) VALUES(?)")
	column := "attempts"
	_, _ = db.Exec("UPDATE outbox SET " + column + "=0")
	_, _ = db.Exec(fmt.Sprintf("UPDATE outbox SET %s=0", column))
	_, _ = db.Exec("UPDATE outbox_archive SET attempts=0")
	_, _ = db.Exec("This message mentions UPDATE outbox SET but is not a statement")
}
`)
	findings := lintOutboxTransitionUpdates(fset, []*ast.File{file})
	if len(findings) != 7 {
		t.Fatalf("lint findings = %v; want all seven outbox mutation forms and no prose/archive match", findings)
	}
	for _, finding := range findings {
		if !strings.Contains(finding, "runtime outbox mutations must use applyOutboxTransition") {
			t.Errorf("finding lacks transition guidance: %q", finding)
		}
	}
}

func TestOutboxTransitionUpdateLintExemptsBuilderAndMigrations(t *testing.T) {
	t.Parallel()
	for _, fixture := range []struct {
		name   string
		source string
	}{
		{name: "outbox_transitions.go", source: `package store

func buildOutboxTransitionStatement() string {
	return "UPDATE outbox SET attempts=0"
}

func migration72Statements() []string {
	return []string{"UPDATE [outbox] SET event_type='legacy'"}
}
`},
		{name: "migration72.go", source: `package store

func runtimeHelper(db DB) {
	_, _ = db.Exec("UPDATE outbox SET attempts=0")
}
`},
	} {
		fset, file := parseOutboxLintSource(t, fixture.name, fixture.source)
		findings := lintOutboxTransitionUpdates(fset, []*ast.File{file})
		if fixture.name == "outbox_transitions.go" && len(findings) != 0 {
			t.Errorf("builder/migration findings = %v; want only exact function exemptions", findings)
		}
		if fixture.name == "migration72.go" && len(findings) != 1 {
			t.Errorf("same-file runtime findings = %v; want non-migration runtime update to fail", findings)
		}
	}
}
