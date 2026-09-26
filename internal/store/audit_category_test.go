package store

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// knownAuditActions lists every audit action that EdgeWatch writes, found by
// searching the non-test sources for AuditEntry actions, audit helper
// arguments, and SQL inserts into security_audit, with the category decided
// for each.
var knownAuditActions = map[string][]string{
	auditCategoryAccount: {
		"admin.display_name_changed", "admin.login", "admin.logout",
		"admin.password_changed", "admin.password_reset", "admin.sessions_revoked",
		"admin.setup", "admin.setup_token_reissued", "admin.totp_disabled",
		"admin.totp_enabled", "admin.totp_recovery_codes_rotated",
		"auth.activation_failed", "auth.legacy_recovery_codes_retired",
		"auth.login_failed", "auth.password_confirmation_failed",
		"auth.rate_limited", "auth.recovery_code_used", "auth.setup_failed",
		"auth.totp_confirmation_failed", "auth.totp_failed",
		"user.activated", "user.activation_issued", "user.activation_revoked",
		"user.created", "user.display_name_changed", "user.login", "user.logout",
		"user.password_changed", "user.password_reset", "user.password_reset_issued",
		"user.sessions_revoked", "user.totp_disabled", "user.totp_enabled",
		"user.totp_recovery_codes_rotated", "user.updated",
	},
	auditCategoryPlatform: {
		"database.backup", "database.restore", "database.restore.pending_deliveries",
		"notifications.config_imported",
	},
	auditCategoryData: {
		"baseline.approved", "baseline.reset",
		"incident.accepted", "incident.suppressed",
		"job.archived", "job.created", "job.deleted",
		"job.notification_destination_removed", "job.notification_destination_replaced",
		"job.paused", "job.rebaseline_requested", "job.restored", "job.resumed", "job.updated",
		"notifications.created", "notifications.deleted", "notifications.pending_discarded",
		"notifications.test", "notifications.test_failed", "notifications.update_routing",
		"notifications.updated",
		"public_dashboard.updated",
		"scan.cancel_requested", "scan.cycle_discarded", "scan.run_requested",
		"scanner_profile.archived", "scanner_profile.created", "scanner_profile.restored",
		"scanner_profile.updated",
	},
}

// Every known action has an explicit entry, including the data actions that
// would get the same category by default, and the table has no other entries.
func TestAuditCategoryCoversEveryKnownAction(t *testing.T) {
	known := 0
	for category, actions := range knownAuditActions {
		for _, action := range actions {
			known++
			explicit, ok := auditActionCategories[action]
			if !ok {
				t.Errorf("audit action %s has no explicit category", action)
				continue
			}
			if explicit != category || auditCategory(action) != category {
				t.Errorf("audit action %s category = %q (auditCategory %q), want %q", action, explicit, auditCategory(action), category)
			}
		}
	}
	if len(auditActionCategories) != known {
		for action := range auditActionCategories {
			found := false
			for _, actions := range knownAuditActions {
				found = found || slices.Contains(actions, action)
			}
			if !found {
				t.Errorf("auditActionCategories lists %s, which is not a known audit action", action)
			}
		}
	}
	for _, action := range []string{"", "test", "future.action", " user.login"} {
		if got := auditCategory(action); got != auditCategoryData {
			t.Errorf("auditCategory(%q) = %q, want the data default", action, got)
		}
	}
}

// The migration backfill and auditCategory agree for every known action and
// for an unknown one.
func TestAuditCategoryBackfillMatchesAuditCategory(t *testing.T) {
	s := openTestStore(t)
	actions := []string{"future.action", "test"}
	for _, list := range knownAuditActions {
		actions = append(actions, list...)
	}
	for _, action := range actions {
		if _, err := s.DB.Exec(`INSERT INTO security_audit(action,created_at,category) VALUES(?,datetime('now'),'')`, action); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.DB.Exec(auditCategoryBackfillStatement()); err != nil {
		t.Fatal(err)
	}
	for _, action := range actions {
		var category string
		if err := s.DB.QueryRow(`SELECT category FROM security_audit WHERE action=?`, action).Scan(&category); err != nil {
			t.Fatal(err)
		}
		if category != auditCategory(action) {
			t.Errorf("backfilled %s = %q, auditCategory = %q", action, category, auditCategory(action))
		}
	}
}

// dottedActionPattern matches strings shaped like an audit action.
var dottedActionPattern = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$`)

// sqlAuditActionPattern finds quoted actions in SQL that writes audit rows.
var sqlAuditActionPattern = regexp.MustCompile(`'([a-z][a-z0-9_]*(?:\.[a-z0-9_]+)+)'`)

// notAuditActions are the dotted string literals in the sources that are not
// audit actions: live-update message types, file and host names. Permission
// names are declared in internal/auth/permissions.go, which is not scanned.
var notAuditActions = map[string]bool{
	"application.update_status":   true,
	"notification.changed":        true,
	"scan.cancellation_requested": true,
	"scan.completed":              true,
	"scan.started":                true,
	"auth.key":                    true,
	"notification.key":            true,
	"edgewatch.db":                true,
	"github.com":                  true,
	"localhost.localdomain":       true,
}

// Every string in the non-test sources that looks like an audit action is
// either categorized explicitly or known not to be an audit action, so a new
// audit action cannot fall back to the data category by accident.
func TestAuditActionLiteralsHaveExplicitCategories(t *testing.T) {
	root := filepath.Join("..", "..")
	fileSet := token.NewFileSet()
	found := map[string]string{}
	for _, dir := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			if filepath.ToSlash(path) == "../../internal/auth/permissions.go" {
				return nil
			}
			file, err := parser.ParseFile(fileSet, path, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			ast.Inspect(file, func(node ast.Node) bool {
				literal, ok := node.(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					return true
				}
				value, err := strconv.Unquote(literal.Value)
				if err != nil {
					return true
				}
				position := fileSet.Position(literal.Pos()).String()
				if dottedActionPattern.MatchString(value) {
					found[value] = position
				}
				if strings.Contains(value, "INTO security_audit") {
					for _, match := range sqlAuditActionPattern.FindAllStringSubmatch(value, -1) {
						found[match[1]] = position
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(found) == 0 {
		t.Fatal("found no action-shaped strings; the source scan is broken")
	}
	var uncategorized []string
	for value, position := range found {
		if _, ok := auditActionCategories[value]; ok || notAuditActions[value] {
			continue
		}
		uncategorized = append(uncategorized, value+" at "+position)
	}
	sort.Strings(uncategorized)
	for _, value := range uncategorized {
		t.Errorf("%s: add it to auditActionCategories with a deliberate category, or to notAuditActions when it is not an audit action", value)
	}
	for _, list := range knownAuditActions {
		for _, action := range list {
			if _, ok := found[action]; !ok {
				t.Errorf("known audit action %s no longer appears in the sources; remove it from auditActionCategories", action)
			}
		}
	}
	for value := range notAuditActions {
		if _, ok := found[value]; !ok {
			t.Errorf("%s no longer appears in the sources; remove it from notAuditActions", value)
		}
	}
}
