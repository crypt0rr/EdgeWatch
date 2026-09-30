package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// The --tenant flag names a business unit by its slug. The host commands that
// act on one unit's data (scan, status, history, baseline and notify test)
// then act on that unit instead of the default one. The admin recovery
// commands, which find their account by a username that is unique across
// every unit, take it as a safety check: they stop unless the account belongs
// to that unit. Every other command refuses the flag.

// flagGiven reports whether the command line set the flag, even to "".
func flagGiven(fs *flag.FlagSet, name string) bool {
	given := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			given = true
		}
	})
	return given
}

// acceptsTenant reports whether the command takes --tenant.
func acceptsTenant(cmd, action string) bool {
	switch cmd {
	case "scan", "status", "history", "baseline", "notify":
		return true
	case "admin":
		return action == "reset-password" || action == "disable-totp"
	}
	return false
}

// checkTenantFlag refuses --tenant on a command that does not take it, and
// an empty slug. It returns the trimmed slug, or "" without the flag.
func checkTenantFlag(fs *flag.FlagSet, cmd, action, slug string) (string, error) {
	if !flagGiven(fs, "tenant") {
		return "", nil
	}
	if !acceptsTenant(cmd, action) {
		name := strings.TrimSpace(cmd + " " + action)
		return "", fmt.Errorf("--tenant does not apply to %s; it is accepted by scan, status, history, baseline, notify test, admin reset-password and admin disable-totp", name)
	}
	slug = strings.TrimSpace(slug)
	if slug == "" {
		return "", errors.New("--tenant needs the slug of a business unit")
	}
	return slug, nil
}

// hostUnit returns the business unit whose slug is slug, and its scope. A
// deleted unit has no slug.
func hostUnit(ctx context.Context, s *store.Store, slug string) (store.Tenant, store.TenantScope, error) {
	return findHostUnit(ctx, s, func(unit store.Tenant) bool { return unit.Slug == slug }, fmt.Errorf("unknown business unit %q", slug))
}

// defaultHostUnit returns the default business unit and its scope. It finds
// the unit by its fixed ID, because the unit can be renamed.
func defaultHostUnit(ctx context.Context, s *store.Store) (store.Tenant, store.TenantScope, error) {
	return findHostUnit(ctx, s, func(unit store.Tenant) bool { return unit.ID == store.DefaultTenantID }, errors.New("the default business unit is missing"))
}

// findHostUnit returns the business unit that match selects among those
// that are not deleted, and its scope, or notFound when there is none.
func findHostUnit(ctx context.Context, s *store.Store, match func(store.Tenant) bool, notFound error) (store.Tenant, store.TenantScope, error) {
	units, err := s.Platform().Tenants(ctx)
	if err != nil {
		return store.Tenant{}, store.TenantScope{}, err
	}
	for _, unit := range units {
		if !match(unit) {
			continue
		}
		scope, err := s.TenantScopeByID(ctx, unit.ID)
		if err != nil {
			return store.Tenant{}, store.TenantScope{}, fmt.Errorf("business unit %q: %w", unit.Slug, err)
		}
		return unit, scope, nil
	}
	return store.Tenant{}, store.TenantScope{}, notFound
}

// tenantCommandReads reports whether a host command that takes --tenant
// only reads the unit's data.
func tenantCommandReads(cmd, action string) bool {
	return cmd == "status" || cmd == "history" || (cmd == "baseline" && action == "export")
}

// hostUnitStore returns the business unit that a host command acts on, the
// one that --tenant named by its slug or the default unit when slug is "",
// and the unit's store. A unit that is being deleted is refused, because its
// data is being erased. A disabled unit is paused: its data can be read, but
// a command that scans, changes a baseline or sends a notification is
// refused until the unit is enabled again. The default unit follows these
// rules with or without --tenant.
func hostUnitStore(ctx context.Context, s *store.Store, slug, cmd, action string) (store.Tenant, *store.TenantStore, error) {
	var unit store.Tenant
	var scope store.TenantScope
	var err error
	if slug == "" {
		unit, scope, err = defaultHostUnit(ctx, s)
	} else {
		unit, scope, err = hostUnit(ctx, s, slug)
	}
	if err != nil {
		return store.Tenant{}, nil, err
	}
	name := strings.TrimSpace(cmd + " " + action)
	switch unit.State {
	case store.TenantStateActive:
	case store.TenantStateDisabled:
		if !tenantCommandReads(cmd, action) {
			return store.Tenant{}, nil, fmt.Errorf("business unit %q is disabled; enable it before running %s", unit.Slug, name)
		}
	default:
		return store.Tenant{}, nil, fmt.Errorf("business unit %q is being deleted; %s cannot use it", unit.Slug, name)
	}
	return unit, s.Tenant(scope), nil
}

// hostScanPausedError explains a scan that stopped because its business unit
// is no longer active. hostUnitStore found the unit active, so it was
// disabled afterwards: before the scan took its lease, when nothing ran, or
// while the scan ran. Such a scan is recorded as canceled and changes no
// baseline, incident or alert, whichever process ran it.
func hostScanPausedError(unit store.Tenant, scan model.Scan, err error) error {
	if scan.ID == "" {
		return fmt.Errorf("business unit %q was disabled before the scan started: %w", unit.Slug, err)
	}
	return fmt.Errorf("business unit %q was disabled while the scan ran; scan %s was canceled and changed no baseline, incident or alert: %w", unit.Slug, scan.ID, err)
}

// confirmAccountUnit runs before a recovery command changes the account.
// When --tenant named a business unit, it stops the command unless the
// account belongs to that unit. It then prints the account, its unit (or
// the platform) and its role, and returns where the account belongs, as
// "unit SLUG" or "platform", for the command's audit record.
func confirmAccountUnit(ctx context.Context, s *store.Store, user store.User, options adminRecoveryOptions) (string, error) {
	where := "platform"
	if user.Role != store.RolePlatformAdmin {
		unit, err := s.Platform().GetTenant(ctx, user.TenantID)
		if err != nil {
			return "", err
		}
		where = "unit " + unit.Slug
	}
	if named := options.unit; named != nil && (user.Role == store.RolePlatformAdmin || user.TenantID != named.ID) {
		return "", fmt.Errorf("user %q belongs to the %s, not to business unit %q; nothing was changed", user.Username, where, named.Slug)
	}
	if options.out == nil {
		return where, nil
	}
	if _, err := fmt.Fprintf(options.out, "user %q (%s, %s)\n", user.Username, where, user.Role); err != nil {
		return "", err
	}
	return where, nil
}

// recoveryAuditDetail is the detail of a host recovery command's audit
// record. It names the account that the command changed by username and
// ID, and where the account belongs, as the console's account records name
// theirs, so a unit's administrators, and the platform's, can tell which
// of their accounts the host recovered. It holds no password, code or
// secret.
func recoveryAuditDetail(factor, change string, user store.User, where string) string {
	return fmt.Sprintf("%s of %s (ID %s, %s) %s from host CLI", factor, user.Username, user.ID, where, change)
}

// hostActorUserID is the account that a host command's audit record names
// in the unit of ts: the original administrator in the default unit, as
// before business units, and no account in another unit, which that
// administrator does not belong to.
func hostActorUserID(ts *store.TenantStore) string {
	if scope, err := ts.Scope(); err == nil && scope != store.DefaultTenantScope() {
		return ""
	}
	return store.LegacyAdminUserID
}
