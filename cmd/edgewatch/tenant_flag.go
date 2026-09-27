package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"strings"

	"github.com/crypt0rr/edgewatch/internal/app"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// The --tenant flag names a business unit by its slug. The host commands that
// act on one unit's data (scan, status, history, baseline and notify test)
// then act on that unit instead of the default one. The admin recovery
// commands, which find their account by a username that is unique across
// every unit, take it as a safety check: they stop unless the account belongs
// to that unit. Every other command refuses the flag, and so does every
// command while experimental.business_units is off.

// errTenantNeedsBusinessUnits refuses --tenant while business units are off.
var errTenantNeedsBusinessUnits = fmt.Errorf("--tenant names a business unit: %w", app.ErrBusinessUnitsDisabled)

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
	units, err := s.Platform().Tenants(ctx)
	if err != nil {
		return store.Tenant{}, store.TenantScope{}, err
	}
	for _, unit := range units {
		if unit.Slug != slug {
			continue
		}
		scope, err := s.TenantScopeByID(ctx, unit.ID)
		if err != nil {
			return store.Tenant{}, store.TenantScope{}, fmt.Errorf("business unit %q: %w", slug, err)
		}
		return unit, scope, nil
	}
	return store.Tenant{}, store.TenantScope{}, fmt.Errorf("unknown business unit %q", slug)
}

// tenantCommandReads reports whether a host command that takes --tenant
// only reads the unit's data.
func tenantCommandReads(cmd, action string) bool {
	return cmd == "status" || cmd == "history" || (cmd == "baseline" && action == "export")
}

// hostUnitStore returns the store of the business unit that a host command
// named with --tenant. A unit that is being deleted is refused, because its
// data is being erased. A disabled unit is paused: its data can be read, but
// a command that scans, changes a baseline or sends a notification is
// refused until the unit is enabled again.
func hostUnitStore(ctx context.Context, s *store.Store, slug, cmd, action string) (*store.TenantStore, error) {
	unit, scope, err := hostUnit(ctx, s, slug)
	if err != nil {
		return nil, err
	}
	name := strings.TrimSpace(cmd + " " + action)
	switch unit.State {
	case store.TenantStateActive:
	case store.TenantStateDisabled:
		if !tenantCommandReads(cmd, action) {
			return nil, fmt.Errorf("business unit %q is disabled; enable it before running %s", slug, name)
		}
	default:
		return nil, fmt.Errorf("business unit %q is being deleted; %s cannot use it", slug, name)
	}
	return s.Tenant(scope), nil
}

// confirmAccountUnit runs before a recovery command changes the account.
// When --tenant named a business unit, it stops the command unless the
// account belongs to that unit. With business units on, it then prints the
// account, its unit (or the platform) and its role.
func confirmAccountUnit(ctx context.Context, s *store.Store, user store.User, options adminRecoveryOptions) error {
	if options.unit == nil && !options.businessUnits {
		return nil
	}
	where := "platform"
	if user.Role != store.RolePlatformAdmin {
		unit, err := s.Platform().GetTenant(ctx, user.TenantID)
		if err != nil {
			return err
		}
		where = "unit " + unit.Slug
	}
	if named := options.unit; named != nil && (user.Role == store.RolePlatformAdmin || user.TenantID != named.ID) {
		return fmt.Errorf("user %q belongs to the %s, not to business unit %q; nothing was changed", user.Username, where, named.Slug)
	}
	if options.out == nil {
		return nil
	}
	_, err := fmt.Fprintf(options.out, "user %q (%s, %s)\n", user.Username, where, user.Role)
	return err
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
