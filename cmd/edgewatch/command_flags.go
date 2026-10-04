package main

import (
	"flag"
	"fmt"
	"sort"
	"strings"
)

// commandFlagAllowlist contains the options that have a defined meaning for
// each CLI command. The FlagSet is shared to keep parsing compatible, so
// validate explicitly set flags before loading configuration or opening the
// database.
var commandFlagAllowlist = map[string]map[string]struct{}{
	"help":                       {},
	"notify-send":                {},
	"version":                    {},
	"daemon":                     allowedFlags("config", "nmap"),
	"config validate":            allowedFlags("config", "output"),
	"scan":                       allowedFlags("config", "output", "job", "nmap", "tenant"),
	"status":                     allowedFlags("config", "output", "job", "tenant"),
	"history":                    allowedFlags("config", "output", "job", "limit", "tenant"),
	"baseline approve":           allowedFlags("config", "output", "job", "scan-id", "tenant"),
	"baseline reset":             allowedFlags("config", "output", "job", "tenant"),
	"baseline export":            allowedFlags("config", "output", "job", "out", "tenant"),
	"backup":                     allowedFlags("config", "output", "out"),
	"restore":                    allowedFlags("config", "output", "from", "dry-run", "allow-sidecar-replay", "allow-active-daemon", "allow-unreadable-destination", "pending-deliveries"),
	"verify":                     allowedFlags("config", "output"),
	"health":                     allowedFlags("config", "output"),
	"notify test":                allowedFlags("config", "output", "tenant"),
	"admin setup-token":          allowedFlags("config", "output", "force"),
	"admin reissue-setup-token":  allowedFlags("config", "output", "force"),
	"admin platform-setup-token": allowedFlags("config", "output", "force"),
	"admin reset-password":       allowedFlags("config", "output", "username", "password-file", "tenant"),
	"admin disable-totp":         allowedFlags("config", "output", "username", "tenant"),
}

func allowedFlags(names ...string) map[string]struct{} {
	allowed := make(map[string]struct{}, len(names))
	for _, name := range names {
		allowed[name] = struct{}{}
	}
	return allowed
}

func commandFlagKey(cmd, action string) string {
	if action == "" {
		return cmd
	}
	return cmd + " " + action
}

// validateCommandFlags rejects explicitly set options that the selected
// command does not use. Unknown commands/actions are left to their existing
// usage handling; this keeps their established error messages intact.
func validateCommandFlags(fs *flag.FlagSet, cmd, action string) error {
	key := commandFlagKey(cmd, action)
	allowed, knownCommand := commandFlagAllowlist[key]
	if !knownCommand {
		return nil
	}
	var unsupported string
	fs.Visit(func(f *flag.Flag) {
		if unsupported != "" {
			return
		}
		if _, ok := allowed[f.Name]; !ok {
			unsupported = f.Name
		}
	})
	if unsupported == "" {
		return nil
	}
	if unsupported == "tenant" {
		if tenant := fs.Lookup("tenant"); tenant != nil {
			_, err := checkTenantFlag(fs, cmd, action, tenant.Value.String())
			if err != nil {
				return err
			}
		}
	}
	command := strings.TrimSpace(key)
	acceptedBy := make([]string, 0)
	for name, flags := range commandFlagAllowlist {
		if _, ok := flags[unsupported]; ok {
			acceptedBy = append(acceptedBy, name)
		}
	}
	sort.Strings(acceptedBy)
	if len(acceptedBy) == 0 {
		return fmt.Errorf("--%s does not apply to %s", unsupported, command)
	}
	return fmt.Errorf("--%s does not apply to %s; it is accepted by %s", unsupported, command, strings.Join(acceptedBy, ", "))
}
