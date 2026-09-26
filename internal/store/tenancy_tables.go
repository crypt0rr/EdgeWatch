package store

// tenancyClass says who owns the rows of a table.
type tenancyClass uint8

const (
	// tenancyDirect tables carry a tenant_id column.
	tenancyDirect tenancyClass = iota + 1
	// tenancyVia tables belong to the tenant of a parent row: a job, a scan,
	// an account, or another table that reaches a direct table.
	tenancyVia
	// tenancyPlatform tables belong to the platform instead of a tenant.
	tenancyPlatform
	// tenancySystem tables hold the daemon's own bookkeeping and no tenant
	// data.
	tenancySystem
	// tenancyShared tables hold public reference data that every tenant may
	// read.
	tenancyShared
)

func (class tenancyClass) String() string {
	switch class {
	case tenancyDirect:
		return "direct"
	case tenancyVia:
		return "via"
	case tenancyPlatform:
		return "platform"
	case tenancySystem:
		return "system"
	case tenancyShared:
		return "shared"
	default:
		return "unclassified"
	}
}

// tableTenancy classifies one table. parent is set for a via table.
type tableTenancy struct {
	class  tenancyClass
	parent string
}

func (tenancy tableTenancy) String() string {
	if tenancy.class == tenancyVia {
		return "via(" + tenancy.parent + ")"
	}
	return tenancy.class.String()
}

// tenantData reports whether the table holds rows that belong to a tenant.
func (tenancy tableTenancy) tenantData() bool {
	return tenancy.class == tenancyDirect || tenancy.class == tenancyVia
}

var (
	directTable   = tableTenancy{class: tenancyDirect}
	platformTable = tableTenancy{class: tenancyPlatform}
	systemTable   = tableTenancy{class: tenancySystem}
	sharedTable   = tableTenancy{class: tenancyShared}
)

func viaTable(parent string) tableTenancy { return tableTenancy{class: tenancyVia, parent: parent} }

// tenancyTables classifies every table of the current schema, including the
// FTS5 virtual tables and their storage tables, by who owns its rows. Indexes
// and triggers follow the table they belong to. The tenant purge and the
// tenant SQL lint read this map, and a test fails when a migration adds a
// table without an entry here or an entry names a table that no longer
// exists.
//
// A via table reaches its tenant through its parent row. Its parent is a
// direct table or another via table, so each chain ends at a tenant_id
// column.
var tenancyTables = map[string]tableTenancy{
	// Tenant roots. A NULL tenant_id marks a platform row where the column
	// allows it: a platform administrator, a platform destination, a
	// platform event, delivery, or audit record, or a built-in profile.
	"events":                         directTable,
	"jobs":                           directTable,
	"latest_scan_hosts":              directTable,
	"managed_notifications":          directTable,
	"outbox":                         directTable,
	"public_dashboards":              directTable,
	"restore_quarantined_deliveries": directTable,
	"scanner_profiles":               directTable,
	"scans":                          directTable,
	"security_audit":                 directTable,
	"users":                          directTable,

	// A job's configuration, baseline, and runtime state.
	"baseline_hosts":         viaTable("jobs"),
	"job_revisions":          viaTable("jobs"),
	"job_runtime":            viaTable("jobs"),
	"job_runtime_meta":       viaTable("jobs"),
	"job_silence_state":      viaTable("jobs"),
	"public_dashboard_hosts": viaTable("jobs"),
	"runtime_incidents":      viaTable("jobs"),
	"scan_cycles":            viaTable("jobs"),

	// Resumable scan work and scan results.
	"legacy_scan_host_backfill":        viaTable("scans"),
	"scan_cycle_discovery_checkpoints": viaTable("scan_cycles"),
	"scan_cycle_units":                 viaTable("scan_cycles"),
	"scan_hosts":                       viaTable("scans"),

	// Account credentials and sessions.
	"recovery_codes": viaTable("users"),
	"sessions":       viaTable("users"),
	"totp_replay":    viaTable("users"),
	"user_invites":   viaTable("users"),

	// Profile history, and the delivery health of a destination, which is
	// keyed by the destination's identity.
	"notification_delivery_health": viaTable("managed_notifications"),
	"scanner_profile_revisions":    viaTable("scanner_profiles"),

	// Host search. Each FTS5 row has the rowid of the row it indexes.
	"baseline_host_search": viaTable("baseline_hosts"),
	"latest_host_search":   viaTable("latest_scan_hosts"),
	"scan_host_search":     viaTable("scan_hosts"),

	// SQLite's storage for the FTS5 tables. The store never reads or writes
	// these directly: their rows are reached and removed only through the
	// virtual table, which is classified above.
	"baseline_host_search_config":  systemTable,
	"baseline_host_search_content": systemTable,
	"baseline_host_search_data":    systemTable,
	"baseline_host_search_docsize": systemTable,
	"baseline_host_search_idx":     systemTable,
	"latest_host_search_config":    systemTable,
	"latest_host_search_content":   systemTable,
	"latest_host_search_data":      systemTable,
	"latest_host_search_docsize":   systemTable,
	"latest_host_search_idx":       systemTable,
	"scan_host_search_config":      systemTable,
	"scan_host_search_content":     systemTable,
	"scan_host_search_data":        systemTable,
	"scan_host_search_docsize":     systemTable,
	"scan_host_search_idx":         systemTable,

	// The platform: the tenants, the installation's setup tokens, and the
	// update check with its platform routing.
	"application_update_state": platformTable,
	"setup_tokens":             platformTable,
	"tenants":                  platformTable,

	// The daemon's bookkeeping.
	"daemon_lease":                  systemTable,
	"fts_backfill_state":            systemTable,
	"job_leases":                    systemTable,
	"notification_config_import":    systemTable,
	"deployment_notification_ids":   systemTable,
	"restore_epochs":                systemTable,
	"scan_cycle_identity_backfill":  systemTable,
	"sqlite_sequence":               systemTable,
	"sse_event_cursor":              systemTable,
	"startup_state":                 systemTable,
	"timestamp_normalization_state": systemTable,
	// Schema 52 retired the legacy administrator row; only migrations read
	// this table.
	"admins": systemTable,
	// The state of inactive config.yaml jobs, keyed by job name. Those jobs
	// belong to the default tenant, and only the host CLI and retention read
	// their state.
	"job_states": systemTable,

	// Public registry data, cached for every tenant.
	"rdap_cache": sharedTable,
}
