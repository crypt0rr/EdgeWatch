package store

// Schema 57 records whether a tenant has a high-cost grant. Earlier releases
// gave each new tenant a high-cost ceiling equal to the lower of the
// deployment's two probe budgets at its creation, as a number like any
// other. Once config.yaml lowered those budgets, that number raised a
// high-cost job's budgets although no platform administrator had granted
// it. From schema 57 a tenant without a grant has high_cost_granted=0 and no
// ceiling, which raises nothing whatever config.yaml sets.
//
// The migration adds the column, which keeps every existing ceiling, and
// then takes the automatic ceiling away from each tenant other than the
// default one whose capacity no platform administrator has ever saved:
// SetTenantCapacity is the only other writer of the ceiling, and it records
// every change in the security audit, which retention never prunes, as
// tenant.capacity_changed. A ceiling that a platform administrator saved
// stays a grant, as does a NULL ceiling, which inherits
// config.MaxProbeCountLimit and which only a platform administrator can set
// on such a tenant. The default tenant keeps its ceiling.
//
// The column's check keeps a tenant without a grant from holding a number
// that a later release could read as a ceiling again. Both statements can
// run again: the column is added once, and a repeated update finds no
// tenant with an automatic ceiling left.
func migration57Statements() []string {
	return []string{
		`ALTER TABLE tenants ADD COLUMN high_cost_granted INTEGER NOT NULL DEFAULT 1 CHECK(high_cost_granted IN (0,1) AND (high_cost_granted=1 OR high_cost_ceiling IS NULL))`,
		`UPDATE tenants SET high_cost_granted=0,high_cost_ceiling=NULL
WHERE is_default=0 AND high_cost_granted=1 AND high_cost_ceiling IS NOT NULL
AND NOT EXISTS (SELECT 1 FROM security_audit AS audit WHERE audit.tenant_id=tenants.id AND audit.action='` + auditActionTenantCapacityChanged + `')`,
	}
}
