package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/crypt0rr/edgewatch/internal/app"
	"github.com/crypt0rr/edgewatch/internal/auth"
	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// The platform console's API, for platform administrators. It manages the
// business units (tenants), their administrators and capacity, the
// platform administrators, the platform's own notification destinations and
// update routing, and it reads the platform audit and the deployment
// status. It never returns a unit's data: a unit appears with its identity,
// state and counts, and a unit's accounts as summaries without credentials.
//
// Only a platform administrator's session holds the permissions of its
// routes; Server.api checks them before platformRoute runs, and
// platformRoute checks the role again. The handlers act through the
// platform's store and the application, which check in their write
// transactions that the actor is an enabled platform administrator.

// isPlatformPermission reports whether a permission is one of the platform
// console's, which only a platform administrator holds.
func isPlatformPermission(permission string) bool {
	switch permission {
	case auth.PermissionUnitsManage, auth.PermissionUnitAccountsManage, auth.PermissionPlatformAuditRead, auth.PermissionPlatformNotificationsManage, auth.PermissionPlatformStatusRead:
		return true
	}
	return false
}

// unitRefView names a business unit.
type unitRefView struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Slug string `json:"slug"`
}

// addSessionScope adds the business unit keys to a session description:
// scope, "platform" for a platform administrator and "unit" for any other
// account; unit, the account's unit or null; and multi_unit, whether more
// than one unit that is not deleted exists.
func (s *Server) addSessionScope(ctx context.Context, response map[string]any, user store.User) error {
	tenants, err := s.Store.Platform().Tenants(ctx)
	if err != nil {
		return err
	}
	response["multi_unit"] = len(tenants) > 1
	response["scope"], response["unit"] = "unit", nil
	if user.Role == store.RolePlatformAdmin {
		response["scope"] = "platform"
		return nil
	}
	for _, tenant := range tenants {
		if tenant.ID == user.TenantID {
			response["unit"] = unitRefView{ID: tenant.ID, Name: tenant.Name, Slug: tenant.Slug}
		}
	}
	return nil
}

// requiredPlatformPermission maps a platform console path, relative to
// /api/v1 and starting with /platform/, to its capability. It mirrors the
// grammar of platformRoute; anything else, including an empty segment, is
// denied.
func requiredPlatformPermission(path, method string) string {
	parts, ok := routeParts(path, "/platform")
	if !ok || len(parts) == 0 || slices.Contains(parts, "") {
		return auth.PermissionDenied
	}
	switch parts[0] {
	case "units":
		return requiredPlatformUnitPermission(parts[1:], method)
	case "admins":
		switch {
		case len(parts) == 1 && (method == http.MethodGet || method == http.MethodPost),
			len(parts) == 2 && (method == http.MethodPatch || method == http.MethodDelete),
			len(parts) == 3 && parts[2] == "activation" && (method == http.MethodPost || method == http.MethodDelete):
			return auth.PermissionUnitAccountsManage
		}
	case "audit":
		if len(parts) == 1 && method == http.MethodGet {
			return auth.PermissionPlatformAuditRead
		}
	case "notifications":
		switch {
		case len(parts) == 1 && (method == http.MethodGet || method == http.MethodPost),
			len(parts) == 2 && parts[1] == "update-routing" && (method == http.MethodPut || method == http.MethodPatch),
			len(parts) == 2 && (method == http.MethodPatch || method == http.MethodDelete):
			return auth.PermissionPlatformNotificationsManage
		}
	case "status":
		if len(parts) == 1 && method == http.MethodGet {
			return auth.PermissionPlatformStatusRead
		}
	}
	return auth.PermissionDenied
}

// requiredPlatformUnitPermission maps the segments after /platform/units.
func requiredPlatformUnitPermission(segments []string, method string) string {
	switch len(segments) {
	case 0:
		if method == http.MethodGet || method == http.MethodPost {
			return auth.PermissionUnitsManage
		}
	case 1:
		if method == http.MethodGet || method == http.MethodPatch || method == http.MethodDelete {
			return auth.PermissionUnitsManage
		}
	case 2:
		switch {
		case (segments[1] == "disable" || segments[1] == "enable") && method == http.MethodPost,
			segments[1] == "capacity" && (method == http.MethodGet || method == http.MethodPatch):
			return auth.PermissionUnitsManage
		case segments[1] == "accounts" && (method == http.MethodGet || method == http.MethodPost):
			return auth.PermissionUnitAccountsManage
		}
	case 4:
		if segments[1] == "accounts" && ((segments[3] == "password-reset" && method == http.MethodPost) || (segments[3] == "sessions" && method == http.MethodDelete)) {
			return auth.PermissionUnitAccountsManage
		}
	}
	return auth.PermissionDenied
}

// platformRoute serves the platform console's routes, the rest of the path
// after /platform/.
func (s *Server) platformRoute(w http.ResponseWriter, r *http.Request, session store.Session, rest string) {
	if session.Role != store.RolePlatformAdmin {
		forbiddenRoute(w)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	parts := strings.Split(strings.Trim(rest, "/"), "/")
	switch {
	case len(parts) == 1 && parts[0] == "units" && r.Method == http.MethodGet:
		s.listPlatformUnits(w, r)
	case len(parts) == 1 && parts[0] == "units" && r.Method == http.MethodPost:
		s.createPlatformUnit(w, r, session)
	case len(parts) == 2 && parts[0] == "units" && r.Method == http.MethodGet:
		s.getPlatformUnit(w, r, parts[1])
	case len(parts) == 2 && parts[0] == "units" && r.Method == http.MethodPatch:
		s.renamePlatformUnit(w, r, session, parts[1])
	case len(parts) == 2 && parts[0] == "units" && r.Method == http.MethodDelete:
		s.deletePlatformUnit(w, r, session, parts[1])
	case len(parts) == 3 && parts[0] == "units" && parts[2] == "disable" && r.Method == http.MethodPost:
		s.setPlatformUnitState(w, r, session, parts[1], false)
	case len(parts) == 3 && parts[0] == "units" && parts[2] == "enable" && r.Method == http.MethodPost:
		s.setPlatformUnitState(w, r, session, parts[1], true)
	case len(parts) == 3 && parts[0] == "units" && parts[2] == "capacity" && r.Method == http.MethodGet:
		s.getPlatformUnitCapacity(w, r, parts[1])
	case len(parts) == 3 && parts[0] == "units" && parts[2] == "capacity" && r.Method == http.MethodPatch:
		s.updatePlatformUnitCapacity(w, r, session, parts[1])
	case len(parts) == 3 && parts[0] == "units" && parts[2] == "accounts" && r.Method == http.MethodGet:
		s.listPlatformUnitAccounts(w, r, parts[1])
	case len(parts) == 3 && parts[0] == "units" && parts[2] == "accounts" && r.Method == http.MethodPost:
		s.invitePlatformUnitAdmin(w, r, session, parts[1])
	case len(parts) == 5 && parts[0] == "units" && parts[2] == "accounts" && parts[4] == "password-reset" && r.Method == http.MethodPost:
		s.resetPlatformUnitAdmin(w, r, session, parts[1], parts[3])
	case len(parts) == 5 && parts[0] == "units" && parts[2] == "accounts" && parts[4] == "sessions" && r.Method == http.MethodDelete:
		s.revokePlatformUnitAccountSessions(w, r, session, parts[1], parts[3])
	case len(parts) == 1 && parts[0] == "admins" && r.Method == http.MethodGet:
		s.listPlatformAdmins(w, r)
	case len(parts) == 1 && parts[0] == "admins" && r.Method == http.MethodPost:
		s.invitePlatformAdmin(w, r, session)
	case len(parts) == 2 && parts[0] == "admins" && r.Method == http.MethodPatch:
		s.updatePlatformAdmin(w, r, session, parts[1])
	case len(parts) == 2 && parts[0] == "admins" && r.Method == http.MethodDelete:
		s.deletePendingPlatformAdmin(w, r, session, parts[1])
	case len(parts) == 3 && parts[0] == "admins" && parts[2] == "activation" && r.Method == http.MethodPost:
		s.renewPlatformAdminInvitation(w, r, session, parts[1])
	case len(parts) == 3 && parts[0] == "admins" && parts[2] == "activation" && r.Method == http.MethodDelete:
		s.revokePlatformAdminInvitation(w, r, session, parts[1])
	case len(parts) == 1 && parts[0] == "audit" && r.Method == http.MethodGet:
		s.platformAudit(w, r)
	case len(parts) == 1 && parts[0] == "notifications" && r.Method == http.MethodGet:
		s.listPlatformNotifications(w, r)
	case len(parts) == 1 && parts[0] == "notifications" && r.Method == http.MethodPost:
		s.createPlatformNotification(w, r, session)
	case len(parts) == 2 && parts[0] == "notifications" && parts[1] == "update-routing" && r.Method == http.MethodPut:
		s.updatePlatformNotificationRouting(w, r, session)
	case len(parts) == 2 && parts[0] == "notifications" && parts[1] == "update-routing" && r.Method == http.MethodPatch:
		s.togglePlatformNotificationRouting(w, r, session)
	case len(parts) == 2 && parts[0] == "notifications" && r.Method == http.MethodPatch:
		s.updatePlatformNotification(w, r, session, parts[1])
	case len(parts) == 2 && parts[0] == "notifications" && r.Method == http.MethodDelete:
		s.deletePlatformNotification(w, r, session, parts[1])
	case len(parts) == 1 && parts[0] == "status" && r.Method == http.MethodGet:
		s.platformStatus(w, r)
	default:
		writeError(w, http.StatusNotFound, "not_found", "endpoint not found", nil)
	}
}

// platformUnitView is a business unit as the platform console shows it: its
// identity, state and counts, never its data.
type platformUnitView struct {
	ID             string    `json:"id"`
	Name           string    `json:"name"`
	Slug           string    `json:"slug"`
	Status         string    `json:"status"`
	IsDefault      bool      `json:"is_default"`
	Revision       int64     `json:"revision"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
	StateChangedAt time.Time `json:"state_changed_at"`
	// Accounts counts every account of the unit, Administrators its enabled
	// administrators, Jobs its jobs that are not archived, and StoredScans
	// the scans its history holds, those of archived jobs included.
	Accounts       int                `json:"accounts"`
	Administrators int                `json:"administrators"`
	Jobs           int                `json:"jobs"`
	StoredScans    int64              `json:"stored_scans"`
	Slots          platformSlotView   `json:"slots"`
	Purge          *platformPurgeView `json:"purge,omitempty"`
}

// platformSlotView is a unit's scan slot use. Limit is the most slots it may
// hold under the deployment's capacity and its own cap.
type platformSlotView struct {
	InUse  int `json:"in_use"`
	Queued int `json:"queued"`
	Limit  int `json:"limit,omitempty"`
}

// platformPurgeView is the progress of the purge of a unit being deleted.
type platformPurgeView struct {
	Phase string `json:"phase"`
	Rows  int64  `json:"rows"`
}

// platformLimitsView holds the deployment's scan settings, which bound every
// unit's capacity.
type platformLimitsView struct {
	MaxConcurrentScans int   `json:"max_concurrent_scans"`
	MaxProbeCount      int64 `json:"max_probe_count"`
	MaxNaabuProbeCount int64 `json:"max_naabu_probe_count"`
	MaxProbeCountLimit int64 `json:"max_probe_count_limit"`
}

func (s *Server) platformLimits() platformLimitsView {
	limits := s.App.DeploymentCapacityLimits()
	return platformLimitsView{MaxConcurrentScans: limits.MaxConcurrentScans, MaxProbeCount: limits.MaxProbeCount, MaxNaabuProbeCount: limits.MaxNaabuProbeCount, MaxProbeCountLimit: config.MaxProbeCountLimit}
}

func platformUnitViewOf(record store.TenantRecord, usage app.SlotUsage) platformUnitView {
	view := platformUnitView{ID: record.ID, Name: record.Name, Slug: record.Slug, Status: record.State, IsDefault: record.IsDefault, Revision: record.Revision, CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt, StateChangedAt: record.StateChangedAt, Accounts: record.Accounts, Administrators: record.Administrators, Jobs: record.Jobs, StoredScans: record.StoredScans}
	if unit, ok := usage.Units[record.ID]; ok {
		view.Slots = platformSlotView{InUse: unit.InUse, Queued: unit.Queued}
	}
	if record.State == store.TenantStateDeleting {
		view.Purge = &platformPurgeView{Phase: record.PurgePhase, Rows: record.PurgeRows}
	}
	return view
}

// forbiddenRoute is the response of a route that does not exist for the
// caller, as Server.api's gate writes it.
func forbiddenRoute(w http.ResponseWriter) {
	writeError(w, http.StatusForbidden, "forbidden", "your account is not allowed to perform this action", map[string]string{"permission": "route"})
}

// writePlatformError maps a failed platform change. notFound is the message
// of a missing resource; the store reports a unit of the wrong kind, a
// foreign account and an unknown ID all as ErrNotFound.
func (s *Server) writePlatformError(w http.ResponseWriter, r *http.Request, err error, action, notFound string) {
	switch {
	case s.writeAuditUnavailable(w, err, action):
	case errors.Is(err, store.ErrNotFound):
		writeError(w, http.StatusNotFound, "not_found", notFound, nil)
	case errors.Is(err, store.ErrConflict):
		writeError(w, http.StatusConflict, "conflict", "the resource was modified; reload and try again", nil)
	case errors.Is(err, store.ErrTenantStateChange):
		writeError(w, http.StatusConflict, "unit_state", err.Error(), nil)
	case errors.Is(err, store.ErrTenantNotActive):
		writeError(w, http.StatusConflict, "unit_not_active", "the business unit is not active", nil)
	case errors.Is(err, store.ErrDefaultTenantDeletion):
		writeError(w, http.StatusConflict, "default_unit", err.Error(), nil)
	case errors.Is(err, store.ErrLastPlatformAdmin):
		writeError(w, http.StatusBadRequest, "last_platform_admin", err.Error(), nil)
	case errors.Is(err, store.ErrAccountNotPermitted):
		writeError(w, http.StatusForbidden, "not_permitted", err.Error(), nil)
	case errors.Is(err, store.ErrTenantNameInUse):
		writeError(w, http.StatusConflict, "conflict", store.ErrTenantNameInUse.Error(), map[string]string{"name": store.ErrTenantNameInUse.Error()})
	case errors.Is(err, store.ErrTenantSlugInUse):
		writeError(w, http.StatusConflict, "conflict", store.ErrTenantSlugInUse.Error(), map[string]string{"slug": store.ErrTenantSlugInUse.Error()})
	case errors.Is(err, store.ErrUsernameUnavailable):
		writeError(w, http.StatusConflict, "conflict", store.ErrUsernameUnavailable.Error(), map[string]string{"username": store.ErrUsernameUnavailable.Error()})
	case errors.Is(err, store.ErrValidation):
		writePlatformValidationError(w, err)
	default:
		s.writeInternalError(w, r, "store", err)
	}
}

// writePlatformValidationError reports a validation error with the field it
// names.
func writePlatformValidationError(w http.ResponseWriter, err error) {
	message := err.Error()
	field := "unit"
	switch {
	case errors.Is(err, store.ErrTenantNameMismatch):
		field = "confirm_name"
	case strings.Contains(message, "slug"):
		field = "slug"
	case strings.Contains(message, "name"):
		field = "name"
	default:
		for _, name := range []string{"max_concurrent_scans", "max_naabu_probe_count", "max_probe_count", "high_cost_ceiling"} {
			if strings.Contains(message, name) {
				field = name
				break
			}
		}
	}
	writeError(w, http.StatusBadRequest, "validation_failed", message, map[string]string{field: message})
}

// platformActorAudit returns the audit entry of a platform
// administrator's action.
func platformActorAudit(session store.Session, action, detail string) store.AuditEntry {
	entry := actorAudit(session, action, detail)
	entry.ActorKind = store.AuditActorPlatform
	return entry
}

// platformUnit returns the unit with the ID, or writes the not-found
// response. A deleted unit's tombstone counts as found only when
// allowDeleted is true.
func (s *Server) platformUnit(w http.ResponseWriter, r *http.Request, id string, allowDeleted bool) (store.TenantRecord, bool) {
	record, err := s.Store.Platform().GetTenant(r.Context(), id)
	if err == nil && record.State == store.TenantStateDeleted && !allowDeleted {
		err = store.ErrNotFound
	}
	if err != nil {
		s.writePlatformError(w, r, err, "", "business unit not found")
		return store.TenantRecord{}, false
	}
	return record, true
}

func (s *Server) listPlatformUnits(w http.ResponseWriter, r *http.Request) {
	records, err := s.Store.Platform().ListTenants(r.Context())
	if err != nil {
		s.writeInternalError(w, r, "store", err)
		return
	}
	usage := s.App.SlotUsage()
	units := make([]platformUnitView, 0, len(records))
	for _, record := range records {
		units = append(units, platformUnitViewOf(record, usage))
	}
	writeJSON(w, http.StatusOK, map[string]any{"units": units, "limits": s.platformLimits()})
}

func (s *Server) getPlatformUnit(w http.ResponseWriter, r *http.Request, id string) {
	record, ok := s.platformUnit(w, r, id, true)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, platformUnitViewOf(record, s.App.SlotUsage()))
}

// slugFromName derives a unit's slug from its name when the request names
// none: lowercase letters and digits, with a hyphen for each run of other
// characters, at most 40 characters. The store validates the result.
func slugFromName(name string) string {
	var slug strings.Builder
	hyphen := false
	for _, character := range strings.ToLower(strings.TrimSpace(name)) {
		switch {
		case character >= 'a' && character <= 'z', character >= '0' && character <= '9':
			slug.WriteRune(character)
			hyphen = false
		case !hyphen && slug.Len() > 0:
			slug.WriteByte('-')
			hyphen = true
		}
		if slug.Len() >= 40 {
			break
		}
	}
	return strings.Trim(slug.String(), "-")
}

func (s *Server) createPlatformUnit(w http.ResponseWriter, r *http.Request, session store.Session) {
	var input struct {
		Name string `json:"name"`
		Slug string `json:"slug"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	slug := strings.TrimSpace(input.Slug)
	if slug == "" {
		slug = slugFromName(input.Name)
	}
	record, err := s.App.CreateUnit(r.Context(), input.Name, slug, platformActorAudit(session, "", ""))
	if err != nil {
		s.writePlatformError(w, r, err, "tenant.created", "business unit not found")
		return
	}
	writeJSON(w, http.StatusCreated, platformUnitViewOf(record, s.App.SlotUsage()))
}

func (s *Server) renamePlatformUnit(w http.ResponseWriter, r *http.Request, session store.Session, id string) {
	var input struct {
		Revision *int64  `json:"revision"`
		Name     *string `json:"name"`
		Slug     *string `json:"slug"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if input.Revision == nil {
		writeError(w, http.StatusBadRequest, "revision_required", "business unit revision is required", map[string]string{"revision": "revision is required"})
		return
	}
	current, ok := s.platformUnit(w, r, id, false)
	if !ok {
		return
	}
	name, slug := current.Name, current.Slug
	if input.Name != nil {
		name = *input.Name
	}
	if input.Slug != nil {
		slug = *input.Slug
	}
	record, err := s.App.RenameUnit(r.Context(), id, *input.Revision, name, slug, platformActorAudit(session, "", ""))
	if errors.Is(err, store.ErrConflict) {
		writeError(w, http.StatusConflict, "conflict", "the business unit was modified; reload and try again", map[string]any{"current": platformUnitViewOf(current, s.App.SlotUsage())})
		return
	}
	if err != nil {
		s.writePlatformError(w, r, err, "tenant.renamed", "business unit not found")
		return
	}
	writeJSON(w, http.StatusOK, platformUnitViewOf(record, s.App.SlotUsage()))
}

// setPlatformUnitState disables or enables a unit after the platform
// administrator confirms its password. Disabling ends the unit's sessions;
// the application ends the unit's work and live-update streams.
func (s *Server) setPlatformUnitState(w http.ResponseWriter, r *http.Request, session store.Session, id string, enable bool) {
	var input struct {
		Password string `json:"password"`
		Revision *int64 `json:"revision"`
	}
	if !decodeJSON(w, r, &input) || !s.confirmUserMutation(w, r, session, input.Password) {
		return
	}
	current, ok := s.platformUnit(w, r, id, false)
	if !ok {
		return
	}
	revision := current.Revision
	if input.Revision != nil {
		revision = *input.Revision
	}
	change, action := s.App.DisableUnit, "tenant.disabled"
	if enable {
		change, action = s.App.EnableUnit, "tenant.enabled"
	}
	record, err := change(r.Context(), id, revision, platformActorAudit(session, "", ""))
	if err != nil {
		s.writePlatformError(w, r, err, action, "business unit not found")
		return
	}
	writeJSON(w, http.StatusOK, platformUnitViewOf(record, s.App.SlotUsage()))
}

func (s *Server) deletePlatformUnit(w http.ResponseWriter, r *http.Request, session store.Session, id string) {
	var input struct {
		ConfirmName string `json:"confirm_name"`
		Password    string `json:"password"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if strings.TrimSpace(input.ConfirmName) == "" {
		writeError(w, http.StatusBadRequest, "validation_failed", "type the business unit's name to confirm the deletion", map[string]string{"confirm_name": "type the business unit's name to confirm the deletion"})
		return
	}
	if !s.confirmUserMutation(w, r, session, input.Password) {
		return
	}
	record, err := s.App.RequestUnitDeletion(r.Context(), id, input.ConfirmName, platformActorAudit(session, "", ""))
	if err != nil {
		s.writePlatformError(w, r, err, "tenant.deletion_requested", "business unit not found")
		return
	}
	writeJSON(w, http.StatusOK, platformUnitViewOf(record, s.App.SlotUsage()))
}

// platformCapacityView is a unit's capacity: its own settings, where null
// inherits the deployment's and a high_cost_ceiling of 0
// (store.HighCostNotGranted) is no high-cost grant, the deployment's
// limits, and its slot use. Revision is the unit's revision when the
// settings were read, which a change of them names.
type platformCapacityView struct {
	UnitID   string                   `json:"unit_id"`
	Revision int64                    `json:"revision"`
	Capacity platformCapacitySettings `json:"capacity"`
	Limits   platformLimitsView       `json:"limits"`
	Slots    platformSlotView         `json:"slots"`
}

type platformCapacitySettings struct {
	MaxConcurrentScans *int   `json:"max_concurrent_scans"`
	MaxProbeCount      *int64 `json:"max_probe_count"`
	MaxNaabuProbeCount *int64 `json:"max_naabu_probe_count"`
	HighCostCeiling    *int64 `json:"high_cost_ceiling"`
}

func (s *Server) platformCapacityViewOf(id string, capacity store.TenantCapacity) platformCapacityView {
	limits := s.platformLimits()
	usage := s.App.SlotUsage()
	slots := platformSlotView{Limit: limits.MaxConcurrentScans}
	if slotCap := capacity.MaxConcurrentScans; slotCap != nil && *slotCap > 0 && *slotCap < slots.Limit {
		slots.Limit = *slotCap
	}
	if unit, ok := usage.Units[id]; ok {
		slots.InUse, slots.Queued = unit.InUse, unit.Queued
	}
	return platformCapacityView{UnitID: id, Capacity: platformCapacitySettings(capacity), Limits: limits, Slots: slots}
}

func (s *Server) getPlatformUnitCapacity(w http.ResponseWriter, r *http.Request, id string) {
	capacity, revision, err := s.Store.Platform().TenantCapacityRevision(r.Context(), id)
	if err != nil {
		s.writePlatformError(w, r, err, "", "business unit not found")
		return
	}
	view := s.platformCapacityViewOf(id, capacity)
	view.Revision = revision
	writeJSON(w, http.StatusOK, view)
}

// optionalLimit is a capacity setting in a PATCH body: absent keeps the
// setting, null inherits the deployment's, and a number sets it. A
// high_cost_ceiling of 0 grants no ceiling; the store validates each number.
type optionalLimit struct {
	set   bool
	value *int64
}

func (o *optionalLimit) UnmarshalJSON(data []byte) error {
	o.set = true
	if string(data) == "null" {
		o.value = nil
		return nil
	}
	var value int64
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	o.value = &value
	return nil
}

func (o optionalLimit) apply(setting **int64) {
	if o.set {
		*setting = o.value
	}
}

// updatePlatformUnitCapacity changes the settings that the body names and
// keeps the others. A body that names the unit's revision, which the
// capacity view reports, is refused with 409 conflict once another change
// moved the unit on, so a form read before another platform
// administrator's change cannot revert it. Without a revision, the change
// applies to the settings read here, and is refused the same way when
// another change is saved between that read and its write.
func (s *Server) updatePlatformUnitCapacity(w http.ResponseWriter, r *http.Request, session store.Session, id string) {
	var input struct {
		Revision           *int64        `json:"revision"`
		MaxConcurrentScans optionalLimit `json:"max_concurrent_scans"`
		MaxProbeCount      optionalLimit `json:"max_probe_count"`
		MaxNaabuProbeCount optionalLimit `json:"max_naabu_probe_count"`
		HighCostCeiling    optionalLimit `json:"high_cost_ceiling"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	capacity, revision, err := s.Store.Platform().TenantCapacityRevision(r.Context(), id)
	if err != nil {
		s.writePlatformError(w, r, err, "", "business unit not found")
		return
	}
	if input.Revision != nil && *input.Revision != revision {
		writeCapacityConflict(w)
		return
	}
	if input.MaxConcurrentScans.set {
		capacity.MaxConcurrentScans = nil
		if value := input.MaxConcurrentScans.value; value != nil {
			if *value < 1 || *value > int64(s.platformLimits().MaxConcurrentScans) {
				writePlatformValidationError(w, fmt.Errorf("%w: max_concurrent_scans must be between 1 and %d", store.ErrValidation, s.platformLimits().MaxConcurrentScans))
				return
			}
			slots := int(*value)
			capacity.MaxConcurrentScans = &slots
		}
	}
	input.MaxProbeCount.apply(&capacity.MaxProbeCount)
	input.MaxNaabuProbeCount.apply(&capacity.MaxNaabuProbeCount)
	input.HighCostCeiling.apply(&capacity.HighCostCeiling)
	err = s.App.SetTenantCapacityAt(r.Context(), id, revision, capacity, platformActorAudit(session, "", ""))
	if errors.Is(err, store.ErrConflict) {
		writeCapacityConflict(w)
		return
	}
	if err != nil {
		s.writePlatformError(w, r, err, "tenant.capacity_changed", "business unit not found")
		return
	}
	s.getPlatformUnitCapacity(w, r, id)
}

// writeCapacityConflict refuses a capacity change that is based on an
// earlier revision of the unit.
func writeCapacityConflict(w http.ResponseWriter) {
	writeError(w, http.StatusConflict, "conflict", "the business unit was modified; reload its capacity and try again", nil)
}

func (s *Server) listPlatformUnitAccounts(w http.ResponseWriter, r *http.Request, id string) {
	if _, ok := s.platformUnit(w, r, id, false); !ok {
		return
	}
	accounts, err := s.Store.Platform().UnitAccounts(r.Context(), id)
	if err != nil {
		s.writePlatformError(w, r, err, "", "business unit not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"accounts": accounts})
}

// invitePlatformUnitAdmin invites an administrator into the unit. The
// platform invites only a unit's administrators; they invite the unit's
// operators and viewers themselves. The one-time activation link is
// returned once.
func (s *Server) invitePlatformUnitAdmin(w http.ResponseWriter, r *http.Request, session store.Session, id string) {
	var input userCreatePayload
	if !decodeJSON(w, r, &input) || !s.confirmUserMutation(w, r, session, input.Password) {
		return
	}
	username, displayName, ok := validateInvitee(w, input.Username, input.DisplayName)
	if !ok {
		return
	}
	if input.Role != "" && input.Role != store.RoleAdministrator {
		const message = "a platform administrator invites only unit administrators"
		writeError(w, http.StatusBadRequest, "validation_failed", message, map[string]string{"role": message})
		return
	}
	if _, ok := s.platformUnit(w, r, id, false); !ok {
		return
	}
	plain, digest, err := auth.NewOpaqueToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "invite_failed", "activation token could not be generated", nil)
		return
	}
	created := time.Now().UTC()
	audit := platformActorAudit(session, "user.created", fmt.Sprintf("unit administrator %s invited by platform administrator %s", username, session.Username))
	user, err := s.Store.Platform().InviteUnitAdmin(r.Context(), id, store.User{Username: username, DisplayName: displayName, Role: store.RoleAdministrator}, digest, created, created.Add(30*time.Minute), audit)
	if err != nil {
		s.writePlatformError(w, r, err, "user.created", "business unit not found")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"user": user.Summary(), "activation_token": plain, "activation_path": activationPath(plain)})
}

// validateInvitee checks an invitee's username and display name, as the
// unit's own invitation does, and writes the field error.
func validateInvitee(w http.ResponseWriter, username, displayName string) (string, string, bool) {
	username = strings.TrimSpace(username)
	if username == "" {
		writeError(w, http.StatusBadRequest, "validation_failed", "username is required", map[string]string{"username": "username is required"})
		return "", "", false
	}
	if _, err := store.NormalizeUsername(username); err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", err.Error(), map[string]string{"username": err.Error()})
		return "", "", false
	}
	if strings.TrimSpace(displayName) == "" {
		displayName = username
	}
	name, err := validateDisplayName(displayName)
	if err != nil {
		writeError(w, http.StatusBadRequest, "validation_failed", err.Error(), map[string]string{"display_name": err.Error()})
		return "", "", false
	}
	return username, name, true
}

// resetPlatformUnitAdmin issues a password-reset link for one of the unit's
// administrators. totp_enrolled tells the console whether the account keeps
// its authenticator, so it can warn that a reset alone then does not let
// someone else sign in.
func (s *Server) resetPlatformUnitAdmin(w http.ResponseWriter, r *http.Request, session store.Session, id, userID string) {
	password, ok := decodeUserPassword(w, r)
	if !ok || !s.confirmUserMutation(w, r, session, password) {
		return
	}
	if _, ok := s.platformUnit(w, r, id, false); !ok {
		return
	}
	account, err := s.Store.Platform().UnitAccount(r.Context(), id, userID)
	if err != nil {
		s.writePlatformError(w, r, err, "", "account not found")
		return
	}
	if account.Role != store.RoleAdministrator {
		writeError(w, http.StatusForbidden, "not_permitted", "a platform administrator resets only unit administrators", nil)
		return
	}
	if !account.Enabled && !account.Pending {
		writeError(w, http.StatusConflict, "user_disabled", "disabled users cannot receive activation or password-reset links", map[string]string{"enabled": "enable the account before issuing an activation or password-reset link"})
		return
	}
	plain, digest, err := auth.NewOpaqueToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "invite_failed", "activation token could not be generated", nil)
		return
	}
	created := time.Now().UTC()
	expires := created.Add(30 * time.Minute)
	audit := platformActorAudit(session, "user.password_reset_issued", fmt.Sprintf("password reset issued for %s by platform administrator %s", account.Username, session.Username))
	if err := s.Store.Platform().IssueUnitAdminPasswordReset(r.Context(), id, userID, digest, created, expires, audit); err != nil {
		s.writePlatformError(w, r, err, "user.password_reset_issued", "account not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"activation_token": plain, "activation_path": activationPath(plain), "expires_at": expires, "totp_enrolled": account.TOTPEnabled})
}

func (s *Server) revokePlatformUnitAccountSessions(w http.ResponseWriter, r *http.Request, session store.Session, id, userID string) {
	password, ok := decodeUserPassword(w, r)
	if !ok || !s.confirmUserMutation(w, r, session, password) {
		return
	}
	if _, ok := s.platformUnit(w, r, id, false); !ok {
		return
	}
	// The record names the account by its username, as the platform's other
	// records of its actions on a unit's accounts do.
	account, err := s.Store.Platform().UnitAccount(r.Context(), id, userID)
	if err != nil {
		s.writePlatformError(w, r, err, "", "account not found")
		return
	}
	audit := platformActorAudit(session, "user.sessions_revoked", fmt.Sprintf("sessions of %s revoked by platform administrator %s", account.Username, session.Username))
	if err := s.Store.Platform().RevokeUnitAccountSessions(r.Context(), id, userID, audit); err != nil {
		if errors.Is(err, store.ErrAuditUnavailable) {
			// The sessions were revoked; only the record is missing.
			s.revokeSSEUser(userID)
		}
		s.writePlatformError(w, r, err, "user.sessions_revoked", "account not found")
		return
	}
	s.revokeSSEUser(userID)
	writeJSON(w, http.StatusNoContent, nil)
}

func (s *Server) listPlatformAdmins(w http.ResponseWriter, r *http.Request) {
	admins, err := s.Store.Platform().PlatformAdmins(r.Context())
	if err != nil {
		s.writeInternalError(w, r, "store", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"admins": admins})
}

// invitePlatformAdmin invites another platform administrator. The account
// stays pending until the invitee redeems the one-time link, which is
// returned once.
func (s *Server) invitePlatformAdmin(w http.ResponseWriter, r *http.Request, session store.Session) {
	var input struct {
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
		Password    string `json:"password"`
	}
	if !decodeJSON(w, r, &input) || !s.confirmUserMutation(w, r, session, input.Password) {
		return
	}
	username, displayName, ok := validateInvitee(w, input.Username, input.DisplayName)
	if !ok {
		return
	}
	plain, digest, err := auth.NewOpaqueToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "invite_failed", "activation token could not be generated", nil)
		return
	}
	created := time.Now().UTC()
	audit := platformActorAudit(session, "", fmt.Sprintf("platform administrator %s invited by %s", username, session.Username))
	admin, err := s.Store.Platform().InvitePlatformAdmin(r.Context(), store.User{Username: username, DisplayName: displayName}, digest, created, created.Add(30*time.Minute), audit)
	if err != nil {
		s.writePlatformError(w, r, err, "platform_admin.invited", "platform administrator not found")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"user": admin, "activation_token": plain, "activation_path": activationPath(plain)})
}

// updatePlatformAdmin enables or disables another platform administrator.
// The last enabled one stays enabled, and an administrator changes its own
// account through the account routes instead. A pending one is neither
// enabled nor disabled: revokePlatformAdminInvitation stops its link,
// renewPlatformAdminInvitation issues a new one, and
// deletePendingPlatformAdmin removes the account.
func (s *Server) updatePlatformAdmin(w http.ResponseWriter, r *http.Request, session store.Session, id string) {
	var input struct {
		Enabled  *bool  `json:"enabled"`
		Revision *int64 `json:"revision"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &input) {
		return
	}
	if input.Enabled == nil {
		writeError(w, http.StatusBadRequest, "validation_failed", "enabled is required", map[string]string{"enabled": "enabled is required"})
		return
	}
	if !s.confirmUserMutation(w, r, session, input.Password) {
		return
	}
	if id == session.UserID {
		writeError(w, http.StatusBadRequest, "self_admin_change", "you cannot enable or disable your own account", nil)
		return
	}
	var revision int64
	if input.Revision != nil {
		revision = *input.Revision
	}
	admin, err := s.Store.Platform().SetPlatformAdminEnabled(r.Context(), id, revision, *input.Enabled, platformActorAudit(session, "", ""))
	if err != nil {
		s.writePlatformError(w, r, err, "platform_admin.updated", "platform administrator not found")
		return
	}
	if !admin.Enabled {
		s.revokeSSEUser(admin.ID)
	}
	writeJSON(w, http.StatusOK, admin)
}

// revokePlatformAdminInvitation revokes the invitation of a pending
// platform administrator, as a unit's administrators revoke a pending
// account's activation link: the link stops working and the account stays
// pending. An account that redeemed its link is refused, and a request that
// finds no usable link is answered no_active_activation.
func (s *Server) revokePlatformAdminInvitation(w http.ResponseWriter, r *http.Request, session store.Session, id string) {
	password, ok := decodeUserPassword(w, r)
	if !ok || !s.confirmUserMutation(w, r, session, password) {
		return
	}
	revoked, err := s.Store.Platform().RevokePlatformAdminInvitation(r.Context(), id, time.Now().UTC(), platformActorAudit(session, "", ""))
	if err != nil {
		s.writePlatformError(w, r, err, "platform_admin.activation_revoked", "platform administrator not found")
		return
	}
	if revoked == 0 {
		writeError(w, http.StatusNotFound, "no_active_activation", "no active activation link exists for this platform administrator", nil)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// renewPlatformAdminInvitation issues a new one-time activation link for a
// pending platform administrator, as a unit's administrators renew a
// pending account's link: it is the way back for an invitation that expired
// or was revoked. The link is returned once, and every older link of the
// account stops working. An account that redeemed its link is refused.
func (s *Server) renewPlatformAdminInvitation(w http.ResponseWriter, r *http.Request, session store.Session, id string) {
	password, ok := decodeUserPassword(w, r)
	if !ok || !s.confirmUserMutation(w, r, session, password) {
		return
	}
	plain, digest, err := auth.NewOpaqueToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "invite_failed", "activation token could not be generated", nil)
		return
	}
	created := time.Now().UTC()
	expires := created.Add(30 * time.Minute)
	admin, err := s.Store.Platform().RenewPlatformAdminInvitation(r.Context(), id, digest, created, expires, platformActorAudit(session, "", ""))
	if err != nil {
		s.writePlatformError(w, r, err, "platform_admin.activation_issued", "platform administrator not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"user": admin, "activation_token": plain, "activation_path": activationPath(plain), "expires_at": expires})
}

// deletePendingPlatformAdmin removes a pending platform administrator, which
// never redeemed its invitation, so its username can be invited again. Its
// links stop working with it. An account that redeemed its link, enabled or
// disabled, is refused: updatePlatformAdmin disables it instead.
func (s *Server) deletePendingPlatformAdmin(w http.ResponseWriter, r *http.Request, session store.Session, id string) {
	password, ok := decodeUserPassword(w, r)
	if !ok || !s.confirmUserMutation(w, r, session, password) {
		return
	}
	if err := s.Store.Platform().DeletePendingPlatformAdmin(r.Context(), id, platformActorAudit(session, "", "")); err != nil {
		s.writePlatformError(w, r, err, "platform_admin.deleted", "platform administrator not found")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) listPlatformNotifications(w http.ResponseWriter, r *http.Request) {
	views, status, err := s.App.Notifier.Platform(s.Store.Platform()).Destinations(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "notification_failed", "notification state could not be loaded", nil)
		return
	}
	state, err := s.Store.Platform().GetApplicationUpdateState(r.Context())
	if err != nil {
		if s.Log != nil {
			s.Log.Warn("platform update routing state unavailable", "error", err)
		}
		writeError(w, http.StatusInternalServerError, "notification_failed", "notification state could not be loaded", nil)
		return
	}
	destinations := state.UpdateNotificationDestinations
	if destinations == nil {
		destinations = []string{}
	}
	routing := map[string]any{"configured": state.UpdateNotificationDestinationsConfigured, "destinations": destinations}
	writeJSON(w, http.StatusOK, map[string]any{"destinations": views, "status": status, "update_routing": routing})
}

// confirmNotificationPassword applies the notification routes' password
// confirmation.
func (s *Server) confirmNotificationPassword(w http.ResponseWriter, r *http.Request, session store.Session, password string) bool {
	if strings.TrimSpace(password) == "" {
		writeError(w, http.StatusBadRequest, "password_required", "account password confirmation is required", map[string]string{"password": "password confirmation is required"})
		return false
	}
	if err := s.Auth.ConfirmPasswordForUser(r.Context(), r, session.UserID, password); err != nil {
		s.writeNotificationAuthError(w, err)
		return false
	}
	return true
}

func (s *Server) createPlatformNotification(w http.ResponseWriter, r *http.Request, session store.Session) {
	var input notificationPayload
	if !decodeJSON(w, r, &input) || !s.confirmNotificationPassword(w, r, session, input.Password) {
		return
	}
	if input.URL == nil {
		writeError(w, http.StatusBadRequest, "validation_failed", "notification URL is required", map[string]string{"url": "notification URL is required"})
		return
	}
	enabled := input.Enabled == nil || *input.Enabled
	view, err := s.App.Notifier.Platform(s.Store.Platform()).CreateManagedWithAudit(r.Context(), input.Name, *input.URL, enabled, platformActorAudit(session, "", "platform notification destination created"))
	if err != nil {
		if s.writeAuditUnavailable(w, err, "platform_notifications.created") {
			return
		}
		s.writeNotificationError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, view)
}

func (s *Server) updatePlatformNotification(w http.ResponseWriter, r *http.Request, session store.Session, id string) {
	var input notificationPayload
	if !decodeJSON(w, r, &input) {
		return
	}
	if input.Revision == nil {
		writeError(w, http.StatusBadRequest, "revision_required", "notification revision is required", nil)
		return
	}
	if !s.confirmNotificationPassword(w, r, session, input.Password) {
		return
	}
	view, err := s.App.Notifier.Platform(s.Store.Platform()).UpdateManagedWithAudit(r.Context(), id, *input.Revision, input.Name, input.URL, input.Enabled, platformActorAudit(session, "", "platform notification destination updated: "+id))
	if err != nil {
		if s.writeAuditUnavailable(w, err, "platform_notifications.updated") {
			return
		}
		s.writeNotificationError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) deletePlatformNotification(w http.ResponseWriter, r *http.Request, session store.Session, id string) {
	var input notificationPayload
	if !decodeJSON(w, r, &input) {
		return
	}
	if input.Revision == nil {
		writeError(w, http.StatusBadRequest, "revision_required", "notification revision is required", nil)
		return
	}
	if !s.confirmNotificationPassword(w, r, session, input.Password) {
		return
	}
	if err := s.App.Notifier.Platform(s.Store.Platform()).DeleteManagedWithAudit(r.Context(), id, *input.Revision, platformActorAudit(session, "", "platform notification destination deleted: "+id)); err != nil {
		if s.writeAuditUnavailable(w, err, "platform_notifications.deleted") {
			return
		}
		s.writeNotificationError(w, err)
		return
	}
	writeJSON(w, http.StatusNoContent, nil)
}

// updatePlatformNotificationRouting chooses the platform destinations that
// receive the platform's copy of the application update alerts. An empty
// array silences it; omitting the field is refused.
func (s *Server) updatePlatformNotificationRouting(w http.ResponseWriter, r *http.Request, session store.Session) {
	var input updateNotificationRoutingPayload
	if !decodeJSON(w, r, &input) || !s.confirmNotificationPassword(w, r, session, input.Password) {
		return
	}
	if input.Destinations == nil {
		writeError(w, http.StatusBadRequest, "validation_failed", "destinations must be an array", map[string]string{"destinations": "select zero or more platform destinations"})
		return
	}
	s.updateRoutingMu.Lock()
	defer s.updateRoutingMu.Unlock()
	// The store checks the selection again when it writes it.
	platform := s.Store.Platform()
	if err := s.App.Notifier.Platform(platform).ValidateDestinationSelection(r.Context(), input.Destinations); err != nil {
		if !writeDestinationSelectionError(w, err) {
			writeError(w, http.StatusInternalServerError, "notification", "notification destinations could not be loaded", nil)
		}
		return
	}
	if err := platform.SetPlatformUpdateDestinations(r.Context(), input.Destinations, platformActorAudit(session, "", "platform update notification routing changed")); err != nil {
		if !writeDestinationSelectionError(w, err) {
			s.writePlatformError(w, r, err, "platform_notifications.update_routing", "notification destination not found")
		}
		return
	}
	destinations := []string{}
	if state, err := platform.GetApplicationUpdateState(r.Context()); err == nil && state.UpdateNotificationDestinations != nil {
		destinations = state.UpdateNotificationDestinations
	}
	writeJSON(w, http.StatusOK, map[string]any{"configured": true, "destinations": destinations})
}

func (s *Server) togglePlatformNotificationRouting(w http.ResponseWriter, r *http.Request, session store.Session) {
	var input toggleNotificationUpdateRoutingPayload
	if !decodeJSON(w, r, &input) || !s.confirmNotificationPassword(w, r, session, input.Password) {
		return
	}
	input.DestinationID = strings.TrimSpace(input.DestinationID)
	if input.DestinationID == "" || input.Enabled == nil {
		writeError(w, http.StatusBadRequest, "validation_failed", "destination_id and enabled are required", map[string]string{"destination_id": "select one configured destination"})
		return
	}
	s.updateRoutingMu.Lock()
	defer s.updateRoutingMu.Unlock()
	platform := s.Store.Platform()
	notifier := s.App.Notifier.Platform(platform)
	if err := notifier.ValidateDestinationSelection(r.Context(), []string{input.DestinationID}); err != nil {
		if !writeDestinationSelectionError(w, err) {
			writeError(w, http.StatusInternalServerError, "notification", "notification destinations could not be loaded", nil)
		}
		return
	}
	state, err := platform.GetApplicationUpdateState(r.Context())
	if err != nil {
		if s.Log != nil {
			s.Log.Warn("platform update routing state unavailable", "error", err)
		}
		writeError(w, http.StatusInternalServerError, "notification_failed", "notification state could not be loaded", nil)
		return
	}
	selection := state.UpdateNotificationDestinations
	if !state.UpdateNotificationDestinationsConfigured {
		selection = nil
	}
	selection = toggleUpdateDestination(selection, input.DestinationID, *input.Enabled)
	if err := platform.SetPlatformUpdateDestinations(r.Context(), selection, platformActorAudit(session, "", "platform update notification routing changed")); err != nil {
		if !writeDestinationSelectionError(w, err) {
			s.writePlatformError(w, r, err, "platform_notifications.update_routing", "notification destination not found")
		}
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"configured": true, "destinations": selection})
}

// platformStatus reports the deployment as numbers: the units by state,
// their accounts, jobs and stored scans, the platform administrators, the
// scan capacity and its use, and the version and update status.
func (s *Server) platformStatus(w http.ResponseWriter, r *http.Request) {
	platform := s.Store.Platform()
	records, err := platform.ListTenants(r.Context())
	if err != nil {
		s.writeInternalError(w, r, "store", err)
		return
	}
	admins, err := platform.PlatformAdmins(r.Context())
	if err != nil {
		s.writeInternalError(w, r, "store", err)
		return
	}
	units := map[string]int{"total": len(records), store.TenantStateActive: 0, store.TenantStateDisabled: 0, store.TenantStateDeleting: 0}
	var accounts, jobs int
	var storedScans int64
	for _, record := range records {
		units[record.State]++
		accounts += record.Accounts
		jobs += record.Jobs
		storedScans += record.StoredScans
	}
	enabledAdmins := 0
	for _, admin := range admins {
		if admin.Enabled {
			enabledAdmins++
		}
	}
	usage := s.App.SlotUsage()
	status := map[string]any{
		"version":         s.Version,
		"updates":         s.applicationUpdateStatus(r.Context()),
		"units":           units,
		"accounts":        accounts,
		"jobs":            jobs,
		"stored_scans":    storedScans,
		"platform_admins": map[string]int{"total": len(admins), "enabled": enabledAdmins},
		"capacity": map[string]any{
			"limits": s.platformLimits(),
			"slots":  map[string]int{"capacity": usage.Capacity, "in_use": usage.InUse, "queued": usage.Queued},
		},
	}
	if proxy, seen := s.Auth.UntrustedProxy(); seen {
		status["untrusted_proxy"] = proxy
	}
	s.addVersionReleaseURL(status)
	writeJSON(w, http.StatusOK, status)
}
