package notify

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/google/uuid"
)

// destinationSet holds the destinations of one tenant: the web-managed
// destinations it owns and, for the tenant that owns them, the deployment
// destinations from config.yaml. Everything a tenant lists, selects, tests,
// or routes an alert to comes from its set, so another tenant's
// destinations and the platform's are not found, exactly as unknown ones.
// A set is a snapshot; its maps are never changed after it is built.
type destinationSet struct {
	managed    map[string]managedDestination
	fileURLs   map[string]string
	fileLegacy map[string]string
	// deployment reports whether the tenant owns the deployment
	// destinations, and with them the config.yaml import state.
	deployment bool
	keyErr     error
}

// defaultSetLocked returns the default tenant's destinations as the last
// Reload read them. The caller holds n.mu. Queue uses it for the alerts of
// config.yaml jobs, which belong to the default tenant; everything else
// reads a tenant's destinations through Notifier.Tenant.
func (n *Notifier) defaultSetLocked() destinationSet {
	managed := make(map[string]managedDestination, len(n.managed))
	for id, entry := range n.managed {
		if entry.record.TenantID == store.DefaultTenantID {
			managed[id] = entry
		}
	}
	return destinationSet{managed: managed, fileURLs: n.fileURLs, fileLegacy: n.fileLegacy, deployment: true, keyErr: n.keyErr}
}

// defaultSet is defaultSetLocked for a caller that does not hold n.mu.
func (n *Notifier) defaultSet() destinationSet {
	n.mu.RLock()
	defer n.mu.RUnlock()
	set := n.defaultSetLocked()
	set.fileURLs, set.fileLegacy = cloneStrings(set.fileURLs), cloneStrings(set.fileLegacy)
	return set
}

// platformSet returns the platform's destinations as the last Reload read
// them: the web-managed destinations without a tenant. The deployment
// destinations from config.yaml belong to the default tenant, not to the
// platform.
func (n *Notifier) platformSet() destinationSet {
	n.mu.RLock()
	defer n.mu.RUnlock()
	managed := map[string]managedDestination{}
	for id, entry := range n.managed {
		if entry.record.TenantID == "" {
			managed[id] = entry
		}
	}
	return destinationSet{managed: managed, fileURLs: map[string]string{}, fileLegacy: map[string]string{}, keyErr: n.keyErr}
}

// PlatformUpdateDestinations resolves the platform's update routing to the
// queue keys of the enabled platform destinations it selects. A tenant's
// destination and a deployment destination are never selected, exactly as
// an unknown one is not. The platform routing has no legacy "every
// destination" mode, so a nil selection, like an empty one, selects
// nothing.
func (n *Notifier) PlatformUpdateDestinations(ctx context.Context, selection []string) ([]string, error) {
	if len(selection) == 0 {
		return []string{}, nil
	}
	if err := n.Reload(ctx); err != nil {
		return nil, err
	}
	return n.platformSet().queue(selection), nil
}

func cloneStrings(values map[string]string) map[string]string {
	cloned := make(map[string]string, len(values))
	for key, value := range values {
		cloned[key] = value
	}
	return cloned
}

// tenantSet reads the destinations of the tenant of ts through that store
// and decrypts them with the current key, so it never holds another
// tenant's destinations or credentials.
func (n *Notifier) tenantSet(ctx context.Context, ts *store.TenantStore) (destinationSet, error) {
	records, err := ts.ListManagedNotifications(ctx)
	deployment := false
	if err == nil {
		deployment, err = ts.OwnsDeploymentNotifications(ctx)
	}
	if err != nil {
		return destinationSet{}, err
	}
	managed, keyErr := n.openManaged(records)
	set := destinationSet{managed: managed, fileURLs: map[string]string{}, fileLegacy: map[string]string{}, deployment: deployment, keyErr: keyErr}
	if deployment {
		n.mu.RLock()
		set.fileURLs, set.fileLegacy = cloneStrings(n.fileURLs), cloneStrings(n.fileLegacy)
		n.mu.RUnlock()
	}
	return set, nil
}

// views returns the redacted metadata of every destination, unsorted and
// without delivery health.
func (set destinationSet) views() []DestinationView {
	views := make([]DestinationView, 0, len(set.fileURLs)+len(set.managed))
	for id, raw := range set.fileURLs {
		views = append(views, DestinationView{ID: "file:" + id, Name: "Deployment destination", Provider: providerForURL(raw), Source: "deployment", Enabled: true, ReadOnly: true})
	}
	for _, entry := range set.managed {
		views = append(views, viewFromManaged(entry))
	}
	return views
}

// finishViews joins delivery health to the views by stable identity, so
// managed credential revisions share one operator-facing view, and sorts
// them for display.
func finishViews(views []DestinationView, health map[string]store.DeliveryHealth) []DestinationView {
	for i := range views {
		identity := "managed:" + views[i].ID
		if views[i].Source == "deployment" {
			identity = strings.TrimPrefix(views[i].ID, "file:")
		}
		applyDeliveryHealth(&views[i], health[identity])
	}
	sort.Slice(views, func(i, j int) bool {
		if views[i].Source != views[j].Source {
			return views[i].Source < views[j].Source
		}
		return strings.ToLower(views[i].Name) < strings.ToLower(views[j].Name)
	})
	return views
}

// legacySelection returns the stable selectors of the destinations that
// take part in the legacy nil selection. It is never nil.
func (set destinationSet) legacySelection() []string {
	selection := make([]string, 0, len(set.fileURLs)+len(set.managed))
	for id := range set.fileURLs {
		selection = append(selection, "file:"+id)
	}
	for id, entry := range set.managed {
		if entry.record.Enabled {
			selection = append(selection, id)
		}
	}
	sort.Strings(selection)
	return selection
}

// status counts the destinations and reports the state of the key that the
// web-managed ones need.
func (set destinationSet) status() map[string]any {
	locked, activeManaged := 0, 0
	for _, entry := range set.managed {
		if entry.locked {
			locked++
		}
		if entry.record.Enabled && !entry.locked {
			activeManaged++
		}
	}
	keyState := "not_required"
	if len(set.managed) > 0 {
		keyState = "ready"
		if set.keyErr != nil {
			keyState = keyErrorCode(set.keyErr)
		} else if locked > 0 {
			keyState = "decrypt_failed"
		}
	}
	return map[string]any{"deployment": len(set.fileURLs), "managed": len(set.managed), "active": len(set.fileURLs) + activeManaged, "locked": locked, "key_state": keyState}
}

// completeStatus adds the config.yaml import outcome, for the tenant that
// owns the deployment destinations, and the delivery totals of the tenant
// of ts. Only the outcome and counts are exposed, never a URL.
func (n *Notifier) completeStatus(ctx context.Context, set destinationSet, ts *store.TenantStore) map[string]any {
	status := set.status()
	if n.Store == nil {
		return status
	}
	if set.deployment {
		// Tell the console when config.yaml still lists URLs that were
		// imported, or when their import failed and they are still delivered
		// from config.yaml.
		if state, err := n.Store.System().NotificationConfigImportState(ctx); err == nil {
			switch {
			case state.Status == store.NotificationConfigImportFailed:
				status["config_import"] = store.NotificationConfigImportFailed
			case state.ImportedURLs > 0:
				status["config_import"] = store.NotificationConfigImportImported
			}
		}
	}
	if health, err := ts.ListDeliveryHealth(ctx); err == nil {
		addDeliveryTotals(status, health)
	}
	return status
}

// addDeliveryTotals adds the delivery totals of one owner's destinations to
// its status: counts only, never a URL or a provider error.
func addDeliveryTotals(status map[string]any, health map[string]store.DeliveryHealth) {
	pending, retrying, deferrals, terminal := 0, 0, 0, 0
	for _, item := range health {
		pending += item.Pending
		retrying += item.Retrying
		deferrals += item.Deferrals
		terminal += item.TerminalFailures
	}
	status["delivery_pending"] = pending
	status["delivery_retrying"] = retrying
	status["delivery_deferrals"] = deferrals
	status["delivery_terminal_failures"] = terminal
}

// keys returns the destinations that an alert with the legacy nil selection
// goes to: every enabled destination of the set. A managed destination may
// be locked because its encryption key is temporarily unavailable; its
// durable outbox entry must still be created so Drain can defer it until the
// key is restored.
func (set destinationSet) keys() map[string]struct{} {
	out := make(map[string]struct{}, len(set.fileURLs)+len(set.managed))
	for id := range set.fileURLs {
		out[id] = struct{}{}
	}
	for id, entry := range set.managed {
		if entry.record.Enabled {
			out[managedKey(id, entry.record.Revision)] = struct{}{}
		}
	}
	return out
}

func (set destinationSet) selectedKeys(selection []string) map[string]struct{} {
	keys := make(map[string]struct{}, len(selection))
	for _, selector := range selection {
		selector = strings.TrimSpace(selector)
		if key, ok := set.keyFor(selector); ok {
			keys[key] = struct{}{}
		}
	}
	return keys
}

// queue resolves a routing selection to sorted queue keys. A nil selection
// is the legacy mode and follows every enabled destination of the set; an
// explicit empty selection disables delivery.
func (set destinationSet) queue(selection []string) []string {
	var keys map[string]struct{}
	if selection == nil {
		keys = set.keys()
	} else {
		keys = set.selectedKeys(selection)
	}
	out := make([]string, 0, len(keys))
	for key := range keys {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

func (set destinationSet) selectorExists(selector string) bool {
	if strings.HasPrefix(selector, "file:") {
		id := strings.TrimPrefix(selector, "file:")
		if id == "" {
			return false
		}
		if _, ok := set.fileURLs[id]; ok {
			return true
		}
		_, ok := set.fileLegacy[id]
		return ok
	}
	_, ok := set.managed[selector]
	return ok
}

func (set destinationSet) keyFor(selector string) (string, bool) {
	if strings.HasPrefix(selector, "file:") {
		id := strings.TrimPrefix(selector, "file:")
		if _, ok := set.fileURLs[id]; ok && id != "" {
			return id, true
		}
		if opaque, ok := set.fileLegacy[id]; ok && opaque != "" {
			return opaque, true
		}
		return "", false
	}
	entry, ok := set.managed[selector]
	if !ok || !entry.record.Enabled {
		return "", false
	}
	return managedKey(entry.record.ID, entry.record.Revision), true
}

// validate checks stable IDs without handling or returning destination
// URLs. Paused and locked managed destinations are accepted. A selector
// that is not in the set, such as another tenant's destination, is refused
// with the same error as an unknown one.
func (set destinationSet) validate(selection []string) error {
	seen := make(map[string]struct{}, len(selection))
	for _, selector := range selection {
		selector = strings.TrimSpace(selector)
		if selector == "" {
			return fmt.Errorf("%w: notification destination ID cannot be empty", ErrInvalidDestinationSelection)
		}
		if _, exists := seen[selector]; exists {
			continue
		}
		seen[selector] = struct{}{}
		if !set.selectorExists(selector) {
			return fmt.Errorf("%w: notification destination %q was not found", ErrInvalidDestinationSelection, selector)
		}
	}
	return nil
}

// canonical prepares a saved routing selection for display; see
// TenantNotifier.CanonicalSelection.
func (set destinationSet) canonical(selection []string) (canonical, missing []string) {
	if selection == nil {
		return nil, nil
	}
	canonical = make([]string, 0, len(selection))
	seen := make(map[string]struct{}, len(selection))
	for _, selector := range selection {
		selector = strings.TrimSpace(selector)
		if selector == "" {
			continue
		}
		if id, ok := strings.CutPrefix(selector, "file:"); ok {
			if _, current := set.fileURLs[id]; !current {
				if opaque := set.fileLegacy[id]; opaque != "" {
					selector = "file:" + opaque
				}
			}
		}
		if _, duplicate := seen[selector]; duplicate {
			continue
		}
		seen[selector] = struct{}{}
		canonical = append(canonical, selector)
		if !set.selectorExists(selector) {
			missing = append(missing, selector)
		}
	}
	sort.Strings(canonical)
	sort.Strings(missing)
	return canonical, missing
}

// testTargets returns one URL per enabled, usable destination and the
// enabled managed destinations that are locked. It deliberately reads
// fileURLs rather than a delivery snapshot: the delivery snapshot also
// carries the legacy digest alias of each deployment URL, which exists only
// to route outbox rows created before opaque IDs and must not add a second
// test message. URLs are not merged, so a managed destination that shares a
// deployment URL is still tested.
func (set destinationSet) testTargets() (urls []string, locked []managedDestination) {
	urls = make([]string, 0, len(set.fileURLs)+len(set.managed))
	for _, raw := range set.fileURLs {
		urls = append(urls, raw)
	}
	for _, entry := range set.managed {
		if !entry.record.Enabled {
			continue
		}
		if entry.locked {
			locked = append(locked, entry)
			continue
		}
		urls = append(urls, entry.url)
	}
	sort.Strings(urls)
	sort.Slice(locked, func(i, j int) bool { return locked[i].record.ID < locked[j].record.ID })
	return urls, locked
}

// testDestination sends a test message to one managed destination of the
// set. A destination outside the set is store.ErrNotFound.
func (set destinationSet) testDestination(ctx context.Context, id string) error {
	entry, ok := set.managed[id]
	if !ok {
		return store.ErrNotFound
	}
	if entry.locked {
		return ErrManagedNotificationLocked
	}
	return safeSendContext(ctx, entry.url, "EdgeWatch notification test")
}

// TenantNotifier is the notifier as one tenant sees it: the tenant's own
// web-managed destinations and, for the default tenant, the deployment
// destinations from config.yaml. Web handlers use it with the request's
// tenant store. Another tenant's destinations and the platform's are not
// found, exactly as unknown ones: they cannot be read, changed, tested,
// selected, or reached by a nil selection.
//
// A TenantNotifier reads the tenant's destinations on first use and answers
// later reads from that snapshot until it changes a destination, so take a
// new one for each request. It is not safe for concurrent use.
type TenantNotifier struct {
	n      *Notifier
	ts     *store.TenantStore
	set    destinationSet
	loaded bool
}

// Tenant returns the notifier as the tenant of ts sees it. A store without
// a valid tenant makes every method fail with store.ErrNoTenantScope.
func (n *Notifier) Tenant(ts *store.TenantStore) *TenantNotifier {
	return &TenantNotifier{n: n, ts: ts}
}

// destinations returns the tenant's destinations, reading them on first
// use.
func (tn *TenantNotifier) destinations(ctx context.Context) (destinationSet, error) {
	if tn.loaded {
		return tn.set, nil
	}
	set, err := tn.n.tenantSet(ctx, tn.ts)
	if err != nil {
		return destinationSet{}, err
	}
	tn.set, tn.loaded = set, true
	return set, nil
}

// Destinations returns the redacted metadata and delivery health of the
// tenant's destinations.
func (tn *TenantNotifier) Destinations(ctx context.Context) ([]DestinationView, error) {
	set, err := tn.destinations(ctx)
	if err != nil {
		return nil, err
	}
	var health map[string]store.DeliveryHealth
	if current, err := tn.ts.ListDeliveryHealth(ctx); err == nil {
		health = current
	}
	return finishViews(set.views(), health), nil
}

// Destination returns one of the tenant's managed destinations. Another
// tenant's destination is store.ErrNotFound, as an unknown one is.
func (tn *TenantNotifier) Destination(ctx context.Context, id string) (DestinationView, error) {
	set, err := tn.destinations(ctx)
	if err != nil {
		return DestinationView{}, err
	}
	entry, ok := set.managed[id]
	if !ok {
		return DestinationView{}, fmt.Errorf("%w: notification %s", store.ErrNotFound, id)
	}
	view := viewFromManaged(entry)
	if health, err := tn.ts.ListDeliveryHealth(ctx); err == nil {
		applyDeliveryHealth(&view, health["managed:"+id])
	}
	return view, nil
}

// Status returns the tenant's destination counts, key state, and delivery
// totals.
func (tn *TenantNotifier) Status(ctx context.Context) (map[string]any, error) {
	set, err := tn.destinations(ctx)
	if err != nil {
		return nil, err
	}
	return tn.n.completeStatus(ctx, set, tn.ts), nil
}

// LegacySelection returns the selectors of the tenant's destinations that
// the legacy nil selection follows. It is never nil without an error.
func (tn *TenantNotifier) LegacySelection(ctx context.Context) ([]string, error) {
	set, err := tn.destinations(ctx)
	if err != nil {
		return nil, err
	}
	return set.legacySelection(), nil
}

// ValidateDestinationSelection checks a job or update routing selection
// against the tenant's destinations. Another tenant's destination ID is
// refused with the same ErrInvalidDestinationSelection as an unknown one.
// A nil selection is valid.
func (tn *TenantNotifier) ValidateDestinationSelection(ctx context.Context, selection []string) error {
	if selection == nil {
		return nil
	}
	set, err := tn.destinations(ctx)
	if err != nil {
		return err
	}
	return set.validate(selection)
}

// CanonicalSelection prepares a saved routing selection for display against
// the tenant's destinations. A legacy deployment digest is replaced by the
// opaque ID of the same destination, so the console can match it against
// the destination list without seeing the digest. Selectors that no longer
// identify a destination of the tenant are kept in the selection and also
// returned in missing. That happens when a deployment URL changes, because
// the changed URL is a new destination, and for a selector of another
// tenant's destination, as for a deleted one. Paused and locked managed
// destinations still exist and are never reported missing. The result never
// contains destination URLs.
func (tn *TenantNotifier) CanonicalSelection(ctx context.Context, selection []string) (canonical, missing []string, err error) {
	set, err := tn.destinations(ctx)
	if err != nil {
		return nil, nil, err
	}
	canonical, missing = set.canonical(selection)
	return canonical, missing, nil
}

// QueueDestinationsForJob resolves the queue keys of an alert for a job of
// the tenant. A nil selection sends to every enabled destination of the
// tenant, never to another tenant's; an explicit empty selection disables
// delivery.
func (tn *TenantNotifier) QueueDestinationsForJob(ctx context.Context, job config.Job) ([]string, error) {
	return tn.QueueDestinationsForSelection(ctx, job.NotificationDestinations)
}

// QueueDestinationsForSelection resolves a selection, such as the tenant's
// update routing, to queue keys of the tenant's destinations.
func (tn *TenantNotifier) QueueDestinationsForSelection(ctx context.Context, selection []string) ([]string, error) {
	set, err := tn.destinations(ctx)
	if err != nil {
		return nil, err
	}
	return set.queue(selection), nil
}

// TestDestination sends a test message to one of the tenant's managed
// destinations. Another tenant's destination is store.ErrNotFound, and
// nothing is sent.
func (tn *TenantNotifier) TestDestination(ctx context.Context, id string) error {
	set, err := tn.destinations(ctx)
	if err != nil {
		return err
	}
	return set.testDestination(ctx, id)
}

// TestSummary sends one test message to each enabled destination of the
// tenant and reports the counts, as testSet describes. It reads the
// tenant's destinations with the current key, so an operator restoring an
// external key can verify it without restarting the daemon.
func (tn *TenantNotifier) TestSummary(ctx context.Context) (TestSummary, error) {
	set, err := tn.destinations(ctx)
	if err != nil {
		return TestSummary{}, err
	}
	return testSet(ctx, set)
}

// CreateManagedWithAudit creates a destination in the tenant. The encrypted
// URL write and its redacted audit record share one store transaction.
func (tn *TenantNotifier) CreateManagedWithAudit(ctx context.Context, name, rawURL string, enabled bool, audit store.AuditEntry) (DestinationView, error) {
	return tn.createManaged(ctx, name, rawURL, enabled, &audit)
}

func (tn *TenantNotifier) createManaged(ctx context.Context, name, rawURL string, enabled bool, audit *store.AuditEntry) (DestinationView, error) {
	name = strings.TrimSpace(name)
	if err := validateName(name); err != nil {
		return DestinationView{}, err
	}
	provider, err := validateManagedURL(rawURL)
	if err != nil {
		return DestinationView{}, err
	}
	// Snapshot the tenant's destinations that exist before this endpoint is
	// inserted. The tenant's jobs with no saved routing selection are frozen
	// to this snapshot transactionally, so the newly created endpoint
	// remains opt-in.
	existing, err := tn.n.tenantSet(ctx, tn.ts)
	if err != nil {
		return DestinationView{}, err
	}
	legacySelection := existing.legacySelection()
	key, err := tn.n.ensureKey(ctx)
	if err != nil {
		return DestinationView{}, err
	}
	id := uuid.NewString()
	nonce, ciphertext, err := sealURL(key, id, strings.TrimSpace(rawURL))
	if err != nil {
		return DestinationView{}, err
	}
	if audit == nil {
		_, err = tn.ts.CreateManagedNotificationWithLegacySelection(ctx, id, name, provider, ciphertext, nonce, enabled, legacySelection)
	} else {
		_, err = tn.ts.CreateManagedNotificationWithLegacySelectionAndAudit(ctx, id, name, provider, ciphertext, nonce, enabled, legacySelection, *audit)
	}
	if err != nil {
		return DestinationView{}, err
	}
	tn.loaded = false
	if err := tn.n.Reload(ctx); err != nil {
		return DestinationView{}, err
	}
	return tn.n.view(id), nil
}

// UpdateManagedWithAudit updates one of the tenant's destinations and
// records a redacted security event. Another tenant's destination is
// store.ErrNotFound, and nothing changes.
func (tn *TenantNotifier) UpdateManagedWithAudit(ctx context.Context, id string, expectedRevision int64, name string, rawURL *string, enabled *bool, audit store.AuditEntry) (DestinationView, error) {
	return tn.updateManaged(ctx, id, expectedRevision, name, rawURL, enabled, &audit)
}

func (tn *TenantNotifier) updateManaged(ctx context.Context, id string, expectedRevision int64, name string, rawURL *string, enabled *bool, audit *store.AuditEntry) (DestinationView, error) {
	n := tn.n
	name = strings.TrimSpace(name)
	if err := validateName(name); err != nil {
		return DestinationView{}, err
	}
	record, err := tn.ts.GetManagedNotification(ctx, id)
	if err != nil {
		return DestinationView{}, err
	}
	// A locked destination can be renamed or disabled while its key is
	// unavailable, but enabling it (or replacing its URL) must prove that the
	// encryption key is usable. This keeps the database metadata from claiming
	// an active destination that the notifier cannot safely decrypt.
	if rawURL != nil || (enabled != nil && *enabled) {
		if _, keyErr := n.ensureKey(ctx); keyErr != nil {
			return DestinationView{}, keyErr
		}
		if rawURL == nil {
			// Open the stored credentials with the key that was just checked,
			// so a restored key unlocks the destination without a reload.
			opened, _ := n.openManaged([]store.ManagedNotification{record})
			if opened[id].locked {
				return DestinationView{}, ErrManagedNotificationLocked
			}
		}
	}
	provider, ciphertext, nonce := record.Provider, record.Ciphertext, record.Nonce
	if rawURL != nil {
		provider, err = validateManagedURL(*rawURL)
		if err != nil {
			return DestinationView{}, err
		}
		key, keyErr := n.ensureKey(ctx)
		if keyErr != nil {
			return DestinationView{}, keyErr
		}
		nonce, ciphertext, err = sealURL(key, id, strings.TrimSpace(*rawURL))
		if err != nil {
			return DestinationView{}, err
		}
	}
	nextEnabled := record.Enabled
	if enabled != nil {
		nextEnabled = *enabled
	}
	var updated store.ManagedNotification
	if audit == nil {
		updated, err = tn.ts.UpdateManagedNotification(ctx, id, expectedRevision, name, provider, ciphertext, nonce, nextEnabled)
	} else {
		updated, err = tn.ts.UpdateManagedNotificationWithAudit(ctx, id, expectedRevision, name, provider, ciphertext, nonce, nextEnabled, *audit)
	}
	if err != nil {
		return DestinationView{}, err
	}
	tn.loaded = false
	if err := n.Reload(ctx); err != nil {
		return DestinationView{}, err
	}
	return n.view(updated.ID), nil
}

// DeleteManagedWithAudit removes one of the tenant's destinations and
// records the action in the same transaction. The destination is also
// removed from the routing of the tenant's jobs and from the tenant's update
// routing; the returned IDs identify the jobs whose routing changed. Another
// tenant's destination is store.ErrNotFound, and nothing changes.
func (tn *TenantNotifier) DeleteManagedWithAudit(ctx context.Context, id string, expectedRevision int64, audit store.AuditEntry) ([]string, error) {
	changedJobs, err := tn.ts.DeleteManagedNotificationWithAudit(ctx, id, expectedRevision, audit)
	if err != nil {
		return nil, err
	}
	tn.loaded = false
	return changedJobs, tn.n.Reload(ctx)
}
