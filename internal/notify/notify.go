package notify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/containrrr/shoutrrr"
	"github.com/containrrr/shoutrrr/pkg/types"
	"github.com/crypt0rr/edgewatch/internal/engine"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/google/uuid"
)

var ErrManagedNotificationLocked = errors.New("managed notification is locked")

// ErrInvalidDestinationSelection reports a routing selection that names a
// destination outside the caller's own. It is the store's error, so a
// selection that the store refuses in the transaction of a routing write is
// handled as one that this package refuses first.
var ErrInvalidDestinationSelection = store.ErrInvalidDestinationSelection

// ErrNotificationSendIndeterminate means the provider did not report an
// outcome before cancellation. The outbox claim is deferred for a full lease
// rather than immediately retried, preventing a duplicate when the provider
// accepted the request just as the daemon stopped waiting.
var ErrNotificationSendIndeterminate = store.ErrDeliveryIndeterminate

// ErrNotificationProviderTimeout means the provider did not answer within
// the provider timeout. It is also ErrNotificationSendIndeterminate, as the
// provider may have accepted the message, and a delivery retries it as a
// provider attempt no sooner than a claim lease later.
var ErrNotificationProviderTimeout = store.ErrDeliveryProviderTimeout

// ErrDeliveryResultNotRecorded means a delivery was sent but its result
// could not be recorded, so the delivery may be sent again once its claim
// expires or the daemon restarts.
var ErrDeliveryResultNotRecorded = errors.New("notification was sent but its delivery could not be recorded")

const (
	notificationWorkers   = 4
	notificationBatchSize = 16
	// A pass is deliberately bounded so a provider outage cannot monopolize
	// the daemon worker. The next wake/tick drains any remaining due rows.
	notificationMaxBatches = 4
	// Shoutrrr sends are bounded by the provider's 15-second timeout. If the
	// caller is canceled first, wait briefly for a definitive result before
	// treating the delivery as indeterminate and deferring it.
	notificationSendCancellationGrace = 2 * time.Second
	// A send that the caller canceled is deferred, as its outcome is
	// indeterminate. Match the store's claim lease so an uncertain provider
	// outcome cannot be retried while the original request may still
	// complete.
	notificationIndeterminateDelay = 30 * time.Minute
	// lateAlertAge is how old an alert is when its message starts to name
	// the time it was raised, as after a provider outage or a redelivery.
	lateAlertAge = 10 * time.Minute
)

// Kept as variables so deterministic provider-timeout tests can use a short
// bound without waiting for the production timeout. The provider timeout
// bounds a send in the notification child, which reports a provider that did
// not answer by then. The caller's hard bound is longer by the process
// margin, which covers the child's start and its sandbox, so the child's own
// timeout fires first; the bound still ends a child that ignores it.
var (
	notificationProviderTimeout = 15 * time.Second
	notificationProcessMargin   = 5 * time.Second
)

// notificationSendBound is the caller's hard bound on one send.
func notificationSendBound() time.Duration {
	return notificationProviderTimeout + notificationProcessMargin
}

// errProviderTimeout is the error of a provider that did not answer within
// the provider timeout.
var errProviderTimeout = errors.New("the notification provider did not answer in time")

// providerTimeoutFailure is the redacted failure of a provider that did not
// answer in time.
func providerTimeoutFailure() error {
	return &store.DeliveryFailure{Err: store.ErrDeliveryProviderTimeout, Class: store.DeliveryClassTimeout}
}

// Kept as variables so the result-write tests can hold the writer briefly.
// A result write that fails, for example while another transaction holds the
// single writer connection for longer than deliveryResultTimeout, is
// retried with a doubling delay for up to deliveryResultRetryWindow.
var (
	deliveryResultTimeout     = 5 * time.Second
	deliveryResultRetryDelay  = 250 * time.Millisecond
	deliveryResultRetryWindow = time.Minute
)

// DestinationView is a destination's redacted metadata. A deployment
// destination from config.yaml has no stored times, so its JSON leaves
// created_at and updated_at out.
type DestinationView struct {
	ID                   string    `json:"id"`
	Name                 string    `json:"name"`
	Provider             string    `json:"provider"`
	Source               string    `json:"source"`
	Enabled              bool      `json:"enabled"`
	Locked               bool      `json:"locked"`
	ReadOnly             bool      `json:"read_only"`
	Revision             int64     `json:"revision,omitempty"`
	CreatedAt            time.Time `json:"created_at,omitzero"`
	UpdatedAt            time.Time `json:"updated_at,omitzero"`
	ErrorCode            string    `json:"error_code,omitempty"`
	Pending              int       `json:"pending,omitempty"`
	Retrying             int       `json:"retrying,omitempty"`
	Deferrals            int       `json:"deferrals,omitempty"`
	TerminalFailures     int       `json:"terminal_failures,omitempty"`
	LastSuccessAt        string    `json:"last_success_at,omitempty"`
	LastFailureAt        string    `json:"last_failure_at,omitempty"`
	LastTerminalAt       string    `json:"last_terminal_at,omitempty"`
	LastErrorCode        string    `json:"last_error_code,omitempty"`
	LastErrorFingerprint string    `json:"last_error_fingerprint,omitempty"`
}

type managedDestination struct {
	record store.ManagedNotification
	url    string
	locked bool
	code   string
}

// Notifier owns the effective destination set. File-managed URLs are loaded
// from deployment configuration until the daemon imports them, while
// web-managed URLs are decrypted from SQLite and can be reloaded without
// restarting the daemon.
type Notifier struct {
	Store *store.Store

	mu            sync.RWMutex
	reloadMu      sync.Mutex
	drainMu       sync.Mutex
	fileURLs      map[string]string
	fileLegacy    map[string]string // legacy digest -> opaque selector
	managed       map[string]managedDestination
	keyPath       string
	keyErr        error
	autoCreateKey bool
	// reloads numbers each full Reload before it reads the destinations, and
	// installed is the newest full snapshot number. Targeted delivery refreshes
	// are serialized with full snapshots by reloadMu and may update one row.
	// installed is guarded by mu.
	reloads   atomic.Uint64
	installed uint64
	// policy is the address policy of the destinations that units own; see
	// SetTargetExclusions.
	policy atomic.Pointer[destinationPolicy]
}

func New(s *store.Store, urls []string) (*Notifier, error) {
	keyPath := ""
	if s != nil {
		// Use the normalized database file, not the DSN: a file: URI in
		// s.Path would otherwise place the key under the working directory.
		keyPath = keyPathBeside(s.FilePath())
	}
	return newWithKeyFile(s, urls, keyPath, true)
}

func NewWithKeyFile(s *store.Store, urls []string, keyPath string) (*Notifier, error) {
	return newWithKeyFile(s, urls, keyPath, false)
}

func newWithKeyFile(s *store.Store, urls []string, keyPath string, autoCreateKey bool) (*Notifier, error) {
	n := &Notifier{Store: s, fileURLs: map[string]string{}, fileLegacy: map[string]string{}, managed: map[string]managedDestination{}, keyPath: keyPath, autoCreateKey: autoCreateKey}
	legacyURLs := make(map[string]string, len(urls))
	for index, raw := range urls {
		if _, err := shoutrrr.CreateSender(raw); err != nil {
			// Name the position only: a digest of the URL would let a reader
			// of the log confirm a guessed URL.
			return nil, fmt.Errorf("invalid Shoutrrr destination: configured notification URL %d of %d", index+1, len(urls))
		}
		legacyURLs[hashURL(raw)] = raw
	}
	opaqueIDs := map[string]string{}
	if s != nil {
		// A URL that the daemon imported as a web-managed destination is no
		// longer a deployment destination, even while config.yaml still lists
		// it. Before the import, every configured URL is delivered as before.
		imported, err := s.System().ImportedDeploymentNotifications(context.Background(), sortedKeys(legacyURLs))
		if err != nil {
			return nil, fmt.Errorf("load imported notification URLs: %w", err)
		}
		for digest := range imported {
			delete(legacyURLs, digest)
		}
		opaqueIDs, err = s.System().EnsureDeploymentNotificationIDs(context.Background(), sortedKeys(legacyURLs))
		if err != nil {
			return nil, fmt.Errorf("persist deployment notification IDs: %w", err)
		}
	}
	for legacy, raw := range legacyURLs {
		opaque := opaqueIDs[legacy]
		if opaque == "" {
			// Library-only notifier instances have no durable store. Preserve
			// their historical selector shape while the appliance path above
			// always uses persisted UUIDs.
			opaque = legacy
		}
		n.fileURLs[opaque] = raw
		n.fileLegacy[legacy] = opaque
	}
	if err := n.Reload(context.Background()); err != nil {
		return nil, err
	}
	return n, nil
}

func sortedKeys(values map[string]string) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func hashURL(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}

func managedKey(id string, revision int64) string {
	return fmt.Sprintf("managed:%s:%d", id, revision)
}

func providerForURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(parsed.Scheme)
}

func validateManagedURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("notification URL is required")
	}
	if _, err := shoutrrr.CreateSender(raw); err != nil {
		return "", errors.New("notification URL is not a valid Shoutrrr destination")
	}
	provider := providerForURL(raw)
	if provider == "" {
		return "", errors.New("notification URL must include a provider scheme")
	}
	return provider, nil
}

// Reload refreshes managed metadata and decrypts destinations with the
// current key. A missing/invalid key locks managed destinations but does not
// stop scans or file-managed notifications. It reads the destinations of
// every tenant and of the platform, because the delivery worker delivers
// the alerts of all of them; each method that answers for a tenant uses only
// that tenant's destinations.
//
// Concurrent reloads may finish in any order, but the cache never goes back
// to an older snapshot: see install. When Reload returns, the cache holds
// every change that was committed before Reload was called.
func (n *Notifier) Reload(ctx context.Context) error {
	n.reloadMu.Lock()
	defer n.reloadMu.Unlock()
	if n.Store == nil {
		// Library-only notifier instances have no managed destinations to
		// reload. Keep the file-backed destinations initialized by the
		// constructor and avoid dereferencing an absent durable store.
		n.mu.Lock()
		n.managed = map[string]managedDestination{}
		n.mu.Unlock()
		return nil
	}
	generation := n.reloads.Add(1)
	records, err := n.Store.System().ListManagedNotifications(ctx)
	if err != nil {
		return err
	}
	managed, keyErr := n.openManaged(records)
	n.install(generation, managed, keyErr)
	return nil
}

// refreshManagedDestination reloads one destination immediately before a
// claimed delivery is sent. It preserves the credential/key-change safety of
// Reload while making the read and decryption cost independent of the number
// of other destinations and tenants.
func (n *Notifier) refreshManagedDestination(ctx context.Context, id string) error {
	if n.Store == nil || id == "" {
		return nil
	}
	n.reloadMu.Lock()
	defer n.reloadMu.Unlock()
	record, err := n.Store.System().GetManagedNotification(ctx, id)
	if errors.Is(err, store.ErrNotFound) {
		n.mu.Lock()
		delete(n.managed, id)
		n.mu.Unlock()
		return nil
	}
	if err != nil {
		return err
	}
	managed, keyErr := n.openManaged([]store.ManagedNotification{record})
	n.mu.Lock()
	n.managed[id] = managed[id]
	n.keyErr = keyErr
	n.mu.Unlock()
	return nil
}

// install puts the snapshot that the reload numbered generation read in the
// cache, unless the cache already holds the snapshot of a reload numbered
// later, and reports whether it did. A reload is numbered before it reads,
// so a reload numbered later started reading after this one was numbered
// and read every change committed before that: installing this snapshot
// over it could only take the cache back to older destinations, such as a
// URL that a replacement has retired.
func (n *Notifier) install(generation uint64, managed map[string]managedDestination, keyErr error) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	if generation <= n.installed {
		return false
	}
	n.managed, n.keyErr, n.installed = managed, keyErr, generation
	return true
}

// openManaged decrypts the records with the current key. A missing or
// invalid key, or a record that the key cannot open, locks the destination
// instead of failing; the key error is returned for the status view.
func (n *Notifier) openManaged(records []store.ManagedNotification) (map[string]managedDestination, error) {
	var key []byte
	var keyErr error
	if len(records) > 0 {
		key, keyErr = loadKey(n.keyPath)
	}
	managed := make(map[string]managedDestination, len(records))
	for _, record := range records {
		entry := managedDestination{record: record}
		if keyErr != nil {
			entry.locked = true
			entry.code = keyErrorCode(keyErr)
		} else {
			var err error
			entry.url, err = openURL(key, record.ID, record.Nonce, record.Ciphertext)
			if err != nil {
				entry.locked = true
				entry.code = "decrypt_failed"
			} else if _, validateErr := validateManagedURL(entry.url); validateErr != nil {
				entry.locked = true
				entry.code = "invalid_destination"
			}
		}
		managed[record.ID] = entry
	}
	return managed, keyErr
}

func keyErrorCode(err error) string {
	switch {
	case errors.Is(err, ErrKeyUnavailable):
		return "key_unavailable"
	case errors.Is(err, ErrKeyPermissions):
		return "key_permissions"
	default:
		return "key_invalid"
	}
}

func (n *Notifier) ensureKey(ctx context.Context) ([]byte, error) {
	// Re-read the file for every credential mutation. This detects an
	// administrator restoring a key after a lock, and prevents a process that
	// survived an external key replacement from encrypting new data with a
	// stale in-memory key.
	key, err := loadKey(n.keyPath)
	if errors.Is(err, ErrKeyUnavailable) {
		if !n.autoCreateKey {
			return nil, ErrKeyUnavailable
		}
		// A key may be generated lazily for the very first managed
		// destination. Once ciphertext exists, however, a missing key must
		// remain a hard lock: silently replacing it would make every existing
		// credential unrecoverable and violate the backup/restore contract.
		records, listErr := n.Store.System().ListManagedNotifications(ctx)
		if listErr != nil {
			return nil, listErr
		}
		if len(records) > 0 {
			return nil, ErrKeyUnavailable
		}
		key, err = createKey(n.keyPath)
		if errors.Is(err, os.ErrExist) {
			key, err = loadKey(n.keyPath)
		}
	}
	if errors.Is(err, ErrKeyInvalid) && n.autoCreateKey {
		// Recover the only failure mode that can be caused by an interrupted
		// first-start creation. Once encrypted destinations exist, even an
		// empty invalid key must remain a hard lock: replacing it would split
		// the key used by the existing ciphertext from the newly generated key.
		records, listErr := n.Store.System().ListManagedNotifications(ctx)
		if listErr != nil {
			return nil, listErr
		}
		if len(records) > 0 {
			return nil, ErrKeyInvalid
		}
		if removeErr := removeInterruptedKey(n.keyPath, 0); removeErr == nil {
			key, err = createKey(n.keyPath)
			if errors.Is(err, os.ErrExist) {
				key, err = loadKey(n.keyPath)
			}
		}
	}
	if err != nil {
		return nil, err
	}
	n.mu.Lock()
	n.keyErr = nil
	n.mu.Unlock()
	return key, nil
}

func validateName(name string) error {
	if name == "" {
		return errors.New("notification name is required")
	}
	if len([]rune(name)) > 100 {
		return errors.New("notification name must be at most 100 characters")
	}
	return nil
}

func (n *Notifier) view(id string) DestinationView {
	n.mu.RLock()
	defer n.mu.RUnlock()
	entry, ok := n.managed[id]
	if !ok {
		return DestinationView{}
	}
	return viewFromManaged(entry)
}

func viewFromManaged(entry managedDestination) DestinationView {
	return viewFromRecord(entry.record, entry.locked, entry.code)
}

func viewFromRecord(record store.ManagedNotification, locked bool, code string) DestinationView {
	return DestinationView{ID: record.ID, Name: record.Name, Provider: record.Provider, Source: "web", Enabled: record.Enabled, Locked: locked, ReadOnly: false, Revision: record.Revision, CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt, ErrorCode: code}
}

func applyDeliveryHealth(view *DestinationView, health store.DeliveryHealth) {
	if view == nil || health.DestinationIdentity == "" {
		return
	}
	view.Pending = health.Pending
	view.Retrying = health.Retrying
	view.Deferrals = health.Deferrals
	view.TerminalFailures = health.TerminalFailures
	if !health.LastSuccessAt.IsZero() {
		view.LastSuccessAt = health.LastSuccessAt.UTC().Format(time.RFC3339Nano)
	}
	if !health.LastFailureAt.IsZero() {
		view.LastFailureAt = health.LastFailureAt.UTC().Format(time.RFC3339Nano)
	}
	if !health.LastTerminalAt.IsZero() {
		view.LastTerminalAt = health.LastTerminalAt.UTC().Format(time.RFC3339Nano)
	}
	view.LastErrorCode = health.LastErrorCode
	view.LastErrorFingerprint = health.LastErrorFingerprint
}

func (n *Notifier) destinationSnapshot() map[string]string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	out := make(map[string]string, len(n.fileURLs)+len(n.managed))
	for id, raw := range n.fileURLs {
		out[id] = raw
	}
	for legacy, opaque := range n.fileLegacy {
		if raw, ok := n.fileURLs[opaque]; ok {
			out[legacy] = raw // compatibility for outbox rows created before migration
		}
	}
	for id, entry := range n.managed {
		if entry.record.Enabled && !entry.locked {
			out[managedKey(id, entry.record.Revision)] = entry.url
		}
	}
	return out
}

// managedDelivery is what resolveManagedDelivery made of the managed
// selector of a claimed delivery.
type managedDelivery int

const (
	// managedMissing: the selector names no destination.
	managedMissing managedDelivery = iota
	// managedReplaced: the destination's credentials changed after the
	// alert was queued, so the alert must never be sent with them.
	managedReplaced
	// managedStale: the cached destination is older than the revision the
	// alert was queued for, so its URL may be one that was since replaced.
	managedStale
	// managedPaused: the destination is paused.
	managedPaused
	// managedDeferred: the destination is locked.
	managedDeferred
	// managedReady: the delivery can be sent to the resolved URL.
	managedReady
)

// resolveManagedDelivery resolves a queued managed selector by its stable
// destination ID rather than requiring the revision embedded in the outbox
// row to still be current. Metadata-only edits intentionally advance that
// revision while preserving queued alerts; an in-flight delivery may still
// carry the previous selector when the edit commits. Returning the current
// URL here lets that delivery complete with the current credentials. A
// paused destination is managedPaused, so its alert is held without a
// failure, and a locked one managedDeferred, the normal deferral path.
//
// A credential change advances the credential revision too, and an alert
// queued before it was queued for the old credentials: a selector whose
// revision is older than the credential revision is managedReplaced, and is
// never resolved to the replacement URL. The URL and the credential revision
// come from the same record, so a concurrent reload cannot pair a new URL
// with an old credential revision.
//
// An alert is queued for the destination's revision at that time, which
// every later revision only exceeds. A selector whose revision is newer than
// the cached record was therefore resolved against a cache older than the
// alert, whose URL may be one that a replacement has retired: it is
// managedStale, and its cached URL is never returned.
func (n *Notifier) resolveManagedDelivery(selector string) (string, managedDelivery) {
	parts := strings.Split(selector, ":")
	if len(parts) < 3 || parts[0] != "managed" || parts[1] == "" {
		return "", managedMissing
	}
	n.mu.RLock()
	entry, ok := n.managed[parts[1]]
	n.mu.RUnlock()
	if !ok {
		return "", managedMissing
	}
	revision, err := strconv.ParseInt(parts[2], 10, 64)
	switch {
	case err != nil || revision < entry.record.CredentialRevision:
		return "", managedReplaced
	case revision > entry.record.Revision:
		return "", managedStale
	case !entry.record.Enabled:
		return "", managedPaused
	case entry.locked:
		return "", managedDeferred
	}
	return entry.url, managedReady
}

func (n *Notifier) lockedDestinationKeys() []string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	keys := make([]string, 0)
	for id, entry := range n.managed {
		if entry.record.Enabled && entry.locked {
			keys = append(keys, managedKey(id, entry.record.Revision))
		}
	}
	sort.Strings(keys)
	return keys
}

// pausedDestinationKeys are durable selectors for managed destinations that
// are intentionally disabled. They remain in the outbox so re-enabling a
// destination resumes queued alerts, but the drain must not claim them and
// misclassify a deliberate pause as a missing provider.
func (n *Notifier) pausedDestinationKeys() []string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	keys := make([]string, 0)
	for id, entry := range n.managed {
		if !entry.record.Enabled {
			keys = append(keys, managedKey(id, entry.record.Revision))
		}
	}
	sort.Strings(keys)
	return keys
}

// Queue queues events of config.yaml jobs, which belong to the default
// tenant, to every enabled destination of that tenant.
func (n *Notifier) Queue(ctx context.Context, events []model.Event) error {
	if err := n.Reload(ctx); err != nil {
		return err
	}
	destinations := n.defaultSet().keys()
	for _, event := range events {
		for destination := range destinations {
			if err := n.Store.System().QueueEvent(ctx, destination, event); err != nil {
				return err
			}
		}
	}
	return nil
}

// Drain delivers due notifications. Cancelling ctx stops dispatch and also
// ends in-flight sends after the cancellation grace period, deferring them as
// indeterminate. Use DrainWithin to bound a pass without cutting off sends.
func (n *Notifier) Drain(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	return n.drain(ctx, ctx)
}

// DrainWithin runs one delivery pass that claims and dispatches deliveries for
// at most window. The window bounds only dispatch: a send that has already
// started keeps running under ctx and its own provider timeout, so a slow but
// healthy provider is neither cut off nor charged an indeterminate deferral
// when the window closes. Claimed deliveries that were not dispatched are
// released without consuming a retry budget. Cancelling ctx, for example at
// shutdown, still ends in-flight sends as Drain does.
func (n *Notifier) DrainWithin(ctx context.Context, window time.Duration) error {
	dispatchCtx, cancel := context.WithTimeout(ctx, window)
	defer cancel()
	return n.drain(ctx, dispatchCtx)
}

// drain claims and dispatches deliveries until dispatchCtx ends, and runs each
// dispatched send under sendCtx. dispatchCtx must be sendCtx or derived from it.
func (n *Notifier) drain(sendCtx, dispatchCtx context.Context) error {
	if err := lockContext(dispatchCtx, &n.drainMu); err != nil {
		return err
	}
	defer n.drainMu.Unlock()
	if err := n.Reload(dispatchCtx); err != nil {
		return err
	}
	destinations := n.destinationSnapshot()
	lockedDestinations := n.lockedDestinationKeys()
	pausedDestinations := n.pausedDestinationKeys()
	excludedDestinations := append(append([]string{}, lockedDestinations...), pausedDestinations...)
	if n.Store != nil {
		if err := n.Store.System().WakeLockedDeliveries(dispatchCtx, destinationSnapshotKeys(destinations)); err != nil {
			return err
		}
		if err := n.Store.System().AgeLockedDeliveries(dispatchCtx, lockedDestinations); err != nil {
			return err
		}
	}
	var all []error
	for batch := 0; batch < notificationMaxBatches; batch++ {
		if dispatchCtx.Err() != nil {
			break
		}
		// A bounded pass drains several batches so a burst of events does not
		// wait for multiple 30-second worker ticks. The batch and pass limits
		// keep provider latency from starving scans and schedule reconciliation.
		deliveries, err := n.Store.System().ClaimDueDeliveriesExcluding(dispatchCtx, notificationBatchSize, uuid.NewString(), excludedDestinations)
		if err != nil {
			return errors.Join(append(all, err)...)
		}
		if len(deliveries) == 0 {
			break
		}
		all = append(all, n.deliverBatch(sendCtx, dispatchCtx, deliveries, destinations)...)
		if dispatchCtx.Err() != nil {
			break
		}
	}
	return errors.Join(all...)
}

func destinationSnapshotKeys(destinations map[string]string) []string {
	keys := make([]string, 0, len(destinations))
	for key := range destinations {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// deliverBatch hands deliveries to the workers until dispatchCtx ends and
// runs each send under sendCtx. Deliveries that were not handed to a worker
// are released without consuming a retry budget.
func (n *Notifier) deliverBatch(sendCtx, dispatchCtx context.Context, deliveries []store.Delivery, destinations map[string]string) []error {
	workers := notificationWorkers
	if len(deliveries) < workers {
		workers = len(deliveries)
	}
	if workers == 0 {
		return nil
	}
	jobs := make(chan store.Delivery)
	results := make(chan error, len(deliveries))
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for delivery := range jobs {
				// A panic in notifier/store glue is just as capable of leaking a
				// claim as a provider panic. Convert it into a redacted terminal
				// delivery result so one bad row cannot kill the worker goroutine.
				results <- n.deliverOneSafe(sendCtx, delivery, destinations)
			}
		}()
	}
	var unsent []store.Delivery
	for _, delivery := range deliveries {
		if dispatchCtx.Err() != nil {
			unsent = append(unsent, delivery)
			continue
		}
		select {
		case jobs <- delivery:
		case <-dispatchCtx.Done():
			unsent = append(unsent, delivery)
		}
	}
	close(jobs)
	wg.Wait()
	close(results)
	var all []error
	for err := range results {
		if err != nil && !errors.Is(err, store.ErrDeliveryClaimLost) {
			all = append(all, err)
		}
	}
	for _, delivery := range unsent {
		// Dispatch ended before this delivery reached a worker. Return the
		// claim without consuming either the provider-attempt or deferral budget.
		if err := n.releaseClaimWithoutBudget(sendCtx, delivery, 0); err != nil && !errors.Is(err, store.ErrDeliveryClaimLost) {
			all = append(all, err)
		}
	}
	return all
}

func (n *Notifier) deliverOneSafe(ctx context.Context, delivery store.Delivery, destinations map[string]string) (err error) {
	defer func() {
		if recover() != nil {
			panicErr := store.ErrDeliveryWorkerPanic
			resultCtx, cancel := deliveryResultContext(ctx)
			defer cancel()
			resultErr := n.Store.System().DeliveryResultClaim(resultCtx, delivery.ID, delivery.ClaimToken, panicErr)
			err = errors.Join(panicErr, resultErr)
		}
	}()
	return n.deliverOne(ctx, delivery, destinations)
}

func lockContext(ctx context.Context, mu *sync.Mutex) error {
	for {
		if mu.TryLock() {
			return nil
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func (n *Notifier) deliverOne(ctx context.Context, delivery store.Delivery, destinations map[string]string) error {
	if err := ctx.Err(); err != nil {
		return errors.Join(err, n.releaseClaimWithoutBudget(ctx, delivery, 0))
	}
	// Drain loads a full managed-destination snapshot once per pass. Refresh
	// this one destination immediately before the claim check so a change made
	// during the pass is observed without reloading other tenants' credentials.
	// The transactional claim check then prevents delivery if the destination
	// was replaced or deleted between refresh and send.
	managedDestination := strings.HasPrefix(delivery.Destination, "managed:")
	if managedDestination {
		parts := strings.SplitN(delivery.Destination, ":", 3)
		if len(parts) != 3 || parts[1] == "" {
			return n.releaseClaim(ctx, delivery, store.ErrDeliveryDestinationMissing, time.Minute)
		}
		if reloadErr := n.refreshManagedDestination(ctx, parts[1]); reloadErr != nil {
			deferErr := n.releaseClaim(ctx, delivery, store.ErrDeliveryDestinationLocked, time.Minute)
			return errors.Join(reloadErr, deferErr)
		}
		destinations = n.destinationSnapshot()
	}
	// A pass claims its batch at once, so a delivery may wait for a worker
	// while its destination is replaced or deleted, or its tenant disabled.
	// Check the claim after the reload above: a replacement or deletion that
	// committed before the check discarded the delivery, so it is not sent,
	// and a tenant that is no longer active holds it.
	if err := n.Store.System().CheckDeliveryClaim(ctx, delivery.ID, delivery.ClaimToken); err != nil {
		switch {
		case errors.Is(err, store.ErrDeliveryHeld):
			// Return the delivery without consuming a budget. The claim
			// query skips it until the tenant is enabled again.
			return n.releaseClaimWithoutBudget(ctx, delivery, 0)
		case errors.Is(err, store.ErrDeliveryClaimLost):
			return err
		default:
			return errors.Join(err, n.releaseClaimWithoutBudget(ctx, delivery, 0))
		}
	}
	raw, ok := destinations[delivery.Destination]
	if managedDestination {
		var state managedDelivery
		raw, state = n.resolveManagedDelivery(delivery.Destination)
		if state == managedStale {
			// The cache is older than the alert. Read the destinations
			// again instead of sending with a URL that may have been
			// replaced since.
			if reloadErr := n.refreshManagedDestination(ctx, strings.SplitN(delivery.Destination, ":", 3)[1]); reloadErr != nil {
				return errors.Join(reloadErr, n.releaseClaimWithoutBudget(ctx, delivery, 0))
			}
			raw, state = n.resolveManagedDelivery(delivery.Destination)
		}
		switch state {
		case managedStale, managedPaused:
			// Return the claim without using a retry or deferral budget
			// and without recording a delivery failure. A later pass
			// resolves a stale delivery again; a paused destination's
			// alert is left out of every pass until the destination is
			// enabled again, as a deliberate pause is not a failure.
			return n.releaseClaimWithoutBudget(ctx, delivery, 0)
		case managedDeferred:
			return n.releaseClaim(ctx, delivery, store.ErrDeliveryDestinationLocked, time.Minute)
		case managedMissing, managedReplaced:
			// An alert queued for replaced credentials is closed as one of
			// a deleted destination. The credential change discarded it,
			// so the claim is normally lost by now and nothing is recorded.
			return n.releaseClaim(ctx, delivery, store.ErrDeliveryDestinationMissing, time.Minute)
		}
		ok = state == managedReady
	}
	var sendErr error
	switch {
	case !ok:
		sendErr = store.ErrDeliveryDestinationMissing
	case managedDestination && n.addressChecked(strings.SplitN(delivery.Destination, ":", 3)[1]):
		// A unit's destination is checked again just before the send, so a
		// name whose answer changed since it was saved is not reached.
		sendErr = n.destinationPolicy().check(ctx, raw)
	}
	if ok && sendErr == nil {
		sendErr = safeSendContext(ctx, raw, alertMessage(delivery.Event, time.Now()))
	}
	if errors.Is(sendErr, ErrNotificationSendIndeterminate) && !errors.Is(sendErr, ErrNotificationProviderTimeout) {
		// The provider outcome is unknown after the cancellation grace period.
		// Keep the safety delay and bounded deferral budget for this genuine
		// indeterminate send; unlike a claim cancelled before dispatch, it may
		// already have been accepted by the provider. A provider that did not
		// answer in time is recorded as a provider attempt instead.
		deferErr := n.releaseClaim(ctx, delivery, store.ErrDeliveryIndeterminate, notificationIndeterminateDelay)
		return errors.Join(sendErr, deferErr)
	}
	return errors.Join(sendErr, n.recordResult(ctx, delivery, sendErr))
}

// alertMessage formats the message of an alert. An alert that is delivered
// late, after a provider outage or a redelivery, names when it was raised,
// so its recipients do not take it for a new one.
func alertMessage(event model.Event, now time.Time) string {
	message := engine.FormatEvent(event)
	if !event.CreatedAt.IsZero() && now.Sub(event.CreatedAt) > lateAlertAge {
		message += "\nRaised at " + event.CreatedAt.UTC().Format("2006-01-02 15:04 UTC")
	}
	return message
}

// recordResult records the outcome of a send. The result write gets a fresh
// bound on each try, and a write that fails is retried with a doubling delay
// for up to deliveryResultRetryWindow: a sent alert whose result is not
// recorded keeps its claim and is sent again once the claim lease ends or the
// daemon restarts. The claim token makes a retry idempotent, and a lost
// claim is not retried. A sent alert that still cannot be recorded is
// reported as ErrDeliveryResultNotRecorded.
func (n *Notifier) recordResult(ctx context.Context, delivery store.Delivery, sendErr error) error {
	delay := deliveryResultRetryDelay
	deadline := time.Now().Add(deliveryResultRetryWindow)
	for {
		resultCtx, cancel := deliveryResultContext(ctx)
		err := n.Store.System().DeliveryResultClaim(resultCtx, delivery.ID, delivery.ClaimToken, sendErr)
		cancel()
		if err == nil || errors.Is(err, store.ErrDeliveryClaimLost) {
			return err
		}
		if !time.Now().Add(delay).Before(deadline) {
			if sendErr == nil {
				return fmt.Errorf("%w: %w", ErrDeliveryResultNotRecorded, err)
			}
			return err
		}
		time.Sleep(delay)
		delay = min(2*delay, 5*time.Second)
	}
}

// addressChecked reports whether the address policy applies to the managed
// destination with the given ID: a unit's destination, unless the host
// operator configured its URL in config.yaml and no one has replaced it since.
func (n *Notifier) addressChecked(id string) bool {
	n.mu.RLock()
	defer n.mu.RUnlock()
	entry, ok := n.managed[id]
	return ok && entry.record.TenantID != "" && !entry.record.ConfigImported
}

func (n *Notifier) releaseClaim(ctx context.Context, delivery store.Delivery, reason error, delay time.Duration) error {
	releaseCtx, cancel := deliveryResultContext(ctx)
	defer cancel()
	return n.Store.System().DeferDeliveryWithError(releaseCtx, delivery.ID, delivery.ClaimToken, reason, delay)
}

func (n *Notifier) releaseClaimWithoutBudget(ctx context.Context, delivery store.Delivery, delay time.Duration) error {
	releaseCtx, cancel := deliveryResultContext(ctx)
	defer cancel()
	return n.Store.System().ReleaseDeliveryClaim(releaseCtx, delivery.ID, delivery.ClaimToken, delay)
}

// deliveryResultContext keeps claim cleanup independent of a canceled parent
// while still giving static context checks an explicit propagation path.
func deliveryResultContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithTimeout(context.WithoutCancel(ctx), deliveryResultTimeout)
}

type notificationSendFunc func(context.Context, string, string) error

func send(ctx context.Context, rawURL, message string) error {
	if notificationIsTestBinary() {
		return sendInProcess(rawURL, message)
	}
	return notificationProcessRunner(ctx, rawURL, message)
}

var notificationIsTestBinary = isTestBinary
var notificationProcessRunner notificationSendFunc = runNotificationProcess

// sendInProcess sends with the provider code in this process and returns
// errProviderTimeout when the provider does not answer within the provider
// timeout.
func sendInProcess(rawURL, message string) error {
	sender, err := shoutrrr.CreateSender(rawURL)
	if err != nil {
		return err
	}
	// The router's own timer reports a timeout only as text. It gets longer,
	// so the timer below ends a slow send and reports it as a timeout.
	sender.Timeout = notificationProviderTimeout + time.Second
	result := make(chan error, 1)
	go func() { result <- errors.Join(sender.Send(message, &types.Params{"title": "EdgeWatch"})...) }()
	timer := time.NewTimer(notificationProviderTimeout)
	defer timer.Stop()
	select {
	case err := <-result:
		return err
	case <-timer.C:
		return errProviderTimeout
	}
}

// notificationProviderSend is isolated behind one function so timeout and
// panic paths can be tested without contacting a real notification service.
// Production code always points it at send.
var notificationProviderSend notificationSendFunc = send

// safeSend deliberately strips provider errors before they reach logs, the
// outbox, or the CLI. Shoutrrr providers may echo a destination URL (and its
// credentials) in their error text, so a failure keeps only its category and
// class, which name no destination; the delivery's own selector identifies
// the destination.
func safeSend(rawURL, message string) error {
	return safeSendContext(context.Background(), rawURL, message)
}

func safeSendContext(ctx context.Context, rawURL, message string) error {
	if err := sendContext(ctx, rawURL, message); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrNotificationSendIndeterminate) {
			return err
		}
		return redactedFailure(err)
	}
	return nil
}

// redactedFailure keeps only the category and class of a send failure. The
// notification child reports them through its exit status; a send in this
// process is classified by the type of its error.
func redactedFailure(err error) error {
	var failure *store.DeliveryFailure
	switch {
	case errors.As(err, &failure):
		return &store.DeliveryFailure{Err: failure.Err, Class: failure.Class}
	case errors.Is(err, store.ErrDeliveryProviderPanic):
		return &store.DeliveryFailure{Err: store.ErrDeliveryProviderPanic}
	}
	class := failureClass(err)
	if class == store.DeliveryClassTimeout {
		return providerTimeoutFailure()
	}
	return &store.DeliveryFailure{Err: store.ErrDeliveryProvider, Class: class}
}

// sendContext sends one message under the caller's hard bound. The send does
// not stop when ctx is canceled: the caller then waits up to the
// cancellation grace for the outcome, so a send that is about to finish when
// the daemon stops, or when a console client goes away, still records it,
// and only a send that is still running after the grace is ended and
// reported as indeterminate. A send that runs past the bound is a provider
// timeout.
func sendContext(ctx context.Context, rawURL, message string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	providerCtx, cancelProvider := context.WithTimeout(context.WithoutCancel(ctx), notificationSendBound())
	defer cancelProvider()
	result := make(chan error, 1)
	go func() {
		// Provider implementations are third-party code. A panic must be
		// converted into the same redacted delivery failure path as any other
		// provider error; it must never take down the daemon's delivery worker.
		defer func() {
			if recover() != nil {
				result <- store.ErrDeliveryProviderPanic
			}
		}()
		result <- notificationProviderSend(providerCtx, rawURL, message)
	}()
	select {
	case err := <-result:
		return boundedResult(providerCtx, err)
	case <-ctx.Done():
		timer := time.NewTimer(notificationSendCancellationGrace)
		defer timer.Stop()
		select {
		case err := <-result:
			return boundedResult(providerCtx, err)
		case <-providerCtx.Done():
			return providerTimeoutFailure()
		case <-timer.C:
			// Returning cancels providerCtx, which ends the child.
			return ErrNotificationSendIndeterminate
		}
	case <-providerCtx.Done():
		// The provider has not reported a definitive result within the hard
		// bound. Do not immediately retry: an external provider may already
		// have accepted the request even while its child is being terminated.
		return providerTimeoutFailure()
	}
}

// boundedResult reports a send that its hard bound ended as a provider
// timeout, as the bound's own case does: the result of the ended child may
// arrive first.
func boundedResult(providerCtx context.Context, err error) error {
	if errors.Is(err, ErrNotificationSendIndeterminate) && errors.Is(providerCtx.Err(), context.DeadlineExceeded) {
		return providerTimeoutFailure()
	}
	return err
}

// TestSummary reports the outcome of a global notification test by count
// only; it never contains destination URLs or provider responses.
type TestSummary struct {
	// Tested is the number of enabled, usable destinations the test covered.
	Tested int `json:"tested"`
	// Failed is the number of tested destinations whose test message was not
	// delivered, including any the test deadline stopped before sending.
	Failed int `json:"failed"`
	// Locked is the number of enabled web-managed destinations that could not
	// be tested because their credentials cannot be decrypted.
	Locked int `json:"locked"`
}

// LockedDestinations opens every web-managed destination of every tenant and
// of the platform with the current key, as Reload does, and returns how many
// enabled ones it cannot open. The notification key is one for the whole
// deployment, so a host command that confirms a restored key checks them
// all, although it sends test messages only to one tenant's destinations.
// When any is locked, the error wraps ErrManagedNotificationLocked. It
// reports a count only: no URL, and no destination of another owner by ID.
// Paused destinations are not counted, as a test does not send to them.
func (n *Notifier) LockedDestinations(ctx context.Context) (int, error) {
	if n.Store == nil {
		return 0, nil
	}
	records, err := n.Store.System().ListManagedNotifications(ctx)
	if err != nil {
		return 0, err
	}
	managed, _ := n.openManaged(records)
	locked := 0
	for _, entry := range managed {
		if entry.record.Enabled && entry.locked {
			locked++
		}
	}
	if locked > 0 {
		return locked, fmt.Errorf("%w: the notification key cannot open %d of the deployment's enabled web-managed destinations", ErrManagedNotificationLocked, locked)
	}
	return 0, nil
}

// CheckKey opens every web-managed destination stored in the database of s,
// of every tenant and of the platform, paused or not, with the notification
// key at keyPath, as Reload would, and returns how many destinations there
// are and how many the key cannot open. A missing, unreadable, or invalid
// key locks every destination. It reads the database only, never creates a
// key, and reports counts only, so a restore can check a backup copy against
// the configured key before it replaces the database.
func CheckKey(ctx context.Context, s *store.Store, keyPath string) (destinations, locked int, err error) {
	if s == nil {
		return 0, 0, errors.New("database is not open")
	}
	records, err := s.System().SealedManagedNotifications(ctx)
	if err != nil {
		return 0, 0, err
	}
	managed, _ := (&Notifier{keyPath: keyPath}).openManaged(records)
	for _, entry := range managed {
		if entry.locked {
			locked++
		}
	}
	return len(records), locked, nil
}

// testSet sends one test message to each enabled destination of the set and
// reports the counts. An enabled managed destination that is locked by a
// missing, replaced, or unreadable key fails the test with
// ErrManagedNotificationLocked, so restoring the wrong key is not reported
// as a successful verification. Paused destinations are not tested, and an
// empty set succeeds with nothing tested.
func testSet(ctx context.Context, set destinationSet) (TestSummary, error) {
	targets, locked := set.testTargets()
	summary := TestSummary{Tested: len(targets), Locked: len(locked)}
	all := make([]error, 0, len(locked))
	for _, entry := range locked {
		all = append(all, fmt.Errorf("%w: destination %s (%s)", ErrManagedNotificationLocked, entry.record.ID, entry.code))
	}
	workers := notificationWorkers
	if len(targets) < workers {
		workers = len(targets)
	}
	if workers == 0 {
		return summary, errors.Join(all...)
	}
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	jobs := make(chan testTarget)
	results := make(chan error, len(targets))
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range jobs {
				if target.checked {
					// A unit's destination whose address the policy refuses
					// fails the test without being contacted.
					if err := set.policy.check(testCtx, target.url); err != nil {
						results <- err
						continue
					}
				}
				results <- safeSendContext(testCtx, target.url, "EdgeWatch notification test")
			}
		}()
	}
	for _, target := range targets {
		select {
		case jobs <- target:
		case <-testCtx.Done():
			// A destination that was never reached is a failed test, not a
			// silently skipped one.
			results <- testCtx.Err()
		}
	}
	close(jobs)
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			summary.Failed++
			all = append(all, err)
		}
	}
	return summary, errors.Join(all...)
}
