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
	"strings"
	"sync"
	"time"

	"github.com/containrrr/shoutrrr"
	"github.com/containrrr/shoutrrr/pkg/types"
	"github.com/crypt0rr/edgewatch/internal/engine"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/google/uuid"
)

var ErrManagedNotificationLocked = errors.New("managed notification is locked")

const notificationWorkers = 4

type DestinationView struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Provider  string    `json:"provider"`
	Source    string    `json:"source"`
	Enabled   bool      `json:"enabled"`
	Locked    bool      `json:"locked"`
	ReadOnly  bool      `json:"read_only"`
	Revision  int64     `json:"revision,omitempty"`
	CreatedAt time.Time `json:"created_at,omitempty"`
	UpdatedAt time.Time `json:"updated_at,omitempty"`
	ErrorCode string    `json:"error_code,omitempty"`
}

type managedDestination struct {
	record store.ManagedNotification
	url    string
	locked bool
	code   string
}

// Notifier owns the effective destination set. File-managed URLs are loaded
// from deployment configuration, while web-managed URLs are decrypted from
// SQLite and can be reloaded without restarting the daemon.
type Notifier struct {
	Store *store.Store

	mu            sync.RWMutex
	drainMu       sync.Mutex
	fileURLs      map[string]string
	managed       map[string]managedDestination
	keyPath       string
	key           []byte
	keyErr        error
	autoCreateKey bool
}

func New(s *store.Store, urls []string) (*Notifier, error) {
	keyPath := ""
	if s != nil {
		keyPath = DefaultKeyPath(s.Path)
	}
	return newWithKeyFile(s, urls, keyPath, true)
}

func NewWithKeyFile(s *store.Store, urls []string, keyPath string) (*Notifier, error) {
	return newWithKeyFile(s, urls, keyPath, false)
}

func newWithKeyFile(s *store.Store, urls []string, keyPath string, autoCreateKey bool) (*Notifier, error) {
	n := &Notifier{Store: s, fileURLs: map[string]string{}, managed: map[string]managedDestination{}, keyPath: keyPath, autoCreateKey: autoCreateKey}
	for _, raw := range urls {
		if _, err := shoutrrr.CreateSender(raw); err != nil {
			id := hashURL(raw)
			return nil, fmt.Errorf("invalid Shoutrrr destination %s", id[:12])
		}
		n.fileURLs[hashURL(raw)] = raw
	}
	if err := n.Reload(context.Background()); err != nil {
		return nil, err
	}
	return n, nil
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
// stop scans or file-managed notifications.
func (n *Notifier) Reload(ctx context.Context) error {
	records, err := n.Store.ListManagedNotifications(ctx)
	if err != nil {
		return err
	}
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
	n.mu.Lock()
	n.managed = managed
	n.key = append([]byte(nil), key...)
	n.keyErr = keyErr
	n.mu.Unlock()
	return nil
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
		records, listErr := n.Store.ListManagedNotifications(ctx)
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
	if err != nil {
		return nil, err
	}
	n.mu.Lock()
	n.key = append([]byte(nil), key...)
	n.keyErr = nil
	n.mu.Unlock()
	return key, nil
}

func (n *Notifier) CreateManaged(ctx context.Context, name, rawURL string, enabled bool) (DestinationView, error) {
	name = strings.TrimSpace(name)
	if err := validateName(name); err != nil {
		return DestinationView{}, err
	}
	provider, err := validateManagedURL(rawURL)
	if err != nil {
		return DestinationView{}, err
	}
	key, err := n.ensureKey(ctx)
	if err != nil {
		return DestinationView{}, err
	}
	id := uuid.NewString()
	nonce, ciphertext, err := sealURL(key, id, strings.TrimSpace(rawURL))
	if err != nil {
		return DestinationView{}, err
	}
	if _, err := n.Store.CreateManagedNotification(ctx, id, name, provider, ciphertext, nonce, enabled); err != nil {
		return DestinationView{}, err
	}
	if err := n.Reload(ctx); err != nil {
		return DestinationView{}, err
	}
	return n.view(id), nil
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

func (n *Notifier) UpdateManaged(ctx context.Context, id string, expectedRevision int64, name string, rawURL *string, enabled *bool) (DestinationView, error) {
	name = strings.TrimSpace(name)
	if err := validateName(name); err != nil {
		return DestinationView{}, err
	}
	record, err := n.Store.GetManagedNotification(ctx, id)
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
			n.mu.RLock()
			entry, present := n.managed[id]
			n.mu.RUnlock()
			if present && entry.locked {
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
	updated, err := n.Store.UpdateManagedNotification(ctx, id, expectedRevision, name, provider, ciphertext, nonce, nextEnabled)
	if err != nil {
		return DestinationView{}, err
	}
	if err := n.Reload(ctx); err != nil {
		return DestinationView{}, err
	}
	return n.view(updated.ID), nil
}

func (n *Notifier) DeleteManaged(ctx context.Context, id string, expectedRevision int64) error {
	if err := n.Store.DeleteManagedNotification(ctx, id, expectedRevision); err != nil {
		return err
	}
	return n.Reload(ctx)
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

// Destination returns one managed destination's redacted metadata. Deployment
// destinations intentionally remain collection-only because they have no
// mutable revision and are represented as a read-only aggregate in the UI.
func (n *Notifier) Destination(ctx context.Context, id string) (DestinationView, error) {
	if err := n.Reload(ctx); err != nil {
		return DestinationView{}, err
	}
	n.mu.RLock()
	entry, ok := n.managed[id]
	n.mu.RUnlock()
	if !ok {
		return DestinationView{}, fmt.Errorf("%w: notification %s", store.ErrNotFound, id)
	}
	return viewFromManaged(entry), nil
}

func viewFromManaged(entry managedDestination) DestinationView {
	return viewFromRecord(entry.record, entry.locked, entry.code)
}

func viewFromRecord(record store.ManagedNotification, locked bool, code string) DestinationView {
	return DestinationView{ID: record.ID, Name: record.Name, Provider: record.Provider, Source: "web", Enabled: record.Enabled, Locked: locked, ReadOnly: false, Revision: record.Revision, CreatedAt: record.CreatedAt, UpdatedAt: record.UpdatedAt, ErrorCode: code}
}

func (n *Notifier) Destinations() []DestinationView {
	n.mu.RLock()
	views := make([]DestinationView, 0, len(n.fileURLs)+len(n.managed))
	for id, raw := range n.fileURLs {
		views = append(views, DestinationView{ID: "file:" + id, Name: "Deployment destination", Provider: providerForURL(raw), Source: "deployment", Enabled: true, ReadOnly: true})
	}
	for _, entry := range n.managed {
		views = append(views, viewFromManaged(entry))
	}
	n.mu.RUnlock()
	sort.Slice(views, func(i, j int) bool {
		if views[i].Source != views[j].Source {
			return views[i].Source < views[j].Source
		}
		return strings.ToLower(views[i].Name) < strings.ToLower(views[j].Name)
	})
	return views
}

func (n *Notifier) ActiveCount() int {
	n.mu.RLock()
	defer n.mu.RUnlock()
	count := len(n.fileURLs)
	for _, entry := range n.managed {
		if entry.record.Enabled && !entry.locked {
			count++
		}
	}
	return count
}

func (n *Notifier) Status() map[string]any {
	n.mu.RLock()
	defer n.mu.RUnlock()
	locked := 0
	activeManaged := 0
	for _, entry := range n.managed {
		if entry.locked {
			locked++
		}
		if entry.record.Enabled && !entry.locked {
			activeManaged++
		}
	}
	keyState := "not_required"
	if len(n.managed) > 0 {
		keyState = "ready"
		if n.keyErr != nil {
			keyState = keyErrorCode(n.keyErr)
		} else if locked > 0 {
			keyState = "decrypt_failed"
		}
	}
	return map[string]any{"deployment": len(n.fileURLs), "managed": len(n.managed), "active": len(n.fileURLs) + activeManaged, "locked": locked, "key_state": keyState}
}

func (n *Notifier) destinationSnapshot() map[string]string {
	n.mu.RLock()
	defer n.mu.RUnlock()
	out := make(map[string]string, len(n.fileURLs)+len(n.managed))
	for id, raw := range n.fileURLs {
		out[id] = raw
	}
	for id, entry := range n.managed {
		if entry.record.Enabled && !entry.locked {
			out[managedKey(id, entry.record.Revision)] = entry.url
		}
	}
	return out
}

// destinationKeys returns the destinations that were enabled when an event
// was created. A managed destination may be locked because its encryption key
// is temporarily unavailable; its durable outbox entry must still be created
// so Drain can defer it until the key is restored.
func (n *Notifier) destinationKeys() map[string]struct{} {
	n.mu.RLock()
	defer n.mu.RUnlock()
	out := make(map[string]struct{}, len(n.fileURLs)+len(n.managed))
	for id := range n.fileURLs {
		out[id] = struct{}{}
	}
	for id, entry := range n.managed {
		if entry.record.Enabled {
			out[managedKey(id, entry.record.Revision)] = struct{}{}
		}
	}
	return out
}

// QueueDestinations reloads metadata and returns enabled destination keys for
// an atomic event transition. Keys are opaque hashes or managed revisions.
func (n *Notifier) QueueDestinations(ctx context.Context) ([]string, error) {
	if err := n.Reload(ctx); err != nil {
		return nil, err
	}
	keys := n.destinationKeys()
	out := make([]string, 0, len(keys))
	for key := range keys {
		out = append(out, key)
	}
	sort.Strings(out)
	return out, nil
}

func (n *Notifier) Queue(ctx context.Context, events []model.Event) error {
	if err := n.Reload(ctx); err != nil {
		return err
	}
	destinations := n.destinationKeys()
	for _, event := range events {
		for destination := range destinations {
			if err := n.Store.QueueEvent(ctx, destination, event); err != nil {
				return err
			}
		}
	}
	return nil
}

func (n *Notifier) Drain(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := lockContext(ctx, &n.drainMu); err != nil {
		return err
	}
	defer n.drainMu.Unlock()
	if err := n.Reload(ctx); err != nil {
		return err
	}
	destinations := n.destinationSnapshot()
	// Keep one pass short enough that a provider outage cannot make the daemon
	// heartbeat stale. The application worker will pick up the next batch.
	deliveries, err := n.Store.ClaimDueDeliveries(ctx, 4, uuid.NewString())
	if err != nil {
		return err
	}
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
				results <- n.deliverOne(ctx, delivery, destinations)
			}
		}()
	}
	for _, delivery := range deliveries {
		select {
		case jobs <- delivery:
		case <-ctx.Done():
			// Unsent claims are left for the normal claim lease to expire. This
			// avoids marking them delivered when a caller canceled the pass.
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
	return errors.Join(all...)
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
	if ctx.Err() != nil {
		return ctx.Err()
	}
	// Refresh before each managed send so an update/delete after the batch was
	// claimed cannot use the stale URL from the first snapshot.
	if strings.HasPrefix(delivery.Destination, "managed:") {
		if reloadErr := n.Reload(ctx); reloadErr != nil {
			deferErr := n.Store.DeferDelivery(ctx, delivery.ID, delivery.ClaimToken, "managed notification state unavailable", time.Minute)
			return errors.Join(reloadErr, deferErr)
		}
		destinations = n.destinationSnapshot()
	}
	raw, ok := destinations[delivery.Destination]
	var sendErr error
	if !ok {
		if strings.HasPrefix(delivery.Destination, "managed:") {
			return n.Store.DeferDelivery(ctx, delivery.ID, delivery.ClaimToken, "managed notification is locked or no longer configured", time.Minute)
		}
		sendErr = errors.New("notification destination is no longer configured")
	} else {
		sendErr = safeSendContext(ctx, raw, engine.FormatEvent(delivery.Event))
	}
	resultErr := n.Store.DeliveryResultClaim(ctx, delivery.ID, delivery.ClaimToken, sendErr)
	return errors.Join(sendErr, resultErr)
}

func send(rawURL, message string) error {
	sender, err := shoutrrr.CreateSender(rawURL)
	if err != nil {
		return err
	}
	sender.Timeout = 15 * time.Second
	errs := sender.Send(message, &types.Params{"title": "EdgeWatch"})
	return errors.Join(errs...)
}

// safeSend deliberately strips provider errors before they reach logs, the
// outbox, or the CLI. Shoutrrr providers may echo a destination URL (and its
// credentials) in their error text, so a short destination fingerprint is the
// most useful diagnostic that can be retained safely.
func safeSend(rawURL, message string) error {
	return safeSendContext(context.Background(), rawURL, message)
}

func safeSendContext(ctx context.Context, rawURL, message string) error {
	if err := sendContext(ctx, rawURL, message); err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		id := hashURL(rawURL)
		return fmt.Errorf("notification delivery failed (%s)", id[:12])
	}
	return nil
}

func sendContext(ctx context.Context, rawURL, message string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	result := make(chan error, 1)
	go func() { result <- send(rawURL, message) }()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (n *Notifier) Test() error {
	return n.TestContext(context.Background())
}

// TestContext refreshes the managed destination cache first so an operator
// restoring an external key can verify it without restarting the daemon.
func (n *Notifier) TestContext(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := n.Reload(ctx); err != nil {
		return err
	}
	snapshot := n.destinationSnapshot()
	urls := make([]string, 0, len(snapshot))
	for _, rawURL := range snapshot {
		urls = append(urls, rawURL)
	}
	sort.Strings(urls)
	workers := notificationWorkers
	if len(urls) < workers {
		workers = len(urls)
	}
	if workers == 0 {
		return nil
	}
	testCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	jobs := make(chan string)
	results := make(chan error, len(urls))
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for rawURL := range jobs {
				results <- safeSendContext(testCtx, rawURL, "EdgeWatch notification test")
			}
		}()
	}
	for _, rawURL := range urls {
		select {
		case jobs <- rawURL:
		case <-testCtx.Done():
		}
	}
	close(jobs)
	wg.Wait()
	close(results)
	var all []error
	for err := range results {
		if err != nil {
			all = append(all, err)
		}
	}
	return errors.Join(all...)
}

func (n *Notifier) TestDestination(id string) error {
	return n.TestDestinationContext(context.Background(), id)
}

func (n *Notifier) TestDestinationContext(ctx context.Context, id string) error {
	if err := n.Reload(ctx); err != nil {
		return err
	}
	n.mu.RLock()
	entry, ok := n.managed[id]
	n.mu.RUnlock()
	if !ok {
		return store.ErrNotFound
	}
	if entry.locked {
		return ErrManagedNotificationLocked
	}
	return safeSendContext(ctx, entry.url, "EdgeWatch notification test")
}
