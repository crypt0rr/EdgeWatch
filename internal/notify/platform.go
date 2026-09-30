package notify

import (
	"context"
	"strings"

	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/google/uuid"
)

// PlatformNotifier is the notifier as the platform sees it: the web-managed
// destinations without a tenant, which receive the platform's copy of an
// update alert. A tenant's destinations and the deployment destinations
// from config.yaml, which belong to the default tenant, are not found,
// exactly as unknown ones: they cannot be listed, changed, or selected in
// the platform's routing. The platform console's handlers use it; every
// change goes through the platform's store, which records it in platform
// scope. URLs are write-only: no method returns one.
type PlatformNotifier struct {
	n  *Notifier
	ps *store.PlatformStore
}

// Platform returns the notifier as the platform sees it.
func (n *Notifier) Platform(ps *store.PlatformStore) *PlatformNotifier {
	return &PlatformNotifier{n: n, ps: ps}
}

// destinations reloads the destinations and returns the platform's.
func (pn *PlatformNotifier) destinations(ctx context.Context) (destinationSet, error) {
	if err := pn.n.Reload(ctx); err != nil {
		return destinationSet{}, err
	}
	return pn.n.platformSet(), nil
}

// Destinations returns the redacted metadata and delivery health of the
// platform's destinations, sorted for display, and their counts, key state,
// and delivery totals, as a tenant's list and status report them. The
// health of a tenant's destinations is never read.
func (pn *PlatformNotifier) Destinations(ctx context.Context) ([]DestinationView, map[string]any, error) {
	set, err := pn.destinations(ctx)
	if err != nil {
		return nil, nil, err
	}
	status := set.status()
	var health map[string]store.DeliveryHealth
	if current, err := pn.ps.ListDeliveryHealth(ctx); err == nil {
		health = current
		addDeliveryTotals(status, health)
	}
	return finishViews(set.views(), health), status, nil
}

// ValidateDestinationSelection checks the platform's update routing against
// the platform's destinations. A tenant's destination, a deployment
// destination, and an unknown ID are refused with the same
// ErrInvalidDestinationSelection.
func (pn *PlatformNotifier) ValidateDestinationSelection(ctx context.Context, selection []string) error {
	set, err := pn.destinations(ctx)
	if err != nil {
		return err
	}
	// The platform's set has no deployment destinations, so a file:
	// selector is not found either.
	return set.validate(selection)
}

// CreateManagedWithAudit creates a platform destination. The URL is sealed
// with the notification key before the store sees it, and the store records
// a redacted audit entry in the same transaction.
func (pn *PlatformNotifier) CreateManagedWithAudit(ctx context.Context, name, rawURL string, enabled bool, audit store.AuditEntry) (DestinationView, error) {
	name = strings.TrimSpace(name)
	if err := validateName(name); err != nil {
		return DestinationView{}, err
	}
	provider, err := validateManagedURL(rawURL)
	if err != nil {
		return DestinationView{}, err
	}
	key, err := pn.n.ensureKey(ctx)
	if err != nil {
		return DestinationView{}, err
	}
	id := uuid.NewString()
	nonce, ciphertext, err := sealURL(key, id, strings.TrimSpace(rawURL))
	if err != nil {
		return DestinationView{}, err
	}
	if _, err := pn.ps.CreatePlatformNotificationWithAudit(ctx, id, name, provider, ciphertext, nonce, enabled, audit); err != nil {
		return DestinationView{}, err
	}
	if err := pn.n.Reload(ctx); err != nil {
		return DestinationView{}, err
	}
	return pn.n.view(id), nil
}

// UpdateManagedWithAudit updates one of the platform's destinations, as
// TenantNotifier.UpdateManagedWithAudit does for a tenant's: a new URL is
// sealed again, and enabling a locked destination or replacing its URL
// needs a usable key. An empty name keeps the current one. A tenant's
// destination is store.ErrNotFound, and nothing changes.
func (pn *PlatformNotifier) UpdateManagedWithAudit(ctx context.Context, id string, expectedRevision int64, name string, rawURL *string, enabled *bool, audit store.AuditEntry) (DestinationView, error) {
	n := pn.n
	record, err := pn.ps.GetPlatformNotification(ctx, id)
	if err != nil {
		return DestinationView{}, err
	}
	if name = strings.TrimSpace(name); name == "" {
		name = record.Name
	}
	if err := validateName(name); err != nil {
		return DestinationView{}, err
	}
	if rawURL != nil || (enabled != nil && *enabled) {
		if _, keyErr := n.ensureKey(ctx); keyErr != nil {
			return DestinationView{}, keyErr
		}
		if rawURL == nil {
			opened, _ := n.openManaged([]store.ManagedNotification{record})
			if opened[id].locked {
				return DestinationView{}, ErrManagedNotificationLocked
			}
		}
	}
	provider, ciphertext, nonce := record.Provider, record.Ciphertext, record.Nonce
	if rawURL != nil {
		if provider, err = validateManagedURL(*rawURL); err != nil {
			return DestinationView{}, err
		}
		key, keyErr := n.ensureKey(ctx)
		if keyErr != nil {
			return DestinationView{}, keyErr
		}
		if nonce, ciphertext, err = sealURL(key, id, strings.TrimSpace(*rawURL)); err != nil {
			return DestinationView{}, err
		}
	}
	nextEnabled := record.Enabled
	if enabled != nil {
		nextEnabled = *enabled
	}
	if _, err := pn.ps.UpdatePlatformNotificationWithAudit(ctx, id, expectedRevision, name, provider, ciphertext, nonce, nextEnabled, audit); err != nil {
		return DestinationView{}, err
	}
	if err := n.Reload(ctx); err != nil {
		return DestinationView{}, err
	}
	return n.view(id), nil
}

// DeleteManagedWithAudit removes one of the platform's destinations and
// drops it from the platform's update routing. A tenant's destination is
// store.ErrNotFound, and nothing changes.
func (pn *PlatformNotifier) DeleteManagedWithAudit(ctx context.Context, id string, expectedRevision int64, audit store.AuditEntry) error {
	if err := pn.ps.DeletePlatformNotificationWithAudit(ctx, id, expectedRevision, audit); err != nil {
		return err
	}
	return pn.n.Reload(ctx)
}
