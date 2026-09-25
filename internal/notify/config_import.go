package notify

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/crypt0rr/edgewatch/internal/store"
	"github.com/google/uuid"
)

// DeploymentDestinationName is the console label of a destination loaded from
// config.yaml. Imported destinations are named after it, with a numeric
// suffix when a web-managed destination already uses the name.
const DeploymentDestinationName = "Deployment destination"

// Bounded reasons for an import that did not complete. They are safe for
// logs, the health command, and the console.
const (
	ConfigImportDatabaseError  = "database_error"
	ConfigImportKeyUnreadable  = "key_unreadable"
	ConfigImportDecryptFailed  = "decrypt_failed"
	ConfigImportEncryptFailed  = "encrypt_failed"
	configImportKeyUnavailable = "key_unavailable"
	configImportKeyPermissions = "key_permissions"
	configImportKeyInvalid     = "key_invalid"
)

// ConfigImportError reports why importing the notification URLs in
// config.yaml did not complete. Nothing was imported, and the URLs remain
// deployment destinations. Neither Code nor Err contains a URL.
type ConfigImportError struct {
	Code string
	Err  error
}

func (e *ConfigImportError) Error() string {
	return fmt.Sprintf("import notification URLs from config.yaml (%s): %v", e.Code, e.Err)
}

func (e *ConfigImportError) Unwrap() error { return e.Err }

func configImportError(code string, err error) error {
	return &ConfigImportError{Code: code, Err: err}
}

// ConfigImportResult summarizes an import with counts and stable IDs only.
type ConfigImportResult struct {
	// Configured is the number of distinct URLs that config.yaml lists.
	Configured int
	// Imported lists the destinations this call created.
	Imported []store.ImportedDeploymentNotification
	// AlreadyImported counts configured URLs that an earlier start imported,
	// including URLs whose imported destination was deleted afterwards.
	AlreadyImported      int
	ChangedJobs          []string
	UpdateRoutingChanged bool
	MovedDeliveries      int64
	MergedDeliveries     int64
}

// ImportedURLs is the number of configured URLs that are recorded as imported
// and are therefore no longer delivered from config.yaml.
func (r ConfigImportResult) ImportedURLs() int {
	return len(r.Imported) + r.AlreadyImported
}

type configuredURL struct {
	raw    string
	digest string
}

// configuredURLs validates the configured URLs exactly as the notifier does and
// returns them once each, in configuration order. The error names only a short
// digest prefix, never the URL.
func configuredURLs(urls []string) ([]configuredURL, error) {
	seen := make(map[string]struct{}, len(urls))
	out := make([]configuredURL, 0, len(urls))
	for _, raw := range urls {
		digest := hashURL(raw)
		if _, err := validateManagedURL(raw); err != nil {
			return nil, fmt.Errorf("invalid Shoutrrr destination %s", digest[:12])
		}
		if _, duplicate := seen[digest]; duplicate {
			continue
		}
		seen[digest] = struct{}{}
		out = append(out, configuredURL{raw: raw, digest: digest})
	}
	return out, nil
}

// ImportConfiguredURLs turns every notification URL from config.yaml that has
// not been imported yet into an encrypted web-managed destination, and moves
// all references to its deployment destination onto it in the same
// transaction. keyFile is notifications.encryption_key_file; when it is empty
// the default key beside the database is used, and it is created when no
// web-managed destination exists yet, as for the first destination created in
// the console.
//
// An invalid URL is returned as a plain configuration error. Any other
// failure is a *ConfigImportError: nothing is imported and the URLs stay
// deployment destinations. A URL recorded by an earlier import is never
// imported again, even when its destination was deleted in the console.
func ImportConfiguredURLs(ctx context.Context, s *store.Store, urls []string, keyFile string) (ConfigImportResult, error) {
	var result ConfigImportResult
	if s == nil {
		return result, errors.New("notification import requires a store")
	}
	configured, err := configuredURLs(urls)
	if err != nil {
		return result, err
	}
	result.Configured = len(configured)
	if len(configured) == 0 {
		return result, nil
	}
	digests := make([]string, 0, len(configured))
	for _, item := range configured {
		digests = append(digests, item.digest)
	}
	imported, err := s.ImportedDeploymentNotifications(ctx, digests)
	if err != nil {
		return result, configImportError(ConfigImportDatabaseError, err)
	}
	pending := make([]configuredURL, 0, len(configured))
	for _, item := range configured {
		if !imported[item.digest] {
			pending = append(pending, item)
		}
	}
	result.AlreadyImported = len(configured) - len(pending)
	if len(pending) == 0 {
		return result, nil
	}
	keyPath, autoCreate := strings.TrimSpace(keyFile), false
	if keyPath == "" {
		keyPath, autoCreate = keyPathBeside(s.FilePath()), true
	}
	sealer := &Notifier{Store: s, keyPath: keyPath, autoCreateKey: autoCreate}
	key, err := sealer.ensureKey(ctx)
	if err != nil {
		return result, configImportError(configImportKeyCode(err), err)
	}
	// Refuse a key that cannot open the existing destinations. Importing
	// under a replaced key would lock the imported destinations as soon as
	// the original key is restored, while config.yaml no longer delivers.
	existing, err := s.ListManagedNotifications(ctx)
	if err != nil {
		return result, configImportError(ConfigImportDatabaseError, err)
	}
	for _, record := range existing {
		if _, openErr := openURL(key, record.ID, record.Nonce, record.Ciphertext); openErr != nil {
			return result, configImportError(ConfigImportDecryptFailed, fmt.Errorf("notification key cannot decrypt destination %s", record.ID))
		}
	}
	items := make([]store.DeploymentNotificationImport, 0, len(pending))
	for _, item := range pending {
		id := uuid.NewString()
		rawURL := strings.TrimSpace(item.raw)
		nonce, ciphertext, sealErr := sealURL(key, id, rawURL)
		if sealErr != nil {
			return result, configImportError(ConfigImportEncryptFailed, sealErr)
		}
		items = append(items, store.DeploymentNotificationImport{LegacyHash: item.digest, ID: id, Name: DeploymentDestinationName, Provider: providerForURL(rawURL), Ciphertext: ciphertext, Nonce: nonce})
	}
	committed, err := s.ImportDeploymentNotifications(ctx, items)
	if err != nil {
		return result, configImportError(ConfigImportDatabaseError, err)
	}
	result.Imported = committed.Imported
	// Another process may have recorded a URL between the read above and the
	// import transaction; the store skipped it.
	result.AlreadyImported += committed.Skipped
	result.ChangedJobs = committed.ChangedJobs
	result.UpdateRoutingChanged = committed.UpdateRoutingChanged
	result.MovedDeliveries = committed.MovedDeliveries
	result.MergedDeliveries = committed.MergedDeliveries
	return result, nil
}

func configImportKeyCode(err error) string {
	switch {
	case errors.Is(err, ErrKeyUnavailable):
		return configImportKeyUnavailable
	case errors.Is(err, ErrKeyPermissions):
		return configImportKeyPermissions
	case errors.Is(err, ErrKeyInvalid):
		return configImportKeyInvalid
	default:
		return ConfigImportKeyUnreadable
	}
}
