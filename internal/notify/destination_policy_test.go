package notify

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// fakeDNS answers destination lookups from a table that a test can change.
type fakeDNS struct {
	mu      sync.Mutex
	answers map[string][]netip.Addr
	lookups []string
}

func useFakeDNS(t *testing.T, answers map[string]string) *fakeDNS {
	t.Helper()
	dns := &fakeDNS{answers: map[string][]netip.Addr{}}
	for host, address := range answers {
		dns.set(host, address)
	}
	previous := destinationLookup
	destinationLookup = func(_ context.Context, host string) ([]netip.Addr, error) {
		dns.mu.Lock()
		defer dns.mu.Unlock()
		dns.lookups = append(dns.lookups, host)
		if addresses, ok := dns.answers[host]; ok {
			return addresses, nil
		}
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	t.Cleanup(func() { destinationLookup = previous })
	return dns
}

func (d *fakeDNS) set(host, address string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.answers[host] = []netip.Addr{netip.MustParseAddr(address)}
}

// A unit's destination whose host is, or resolves to, an address that the
// scanner refuses is refused when it is created or its URL is replaced, with
// a fixed error that names neither the URL nor the address. A public host is
// accepted, and an explicitly empty scanner.target_exclusions accepts the
// loopback address too.
func TestUnitDestinationRefusesExcludedAddresses(t *testing.T) {
	ctx := context.Background()
	useFakeDNS(t, map[string]string{
		"loopback.example": "127.0.0.1",
		"metadata.example": "169.254.169.254",
		"mapped.example":   "::ffff:127.0.0.1",
		"public.example":   "203.0.113.10",
	})
	notifier, _, _, _ := twoTenantNotifier(t)
	if err := notifier.SetTargetExclusions(config.DefaultTargetExclusions()); err != nil {
		t.Fatal(err)
	}
	refused := []string{
		"generic://127.0.0.1:8080/hook?disabletls=yes",
		"generic://[::1]/hook?disabletls=yes",
		"generic://169.254.169.254/latest/meta-data",
		"generic://0.0.0.0/hook",
		"generic://[fe80::1%25eth0]/hook",
		"generic://loopback.example/hook",
		"generic+http://metadata.example/hook",
		"ntfy://user:secret@loopback.example/topic",
		"gotify://mapped.example/token",
		"smtp://user:secret@metadata.example:25/?from=a@example.com&to=b@example.com",
		"teams://11111111-4444-4444-8444-cccccccccccc@22222222-4444-4444-8444-cccccccccccc/33333333012222222222333333333344/44444444-4444-4444-8444-cccccccccccc?host=loopback.example",
	}
	for _, raw := range refused {
		_, err := defaultNotifier(notifier).createManaged(ctx, "Refused", raw, true, nil)
		if !errors.Is(err, ErrDestinationExcluded) {
			t.Errorf("create %s: %v, want the destination refused", raw, err)
			continue
		}
		parsed, _ := url.Parse(raw)
		for _, secret := range []string{raw, parsed.Hostname(), "127.0.0.1", "169.254"} {
			if secret != "" && strings.Contains(err.Error(), secret) {
				t.Errorf("create %s: the error %q names %q", raw, err, secret)
			}
		}
	}
	created, err := defaultNotifier(notifier).createManaged(ctx, "Public", "generic://public.example/hook", true, nil)
	if err != nil {
		t.Fatalf("a public destination was refused: %v", err)
	}
	// Discord and the other fixed-host providers connect to their public API
	// host; the host part of their URL is a token or an ID.
	if _, err := defaultNotifier(notifier).createManaged(ctx, "Telegram", "telegram://123456:token@telegram?chats=@edgewatch", true, nil); err != nil {
		t.Fatalf("a fixed-host provider was refused: %v", err)
	}
	loopback := "generic://127.0.0.1/hook?disabletls=yes"
	if _, err := defaultNotifier(notifier).updateManaged(ctx, created.ID, created.Revision, "Public", &loopback, nil, nil); !errors.Is(err, ErrDestinationExcluded) {
		t.Fatalf("replacing the URL with a loopback one = %v, want it refused", err)
	}
	if err := notifier.SetTargetExclusions([]string{}); err != nil {
		t.Fatal(err)
	}
	if _, err := defaultNotifier(notifier).updateManaged(ctx, created.ID, created.Revision, "Public", &loopback, nil, nil); err != nil {
		t.Fatalf("with scanner.target_exclusions: [] the loopback URL = %v, want it accepted", err)
	}
}

// A configured exclusion is refused as the defaults are, with the scanner's
// CIDR matching, and the loopback, link-local, and unspecified addresses stay
// refused next to it. A nil list, for embedded callers, refuses nothing.
func TestDestinationPolicyMatchesTargetExclusions(t *testing.T) {
	notifier := &Notifier{}
	if err := notifier.SetTargetExclusions([]string{"10.0.0.0/8", "2001:db8::1"}); err != nil {
		t.Fatal(err)
	}
	policy := notifier.destinationPolicy()
	for address, want := range map[string]bool{
		"10.1.2.3": true, "2001:db8::1": true, "2001:db8::2": false, "127.0.0.2": true, "::": true,
		"169.254.10.1": true, "fe80::2": true, "ff02::1": true, "192.0.2.1": false, "::ffff:10.0.0.1": true,
	} {
		if got := policy.refuses(netip.MustParseAddr(address)); got != want {
			t.Errorf("refuses(%s) = %v, want %v", address, got, want)
		}
	}
	if err := notifier.SetTargetExclusions([]string{"not a network"}); err == nil {
		t.Fatal("an invalid exclusion was accepted")
	}
	if err := notifier.SetTargetExclusions(nil); err != nil || notifier.destinationPolicy() != nil {
		t.Fatalf("a nil list installed a policy: %v", err)
	}
	if err := notifier.destinationPolicy().check(context.Background(), "generic://127.0.0.1/hook"); err != nil {
		t.Fatalf("without a policy a loopback destination = %v", err)
	}
}

func TestDestinationHostsFollowTheProvider(t *testing.T) {
	t.Parallel()
	for raw, want := range map[string][]string{
		"generic://hooks.example:8443/path":                   {"hooks.example"},
		"generic+https://hooks.example/path":                  {"hooks.example"},
		"ntfy://user:secret@ntfy.example/topic":               {"ntfy.example"},
		"smtp://user:secret@[2001:db8::25]:25/?from=a@b.c":    {"2001:db8::25"},
		"teams://group@tenant/alt/owner?host=example.webhook": {"example.webhook"},
		"teams://group@tenant/alt/owner?HOST=[::1]:443":       {"::1"},
		"teams://group@tenant/alt/owner":                      nil,
		"discord://token@123456789":                           nil,
		"telegram://token@telegram?chats=@channel":            nil,
		"logger://": nil,
		"%":         nil,
	} {
		if got := destinationHosts(raw); !reflect.DeepEqual(got, want) {
			t.Errorf("destinationHosts(%q) = %v, want %v", raw, got, want)
		}
	}
}

// A unit's destination whose DNS answer changed to an excluded address after
// it was saved is not sent to: the delivery fails as a provider attempt with
// the destination_excluded code, and its test fails without contacting it.
// A platform destination, which a platform administrator configures, is not
// checked.
func TestSendRefusesADestinationThatNowResolvesToAnExcludedAddress(t *testing.T) {
	ctx := context.Background()
	dns := useFakeDNS(t, map[string]string{"hooks.example": "203.0.113.10"})
	notifier, db, created := queuedManagedDelivery(t, "generic://hooks.example/alerts")
	if err := notifier.SetTargetExclusions(config.DefaultTargetExclusions()); err != nil {
		t.Fatal(err)
	}
	sends := recordSends(t)
	dns.set("hooks.example", "127.0.0.1")
	if err := notifier.Drain(ctx); !errors.Is(err, ErrDestinationExcluded) {
		t.Fatalf("drain = %v, want the destination refused", err)
	}
	if sent := sends(); len(sent) != 0 {
		t.Fatalf("a destination that resolves to loopback was sent to: %v", sent)
	}
	if row := onlyOutboxRow(t, db); row.attempts != 1 || row.code != "destination_excluded" || row.sent != "" {
		t.Fatalf("delivery = %+v, want one failed attempt with destination_excluded", row)
	}
	if err := defaultNotifier(notifier).TestDestination(ctx, created.ID); !errors.Is(err, ErrDestinationExcluded) {
		t.Fatalf("test = %v, want the destination refused", err)
	}
	if _, err := defaultNotifier(notifier).TestSummary(ctx); !errors.Is(err, ErrDestinationExcluded) {
		t.Fatalf("test summary = %v, want the destination refused", err)
	}
	if sent := sends(); len(sent) != 0 {
		t.Fatalf("a test reached a destination that resolves to loopback: %v", sent)
	}

	audit := addPlatformAdmin(t, db)
	platform, err := notifier.Platform(db.Platform()).CreateManagedWithAudit(ctx, "Platform", "generic://127.0.0.1/alerts?disabletls=yes", true, audit)
	if err != nil {
		t.Fatalf("a platform destination was refused: %v", err)
	}
	if err := db.System().QueueEvent(ctx, managedKey(platform.ID, platform.Revision), model.Event{Type: "application-update-available", LatestVersion: "9.9.9", CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	_ = notifier.Drain(ctx)
	if sent := sends(); len(sent) != 1 || !strings.Contains(sent[0], "127.0.0.1") {
		t.Fatalf("platform sends = %v, want the platform destination sent to", sent)
	}
}

// A failure's fingerprint names its kind only: the same failure of two
// destinations has the same fingerprint, a different kind another, and
// neither it nor the returned error holds a digest of a destination URL.
func TestDeliveryFailureFingerprintIsIndependentOfTheURL(t *testing.T) {
	ctx := context.Background()
	notifier, db, _, _ := twoTenantNotifier(t)
	urls := []string{"generic://first.example/secret-token-one", "generic://second.example/secret-token-two", "generic://third.example/secret-token-three"}
	ids := make([]string, len(urls))
	for i, raw := range urls {
		created, err := defaultNotifier(notifier).createManaged(ctx, "Destination "+string(rune('A'+i)), raw, true, nil)
		if err != nil {
			t.Fatal(err)
		}
		ids[i] = created.ID
		if err := db.System().QueueEvent(ctx, managedKey(created.ID, created.Revision), model.Event{Type: "port-opened", Job: "edge", TenantID: store.DefaultTenantID, CreatedAt: time.Now().UTC()}); err != nil {
			t.Fatal(err)
		}
	}
	previous := notificationProviderSend
	notificationProviderSend = func(_ context.Context, raw, _ string) error {
		if strings.Contains(raw, "third") {
			return &url.Error{Op: "Post", URL: raw, Err: &net.OpError{Op: "dial", Err: &net.DNSError{Err: "no such host", Name: "third.example"}}}
		}
		return &url.Error{Op: "Post", URL: raw, Err: &net.OpError{Op: "dial", Err: errors.New("connection refused")}}
	}
	t.Cleanup(func() { notificationProviderSend = previous })
	drainErr := notifier.Drain(ctx)
	if drainErr == nil {
		t.Fatal("the failed deliveries were not reported")
	}
	views := map[string]DestinationView{}
	for _, view := range defaultDestinations(t, notifier) {
		views[view.ID] = view
	}
	first, second, third := views[ids[0]].LastErrorFingerprint, views[ids[1]].LastErrorFingerprint, views[ids[2]].LastErrorFingerprint
	if first == "" || first != second {
		t.Fatalf("the same failure of two destinations has fingerprints %q and %q, want one", first, second)
	}
	if third == "" || third == first {
		t.Fatalf("a DNS failure has fingerprint %q, want one other than the connect failure's %q", third, first)
	}
	for _, raw := range urls {
		sum := sha256.Sum256([]byte(raw))
		digest := hex.EncodeToString(sum[:])
		for _, text := range []string{first, third, drainErr.Error()} {
			if strings.Contains(text, digest[:8]) || strings.Contains(text, "secret-token") {
				t.Fatalf("%q holds a digest of, or text from, the destination URL %s", text, raw)
			}
		}
		// The fingerprint of earlier releases: a digest of the error text,
		// which held a digest of the URL. It no longer matches.
		legacy := sha256.Sum256([]byte("notification provider failed: notification delivery failed (" + digest[:12] + ")"))
		if hex.EncodeToString(legacy[:])[:16] == first {
			t.Fatalf("the fingerprint can still be recomputed from the URL %s", raw)
		}
	}
}

// A destination's alerts that failed for good are listed by their metadata
// only, and a redelivery makes the next delivery pass send them to the
// destination's current URL. Another unit cannot list or redeliver them.
func TestRedeliveredAlertIsSentToTheCurrentURL(t *testing.T) {
	ctx := context.Background()
	notifier, db, _, other := twoTenantNotifier(t)
	created, err := defaultNotifier(notifier).createManaged(ctx, "Webhook", "generic://broken.example/old-secret", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.System().QueueEvent(ctx, managedKey(created.ID, created.Revision), model.Event{Type: "port-opened", Job: "edge", TenantID: store.DefaultTenantID, CreatedAt: time.Now().UTC().Add(-4 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.ExecContext(ctx, `UPDATE outbox SET attempts=15,terminal_at=?,last_error='delivery_failed'`, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	repaired := "generic://repaired.example/new-secret"
	if _, err := defaultNotifier(notifier).UpdateManagedKeepingPendingWithAudit(ctx, created.ID, created.Revision, "Webhook", &repaired, nil, store.AuditEntry{Action: "notifications.updated"}); err != nil {
		t.Fatal(err)
	}
	deliveries, err := defaultNotifier(notifier).TerminalDeliveries(ctx, created.ID, 0, 10)
	if err != nil || len(deliveries) != 1 || deliveries[0].EventType != "port-opened" || deliveries[0].Job != "edge" || deliveries[0].Attempts != 15 || deliveries[0].ErrorCode != "delivery_failed" {
		t.Fatalf("terminal deliveries = %+v, %v", deliveries, err)
	}
	if _, err := notifier.Tenant(other).TerminalDeliveries(ctx, created.ID, 0, 10); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("another unit listed the deliveries: %v", err)
	}
	if _, err := notifier.Tenant(other).RedeliverTerminalDeliveries(ctx, created.ID, nil, store.AuditEntry{Action: "notifications.redelivered"}); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("another unit redelivered the deliveries: %v", err)
	}
	sends := recordSends(t)
	if err := notifier.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	if sent := sends(); len(sent) != 0 {
		t.Fatalf("a terminal delivery was sent before its redelivery: %v", sent)
	}
	count, err := defaultNotifier(notifier).RedeliverTerminalDeliveries(ctx, created.ID, nil, store.AuditEntry{Action: "notifications.redelivered"})
	if err != nil || count != 1 {
		t.Fatalf("redelivered %d, %v; want 1", count, err)
	}
	var messages []string
	previous := notificationProviderSend
	notificationProviderSend = func(_ context.Context, raw, message string) error {
		messages = append(messages, raw+"\n"+message)
		return nil
	}
	t.Cleanup(func() { notificationProviderSend = previous })
	if err := notifier.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	if len(messages) != 1 || !strings.HasPrefix(messages[0], repaired) || !strings.Contains(messages[0], "Raised at ") {
		t.Fatalf("sends = %q, want the alert sent once to the repaired URL with the time it was raised", messages)
	}
	if row := onlyOutboxRow(t, db); row.sent == "" {
		t.Fatalf("delivery = %+v, want it sent", row)
	}
}

// A destination imported from config.yaml keeps the URL that the host
// operator configured, so the address policy does not refuse it, for
// deliveries and tests alike. Once a unit administrator replaces its URL, it
// is checked like any other destination of the unit.
func TestImportedDestinationKeepsItsOperatorConfiguredURL(t *testing.T) {
	ctx := context.Background()
	db, _ := openImportStore(t)
	result, err := ImportConfiguredURLs(ctx, db, []string{"generic://127.0.0.1:9/hook?disabletls=yes"}, "")
	if err != nil || len(result.Imported) != 1 {
		t.Fatalf("import = %+v, %v", result, err)
	}
	id := result.Imported[0].ID
	notifier, err := New(db, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := notifier.SetTargetExclusions(config.DefaultTargetExclusions()); err != nil {
		t.Fatal(err)
	}
	record, err := db.Tenant(store.DefaultTenantScope()).GetManagedNotification(ctx, id)
	if err != nil || !record.ConfigImported {
		t.Fatalf("imported record = %+v, %v", record, err)
	}
	sends := recordSends(t)
	if err := db.System().QueueEvent(ctx, managedKey(id, record.Revision), model.Event{Type: "port-opened", Job: "edge", TenantID: store.DefaultTenantID, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := notifier.Drain(ctx); err != nil {
		t.Fatalf("drain = %v", err)
	}
	if err := defaultNotifier(notifier).TestDestination(ctx, id); err != nil {
		t.Fatalf("test = %v", err)
	}
	if summary, err := defaultNotifier(notifier).TestSummary(ctx); err != nil || summary.Tested != 1 {
		t.Fatalf("test summary = %+v, %v", summary, err)
	}
	if sent := sends(); len(sent) != 3 {
		t.Fatalf("sends = %v, want the delivery and both tests", sent)
	}
	loopback := "generic://127.0.0.1:10/hook?disabletls=yes"
	if _, err := defaultNotifier(notifier).updateManaged(ctx, id, record.Revision, "Deployment destination", &loopback, nil, nil); !errors.Is(err, ErrDestinationExcluded) {
		t.Fatalf("replacing the imported URL with a loopback one = %v, want it refused", err)
	}
	public := "generic://203.0.113.10/hook"
	updated, err := defaultNotifier(notifier).updateManaged(ctx, id, record.Revision, "Deployment destination", &public, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if record, err := db.Tenant(store.DefaultTenantScope()).GetManagedNotification(ctx, updated.ID); err != nil || record.ConfigImported {
		t.Fatalf("the replaced destination = %+v, %v; want it checked as a unit's", record, err)
	}
}
