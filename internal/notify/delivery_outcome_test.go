package notify

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/model"
	"github.com/crypt0rr/edgewatch/internal/store"
)

// useFakeChild sends through runNotificationProcess, the production path,
// with a shell script in place of the notification child. started receives
// a value each time a child starts.
func useFakeChild(t *testing.T, script string) (started <-chan struct{}) {
	t.Helper()
	starts := make(chan struct{}, 64)
	originalIsTestBinary, originalExecutable, originalCommand := notificationIsTestBinary, notificationExecutable, notificationCommandContext
	notificationIsTestBinary = func() bool { return false }
	notificationExecutable = func() (string, error) { return "/usr/local/bin/edgewatch", nil }
	notificationCommandContext = func(ctx context.Context, _ string, _ ...string) *exec.Cmd {
		starts <- struct{}{}
		return exec.CommandContext(ctx, "/bin/sh", "-c", script)
	}
	t.Cleanup(func() {
		notificationIsTestBinary, notificationExecutable, notificationCommandContext = originalIsTestBinary, originalExecutable, originalCommand
	})
	return starts
}

// queuedManagedDelivery creates a unit destination and queues one alert for it.
func queuedManagedDelivery(t *testing.T, rawURL string) (*Notifier, *store.Store, DestinationView) {
	t.Helper()
	ctx := context.Background()
	notifier, db, _, _ := twoTenantNotifier(t)
	created, err := defaultNotifier(notifier).createManaged(ctx, "Webhook", rawURL, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.System().QueueEvent(ctx, managedKey(created.ID, created.Revision), model.Event{Type: "port-opened", Job: "edge", TenantID: store.DefaultTenantID, CreatedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	return notifier, db, created
}

// outboxRow is the delivery state of the only outbox row.
type outboxRow struct {
	attempts, deferrals        int
	sent, terminal, code, next string
	nextAt                     time.Time
}

func onlyOutboxRow(t *testing.T, db *store.Store) outboxRow {
	t.Helper()
	var row outboxRow
	var sent *string
	if err := db.DB.QueryRow(`SELECT attempts,deferrals,sent_at,terminal_at,last_error,next_at FROM outbox`).Scan(&row.attempts, &row.deferrals, &sent, &row.terminal, &row.code, &row.next); err != nil {
		t.Fatal(err)
	}
	if sent != nil {
		row.sent = *sent
	}
	parsed, err := time.Parse(time.RFC3339Nano, row.next)
	if err != nil {
		t.Fatal(err)
	}
	row.nextAt = parsed
	return row
}

// The notification child reports the class of a failed send with its exit
// status, and the daemon turns it into a redacted failure of that class. A
// child that reports a timeout is a provider timeout, which is also
// indeterminate.
func TestNotificationChildExitStatusReportsFailureClass(t *testing.T) {
	for _, tc := range []struct {
		status int
		want   error
		class  string
	}{
		{childExitDNS, store.ErrDeliveryProvider, store.DeliveryClassDNS},
		{childExitConnect, store.ErrDeliveryProvider, store.DeliveryClassConnect},
		{childExitTLS, store.ErrDeliveryProvider, store.DeliveryClassTLS},
		{childExitTimeout, ErrNotificationProviderTimeout, store.DeliveryClassTimeout},
		{1, store.ErrDeliveryProvider, store.DeliveryClassProvider},
		{2, store.ErrDeliveryProvider, store.DeliveryClassProvider},
	} {
		useFakeChild(t, "exit "+strconv.Itoa(tc.status))
		err := runNotificationProcess(context.Background(), "generic://example.invalid", "test")
		var failure *store.DeliveryFailure
		if !errors.Is(err, tc.want) || !errors.As(err, &failure) || failure.Class != tc.class {
			t.Errorf("exit %d: error = %v, want %v of class %s", tc.status, err, tc.want, tc.class)
		}
		if tc.status == childExitTimeout && !errors.Is(err, ErrNotificationSendIndeterminate) {
			t.Errorf("exit %d: a provider timeout must stay indeterminate: %v", tc.status, err)
		}
	}
}

// The child classifies a failed send by the type of the provider's error and
// exits with the status of that class: a provider that never answers is a
// timeout, an address that refuses the connection is a connect failure, and
// a certificate that the child does not trust is a TLS failure.
func TestRunSendChildExitStatusNamesTheFailure(t *testing.T) {
	previous := notificationProviderTimeout
	t.Cleanup(func() { notificationProviderTimeout = previous })

	release := make(chan struct{})
	hung := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { <-release }))
	t.Cleanup(func() { close(release); hung.Close() })
	trusted := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	t.Cleanup(trusted.Close)
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closedAddress := closed.Addr().String()
	_ = closed.Close()

	for _, tc := range []struct {
		name, url string
		timeout   time.Duration
		status    int
	}{
		{"no answer", "generic://" + hostOf(t, hung.URL) + "/alerts?disabletls=yes", 200 * time.Millisecond, childExitTimeout},
		{"refused", "generic://" + closedAddress + "/alerts?disabletls=yes", 5 * time.Second, childExitConnect},
		{"untrusted certificate", "generic://" + hostOf(t, trusted.URL) + "/alerts", 5 * time.Second, childExitTLS},
	} {
		t.Run(tc.name, func(t *testing.T) {
			notificationProviderTimeout = tc.timeout
			payload, err := json.Marshal(notificationProcessRequest{URL: tc.url, Message: "test"})
			if err != nil {
				t.Fatal(err)
			}
			started := time.Now()
			err = RunSendChild(strings.NewReader(string(payload)))
			var childErr *ChildExitError
			if !errors.As(err, &childErr) || childErr.ExitCode() != tc.status {
				t.Fatalf("child error = %v, want exit status %d", err, tc.status)
			}
			if elapsed := time.Since(started); elapsed > tc.timeout+2*time.Second {
				t.Fatalf("the child took %s; the provider timeout did not end it", elapsed)
			}
		})
	}
}

func hostOf(t *testing.T, raw string) string {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed.Host
}

// failureClass reads only the type of a provider error.
func TestFailureClassNamesErrorTypes(t *testing.T) {
	t.Parallel()
	wrap := func(err error) error { return &url.Error{Op: "Post", URL: "https://secret@example.invalid", Err: err} }
	for _, tc := range []struct {
		err  error
		want string
	}{
		{errProviderTimeout, store.DeliveryClassTimeout},
		{wrap(&net.OpError{Op: "dial", Err: &net.DNSError{Err: "no such host", Name: "example.invalid", IsNotFound: true}}), store.DeliveryClassDNS},
		{wrap(&net.OpError{Op: "dial", Err: errors.New("connection refused")}), store.DeliveryClassConnect},
		{wrap(x509.UnknownAuthorityError{}), store.DeliveryClassTLS},
		{wrap(x509.HostnameError{}), store.DeliveryClassTLS},
		{wrap(x509.CertificateInvalidError{}), store.DeliveryClassTLS},
		{wrap(&tls.CertificateVerificationError{Err: errors.New("bad")}), store.DeliveryClassTLS},
		{wrap(tls.RecordHeaderError{}), store.DeliveryClassTLS},
		{wrap(tls.AlertError(40)), store.DeliveryClassTLS},
		{wrap(&net.OpError{Op: "read", Err: errors.New("reset")}), store.DeliveryClassProvider},
		{errors.New("server returned response status code 500"), store.DeliveryClassProvider},
	} {
		if got := failureClass(tc.err); got != tc.want {
			t.Errorf("failureClass(%v) = %s, want %s", tc.err, got, tc.want)
		}
	}
}

// A provider that never answers fails the delivery as a provider attempt,
// not as an indeterminate deferral: through the process runner, the child's
// timeout and the parent's bound, when the child ignores its own timeout,
// are both provider timeouts. The alert waits at least a claim lease before
// it is sent again, and it stays retryable well past the eight deferrals
// that used to end it after about four hours.
func TestProviderTimeoutIsRetriedAsAProviderAttempt(t *testing.T) {
	previousTimeout, previousMargin := notificationProviderTimeout, notificationProcessMargin
	notificationProviderTimeout, notificationProcessMargin = 50*time.Millisecond, 50*time.Millisecond
	t.Cleanup(func() { notificationProviderTimeout, notificationProcessMargin = previousTimeout, previousMargin })
	for _, tc := range []struct{ name, script string }{
		{"child reports the timeout", "exit 13"},
		{"child ignores its timeout", "exec sleep 30"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			useFakeChild(t, tc.script)
			notifier, db, _ := queuedManagedDelivery(t, "generic://203.0.113.10/alerts")
			var outage time.Duration
			for pass := 1; pass <= 10; pass++ {
				before := time.Now().UTC()
				if err := notifier.Drain(ctx); !errors.Is(err, ErrNotificationProviderTimeout) {
					t.Fatalf("pass %d: drain error = %v, want a provider timeout", pass, err)
				}
				row := onlyOutboxRow(t, db)
				if row.attempts != pass || row.deferrals != 0 || row.code != "provider_timeout" || row.terminal != "" || row.sent != "" {
					t.Fatalf("pass %d: delivery = %+v, want %d provider attempts, no deferral, still retryable", pass, row, pass)
				}
				delay := row.nextAt.Sub(before)
				if delay < 29*time.Minute {
					t.Fatalf("pass %d: retry scheduled after %s, want at least the claim lease", pass, delay)
				}
				outage += delay
				// Simulate the outage lasting until the retry is due.
				if _, err := db.DB.ExecContext(ctx, `UPDATE outbox SET next_at=?`, time.Now().UTC().Add(-time.Second).Format(time.RFC3339Nano)); err != nil {
					t.Fatal(err)
				}
			}
			if outage < 4*time.Hour {
				t.Fatalf("ten timed-out attempts cover %s of outage, want more than four hours", outage)
			}
		})
	}
}

// A send that the caller cancels keeps running for the cancellation grace,
// also through the process runner: a child that finishes within it records
// a definitive success, and only a child that runs longer is ended and its
// delivery deferred as indeterminate.
func TestCanceledDeliveryWaitsForTheChildWithinTheGrace(t *testing.T) {
	t.Run("finishes within the grace", func(t *testing.T) {
		started := useFakeChild(t, "sleep 0.3; exit 0")
		notifier, db, _ := queuedManagedDelivery(t, "generic://203.0.113.10/alerts")
		drainCtx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- notifier.Drain(drainCtx) }()
		select {
		case <-started:
		case <-time.After(10 * time.Second):
			t.Fatal("the child did not start")
		}
		cancel()
		if err := <-done; err != nil {
			t.Fatalf("drain = %v, want the send's definitive success", err)
		}
		if row := onlyOutboxRow(t, db); row.sent == "" || row.deferrals != 0 || row.attempts != 0 {
			t.Fatalf("delivery = %+v, want it sent without a deferral", row)
		}
	})
	t.Run("runs past the grace", func(t *testing.T) {
		started := useFakeChild(t, "exec sleep 30")
		notifier, db, _ := queuedManagedDelivery(t, "generic://203.0.113.10/alerts")
		drainCtx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- notifier.Drain(drainCtx) }()
		select {
		case <-started:
		case <-time.After(10 * time.Second):
			t.Fatal("the child did not start")
		}
		canceled := time.Now()
		cancel()
		err := <-done
		if elapsed := time.Since(canceled); elapsed > notificationSendCancellationGrace+3*time.Second || elapsed < notificationSendCancellationGrace-100*time.Millisecond {
			t.Fatalf("drain returned %s after cancellation, want about the %s grace", elapsed, notificationSendCancellationGrace)
		}
		if !errors.Is(err, ErrNotificationSendIndeterminate) || errors.Is(err, ErrNotificationProviderTimeout) {
			t.Fatalf("drain = %v, want an indeterminate send", err)
		}
		if row := onlyOutboxRow(t, db); row.sent != "" || row.deferrals != 1 || row.attempts != 0 || row.code != "delivery_indeterminate" {
			t.Fatalf("delivery = %+v, want one indeterminate deferral", row)
		}
	})
}

// A sent alert whose result write meets a busy writer is recorded once the
// writer is free, and the next pass does not send it again. A result that
// still cannot be written is reported as sent but not recorded.
func TestSentDeliveryResultSurvivesWriterContention(t *testing.T) {
	previousTimeout, previousDelay, previousWindow := deliveryResultTimeout, deliveryResultRetryDelay, deliveryResultRetryWindow
	deliveryResultTimeout, deliveryResultRetryDelay = 100*time.Millisecond, 50*time.Millisecond
	t.Cleanup(func() {
		deliveryResultTimeout, deliveryResultRetryDelay, deliveryResultRetryWindow = previousTimeout, previousDelay, previousWindow
	})
	for _, tc := range []struct {
		name         string
		hold, window time.Duration
		recorded     bool
	}{
		{"writer freed within the window", 600 * time.Millisecond, 10 * time.Second, true},
		{"writer held past the window", 3 * time.Second, 400 * time.Millisecond, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			deliveryResultRetryWindow = tc.window
			notifier, db, _ := queuedManagedDelivery(t, "generic://203.0.113.10/alerts")
			ctx := context.Background()
			var sends atomic.Int32
			released := make(chan struct{})
			previous := notificationProviderSend
			notificationProviderSend = func(context.Context, string, string) error {
				if sends.Add(1) == 1 {
					// Another transaction takes the single writer connection
					// while the provider accepts the alert.
					tx, err := db.DB.BeginTx(ctx, nil)
					if err != nil {
						return err
					}
					go func() {
						time.Sleep(tc.hold)
						_ = tx.Rollback()
						close(released)
					}()
				}
				return nil
			}
			t.Cleanup(func() { notificationProviderSend = previous })
			err := notifier.Drain(ctx)
			<-released
			if tc.recorded {
				if err != nil {
					t.Fatalf("drain = %v", err)
				}
				if row := onlyOutboxRow(t, db); row.sent == "" {
					t.Fatalf("delivery = %+v, want it recorded as sent", row)
				}
				if err := notifier.Drain(ctx); err != nil {
					t.Fatal(err)
				}
				if got := sends.Load(); got != 1 {
					t.Fatalf("the alert was sent %d times, want once", got)
				}
				return
			}
			if !errors.Is(err, ErrDeliveryResultNotRecorded) {
				t.Fatalf("drain = %v, want the sent alert reported as not recorded", err)
			}
			if row := onlyOutboxRow(t, db); row.sent != "" {
				t.Fatalf("delivery = %+v, want it unrecorded", row)
			}
		})
	}
}

// An alert delivered long after it was raised names when it was raised.
func TestLateAlertNamesWhenItWasRaised(t *testing.T) {
	t.Parallel()
	raised := time.Date(2026, 10, 1, 8, 30, 0, 0, time.UTC)
	event := model.Event{Type: "port-opened", Job: "edge", CreatedAt: raised}
	if message := alertMessage(event, raised.Add(time.Minute)); strings.Contains(message, "Raised at") {
		t.Fatalf("a prompt alert names its time: %q", message)
	}
	if message := alertMessage(event, raised.Add(3*time.Hour)); !strings.HasSuffix(message, "\nRaised at 2026-10-01 08:30 UTC") {
		t.Fatalf("a late alert = %q, want it to name when it was raised", message)
	}
	if message := alertMessage(model.Event{Type: "port-opened", Job: "edge"}, raised); strings.Contains(message, "Raised at") {
		t.Fatalf("an alert without a time names one: %q", message)
	}
}
