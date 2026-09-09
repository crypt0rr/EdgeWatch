package app

import (
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/notify"
	"github.com/crypt0rr/edgewatch/internal/store"
)

func TestNewRejectsUnsafeConfiguredSecretFiles(t *testing.T) {
	for _, test := range []struct {
		name string
		set  func(*config.Config, string)
		want error
	}{
		{
			name: "notification key",
			set: func(cfg *config.Config, path string) {
				cfg.Notifications.EncryptionKeyFile = path
			},
			want: notify.ErrKeyPermissions,
		},
		{
			name: "authentication key",
			set: func(cfg *config.Config, path string) {
				cfg.Web.AuthKeyFile = path
			},
			want: store.ErrAuthKeyPermissions,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			database, err := store.Open(filepath.Join(dir, "edgewatch.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close()
			keyPath := filepath.Join(dir, test.name+".key")
			if err := os.WriteFile(keyPath, make([]byte, 32), 0o644); err != nil {
				t.Fatal(err)
			}
			cfg := &config.Config{
				Version: 1, Database: database.Path, Retention: config.Duration(24 * time.Hour),
				Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080"},
			}
			test.set(cfg, keyPath)
			_, err = New(cfg, database, "missing-nmap", slog.New(slog.NewTextHandler(io.Discard, nil)))
			if !errors.Is(err, test.want) {
				t.Fatalf("startup error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestNewRejectsMissingExplicitNotificationKey(t *testing.T) {
	database, err := store.Open(filepath.Join(t.TempDir(), "edgewatch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	cfg := &config.Config{
		Version: 1, Database: database.Path, Retention: config.Duration(24 * time.Hour),
		Scheduler: config.Scheduler{MaxConcurrent: 1}, Web: config.Web{Listen: "127.0.0.1:8080"},
		Notifications: config.Notifications{EncryptionKeyFile: filepath.Join(t.TempDir(), "missing.key")},
	}
	_, err = New(cfg, database, "missing-nmap", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if !errors.Is(err, notify.ErrKeyUnavailable) {
		t.Fatalf("missing explicit notification key error = %v", err)
	}
}
