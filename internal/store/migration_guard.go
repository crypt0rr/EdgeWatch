package store

import (
	"errors"
)

// ErrMigrationInProgress is the refusal of an open that would migrate a
// database while another process migrates or restores a database in the same
// directory.
var ErrMigrationInProgress = errors.New("another EdgeWatch process is migrating or restoring the database in this directory")

// errMigrationGuardUnsupported reports that the directory of a database
// cannot be locked, for example on a file system without flock. The open
// then migrates without the guard, protected by the schema marker check of
// each step.
var errMigrationGuardUnsupported = errors.New("the database directory cannot be locked")

// acquireMigrationGuard takes, without waiting, the exclusive advisory lock
// on the directory of a database that a migrating open holds until the
// migration and its startup phases have finished. It is the lock with which
// restores of the same directory serialize, so a migration never runs while
// a restore stages or replaces the database, and a second daemon on the
// same data volume is refused instead of upgrading the schema or rewriting
// startup_state under the first one. The kernel releases the lock when the
// process exits, so a crash leaves nothing to clean up. A busy lock returns
// an error wrapping ErrMigrationInProgress.
//
// Platforms without an implementation return a no-op unlock.
var acquireMigrationGuard = acquireUnsupportedMigrationGuard

func acquireUnsupportedMigrationGuard(string) (func(), error) {
	return func() {}, nil
}
