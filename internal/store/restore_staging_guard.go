package store

import "context"

// acquireRestoreStagingGuard serializes restore operations that share a
// destination directory. Platforms without an advisory directory-lock
// implementation retain restore behavior but skip orphan cleanup, rather
// than risk removing another process's active staging copy.
var acquireRestoreStagingGuard = func(context.Context, string) (unlock func(), supported bool, err error) {
	return nil, false, nil
}
