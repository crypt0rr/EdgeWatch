package store

import (
	"os"
	"path/filepath"
	"sync"
)

// openDatabases records the on-disk databases that stores in this process
// have open. SQLite's unix VFS uses POSIX record locks, and closing any
// descriptor for a database file releases every POSIX lock this process holds
// on it. Probe sidecar cleanup opens its own descriptor to test for other
// connections, so it only does that for a database that no store in this
// process has open.
var openDatabases = &openDatabaseRegistry{entries: map[*openDatabaseEntry]struct{}{}}

type openDatabaseRegistry struct {
	mu      sync.Mutex
	entries map[*openDatabaseEntry]struct{}
}

type openDatabaseEntry struct {
	path string
	info os.FileInfo
}

// register records database as open by a store until the returned function
// runs. The function is safe to call more than once.
func (r *openDatabaseRegistry) register(database string) func() {
	entry := &openDatabaseEntry{path: openDatabaseKey(database)}
	if info, err := os.Stat(database); err == nil {
		entry.info = info
	}
	r.mu.Lock()
	r.entries[entry] = struct{}{}
	r.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			r.mu.Lock()
			delete(r.entries, entry)
			r.mu.Unlock()
		})
	}
}

// withUnused runs fn only when no store in this process has database open,
// matching by path or by file identity. It holds the registry lock while fn
// runs, so no store in this process can open the database in the meantime.
func (r *openDatabaseRegistry) withUnused(database string, fn func()) {
	path := openDatabaseKey(database)
	info, statErr := os.Stat(database)
	r.mu.Lock()
	defer r.mu.Unlock()
	for entry := range r.entries {
		if entry.path == path || (statErr == nil && entry.info != nil && os.SameFile(entry.info, info)) {
			return
		}
	}
	fn()
}

func openDatabaseKey(database string) string {
	if absolute, err := filepath.Abs(database); err == nil {
		return absolute
	}
	return filepath.Clean(database)
}
