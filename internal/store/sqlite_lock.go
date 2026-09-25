package store

// lockSQLiteDatabase takes a non-blocking lock that proves no other SQLite
// connection has the database open, and returns the function that releases
// it. Only Linux sets it, because an open file description lock also
// conflicts with SQLite's POSIX locks held by this process. Elsewhere it stays
// nil, and read-only probes keep their WAL/SHM pair instead of guessing.
var lockSQLiteDatabase func(database string) (unlock func(), ok bool)

// withExclusiveSQLiteDatabase runs fn only while no other SQLite connection
// has the database open, and reports whether fn ran. While the lock is held,
// no connection can attach to the database, open its WAL, or create a
// journal.
//
// Closing the lock's descriptor releases every POSIX lock this process holds
// on the file, so callers must only use this when no SQLite connection in
// this process has the database open.
func withExclusiveSQLiteDatabase(database string, fn func()) bool {
	if lockSQLiteDatabase == nil {
		return false
	}
	unlock, ok := lockSQLiteDatabase(database)
	if !ok {
		return false
	}
	defer unlock()
	fn()
	return true
}
