//go:build race

package store

// raceEnabled reports whether the test binary runs under the race detector,
// which slows SQLite down by more than an order of magnitude.
const raceEnabled = true
