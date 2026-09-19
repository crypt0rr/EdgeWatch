package store

import "time"

// sqliteTimestamp is the canonical representation for timestamps used in
// SQLite ordering predicates. RFC3339Nano omits trailing zeroes, which makes
// otherwise equal instants sort lexically in the wrong order when one value
// has a fractional component and another does not. A fixed-width UTC value
// keeps the existing text indexes usable and remains RFC3339 compatible.
const sqliteTimestampLayout = "2006-01-02T15:04:05.000000000Z07:00"

func sqliteTimestamp(value time.Time) string {
	return value.UTC().Format(sqliteTimestampLayout)
}

func normalizeSQLiteTimestamp(value string) (string, bool) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		return value, false
	}
	return sqliteTimestamp(parsed), true
}
