package store

import (
	"cmp"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
)

// The perimeter of a business unit is the address space its administrators
// declare: ranges it owns (kind prefix) and third-party ranges it may scan
// but does not own (kind authorized). A declaration states ownership or
// permission; it does not authorize a scan, and nothing in the store scans,
// creates or changes a job because of it. The rows are unit data in
// perimeter_seeds: a unit's requests read and write them only through
// TenantStore, and the daemon purges them with the unit.

// The kinds of a perimeter range, as perimeter_seeds.kind stores them. The
// schema also accepts PerimeterKindASN for a later ASN watch, but a
// declaration refuses it.
const (
	PerimeterKindPrefix     = "prefix"
	PerimeterKindAuthorized = "authorized"
	PerimeterKindASN        = "asn"
)

// perimeterSourceDeclared is the source of every range an administrator
// declares. The schema keeps 'adopted' for ranges that a later ASN watch
// adopts from announced space.
const perimeterSourceDeclared = "declared"

// The limits of the perimeter.
const (
	// MaxPerimeterRanges bounds the prefix and authorized ranges of one
	// unit. A declaration counts them after its insert, in its own
	// transaction, so values it skipped as duplicates never count.
	MaxPerimeterRanges = 1024
	// MaxPerimeterEntriesPerRequest bounds the entries of one declaration.
	MaxPerimeterEntriesPerRequest = 256
	// MaxPerimeterLabelRunes bounds a range's label, as config.MaxJobNameRunes
	// bounds a job name.
	MaxPerimeterLabelRunes = 200
	// perimeterLineValueBytes bounds the value that a refused entry echoes.
	perimeterLineValueBytes = 64
)

// The audit actions of the perimeter. Both are data actions of the unit.
const (
	auditPerimeterSeedsAdded  = "perimeter.seeds_added"
	auditPerimeterSeedRemoved = "perimeter.seed_removed"
)

// The reasons a declaration gives for a refused entry. Each is a fixed text,
// so a refusal never quotes more of the entry than its cut value.
const (
	perimeterReasonKind          = "kind must be prefix or authorized"
	perimeterReasonASN           = "ASN declarations are not supported; declare the prefixes the ASN announces"
	perimeterReasonValue         = "not an IP address or CIDR prefix"
	perimeterReasonZone          = "zones are not allowed"
	perimeterReasonMapped        = "write the IPv4 form"
	perimeterReasonIPv4Short     = "IPv4 prefixes must be /8 or longer"
	perimeterReasonIPv6Short     = "IPv6 prefixes must be /16 or longer"
	perimeterReasonUnspecified   = "unspecified address space is not allowed"
	perimeterReasonLoopback      = "loopback address space is not allowed"
	perimeterReasonMulticast     = "multicast address space is not allowed"
	perimeterReasonLinkLocal     = "link-local address space is not allowed"
	perimeterReasonLabelEncoding = "label must be valid UTF-8"
	perimeterReasonLabelLength   = "label must be at most 200 characters"
	perimeterReasonLabelControl  = "label must not contain control characters"
	perimeterReasonOwned         = "already declared as owned"
	perimeterReasonAuthorized    = "already declared as authorized"
)

// perimeterSpecialRanges are the address spaces that no declared range may
// overlap, with the reason for each. None of them is reachable perimeter.
var perimeterSpecialRanges = []struct {
	prefix netip.Prefix
	reason string
}{
	{netip.MustParsePrefix("0.0.0.0/32"), perimeterReasonUnspecified},
	{netip.MustParsePrefix("127.0.0.0/8"), perimeterReasonLoopback},
	{netip.MustParsePrefix("224.0.0.0/4"), perimeterReasonMulticast},
	{netip.MustParsePrefix("169.254.0.0/16"), perimeterReasonLinkLocal},
	{netip.MustParsePrefix("::/128"), perimeterReasonUnspecified},
	{netip.MustParsePrefix("::1/128"), perimeterReasonLoopback},
	{netip.MustParsePrefix("ff00::/8"), perimeterReasonMulticast},
	{netip.MustParsePrefix("fe80::/10"), perimeterReasonLinkLocal},
}

// perimeterMappedPrefix holds the IPv4-mapped IPv6 addresses. The scanner
// treats such a target as IPv4, so a range in it must be declared in its
// IPv4 form.
var perimeterMappedPrefix = netip.MustParsePrefix("::ffff:0:0/96")

var (
	// ErrPerimeterLimit reports a declaration that would leave the unit
	// with more than MaxPerimeterRanges ranges. A *PerimeterLimitError
	// matches it and ErrValidation.
	ErrPerimeterLimit = errors.New("perimeter range limit reached")
	// ErrPerimeterEntryCount reports a declaration without entries or with
	// more than MaxPerimeterEntriesPerRequest. A *PerimeterEntryCountError
	// matches it and ErrValidation.
	ErrPerimeterEntryCount = errors.New("perimeter declaration has too few or too many entries")
)

// PerimeterSeed is one declared range of a unit. Value is the canonical
// CIDR: host bits masked, and a bare address as a /32 or /128.
type PerimeterSeed struct {
	ID          string    `json:"id"`
	Kind        string    `json:"kind"`
	Value       string    `json:"value"`
	Label       string    `json:"label"`
	Source      string    `json:"source"`
	AdoptedFrom string    `json:"adopted_from"`
	CreatedAt   time.Time `json:"created_at"`
	CreatedBy   string    `json:"created_by"`
}

// PerimeterEntry is one range of a declaration, as the console sends it.
type PerimeterEntry struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
	Label string `json:"label"`
}

// PerimeterDeclareResult counts the ranges a declaration created and the
// entries it skipped because their value was already declared under the same
// kind, stored or earlier in the same declaration.
type PerimeterDeclareResult struct {
	Created int `json:"created"`
	Skipped int `json:"skipped"`
}

// PerimeterLineError is the refusal of one entry of a declaration. Index is
// the entry's position in the declaration, Value the value as submitted, cut
// to 64 bytes, and Reason a fixed text.
type PerimeterLineError struct {
	Index  int    `json:"index"`
	Value  string `json:"value"`
	Reason string `json:"reason"`
}

// PerimeterValidationError refuses a declaration with at least one invalid
// entry. It lists every refused entry in the order of the declaration, and
// matches ErrValidation. Nothing of the declaration is written.
type PerimeterValidationError struct {
	Entries []PerimeterLineError
}

func (e *PerimeterValidationError) Error() string {
	return fmt.Sprintf("perimeter declaration refused: %d invalid entries", len(e.Entries))
}

func (e *PerimeterValidationError) Is(target error) bool { return target == ErrValidation }

// PerimeterLimitError refuses a declaration that would leave the unit with
// more than Limit ranges. Held counts the ranges the unit held before the
// declaration and New those the declaration would have created. It matches
// ErrPerimeterLimit and ErrValidation, and nothing of the declaration is
// written.
type PerimeterLimitError struct {
	Limit int `json:"limit"`
	Held  int `json:"held"`
	New   int `json:"new"`
}

func (e *PerimeterLimitError) Error() string {
	return fmt.Sprintf("a business unit holds at most %d perimeter ranges: it holds %d and the declaration adds %d", e.Limit, e.Held, e.New)
}

func (e *PerimeterLimitError) Is(target error) bool {
	return target == ErrPerimeterLimit || target == ErrValidation
}

// PerimeterEntryCountError refuses a declaration with Count entries, which is
// none or more than Limit. It matches ErrPerimeterEntryCount and
// ErrValidation.
type PerimeterEntryCountError struct {
	Count int `json:"count"`
	Limit int `json:"limit"`
}

func (e *PerimeterEntryCountError) Error() string {
	return fmt.Sprintf("declare between 1 and %d entries", e.Limit)
}

func (e *PerimeterEntryCountError) Is(target error) bool {
	return target == ErrPerimeterEntryCount || target == ErrValidation
}

// perimeterSeedColumns are the columns that scanPerimeterSeed reads.
const perimeterSeedColumns = `id,kind,value,label,source,adopted_from,created_at,created_by`

// scanPerimeterSeed reads the columns of perimeterSeedColumns.
func scanPerimeterSeed(scan func(...any) error) (PerimeterSeed, error) {
	var seed PerimeterSeed
	var created string
	if err := scan(&seed.ID, &seed.Kind, &seed.Value, &seed.Label, &seed.Source, &seed.AdoptedFrom, &created, &seed.CreatedBy); err != nil {
		return PerimeterSeed{}, err
	}
	seed.CreatedAt = scanTime(created)
	return seed, nil
}

// ListPerimeterSeeds returns the unit's declared ranges, never nil without an
// error, in address order: IPv4 before IPv6, then by address, the shorter
// prefix first, then by kind and ID. A value that is not a CIDR, such as an
// ASN, follows the ranges in the order of its text.
func (ts *TenantStore) ListPerimeterSeeds(ctx context.Context) ([]PerimeterSeed, error) {
	if err := ts.ready(); err != nil {
		return nil, err
	}
	rows, err := ts.store.reader().QueryContext(ctx, `SELECT `+perimeterSeedColumns+` FROM perimeter_seeds WHERE tenant_id=? ORDER BY id`, ts.scope.id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	seeds := []PerimeterSeed{}
	for rows.Next() {
		seed, err := scanPerimeterSeed(rows.Scan)
		if err != nil {
			return nil, err
		}
		seeds = append(seeds, seed)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sortPerimeterSeeds(seeds)
	return seeds, nil
}

// sortPerimeterSeeds puts seeds in the order that ListPerimeterSeeds
// documents.
func sortPerimeterSeeds(seeds []PerimeterSeed) {
	type keyed struct {
		seed   PerimeterSeed
		prefix netip.Prefix
		ok     bool
	}
	keys := make([]keyed, len(seeds))
	for i, seed := range seeds {
		prefix, err := netip.ParsePrefix(seed.Value)
		keys[i] = keyed{seed: seed, prefix: prefix, ok: err == nil}
	}
	slices.SortFunc(keys, func(a, b keyed) int {
		var order int
		switch {
		case a.ok && b.ok:
			order = cmp.Or(a.prefix.Addr().Compare(b.prefix.Addr()), cmp.Compare(a.prefix.Bits(), b.prefix.Bits()))
		case a.ok:
			return -1
		case b.ok:
			return 1
		default:
			order = strings.Compare(a.seed.Value, b.seed.Value)
		}
		return cmp.Or(order, strings.Compare(a.seed.Kind, b.seed.Kind), strings.Compare(a.seed.ID, b.seed.ID))
	})
	for i := range keys {
		seeds[i] = keys[i].seed
	}
}

// GetPerimeterSeed returns one of the unit's declared ranges. An unknown ID
// and another unit's ID are both ErrNotFound, with an error that does not
// name the ID.
func (ts *TenantStore) GetPerimeterSeed(ctx context.Context, id string) (PerimeterSeed, error) {
	if err := ts.ready(); err != nil {
		return PerimeterSeed{}, err
	}
	seed, err := scanPerimeterSeed(ts.store.reader().QueryRowContext(ctx, `SELECT `+perimeterSeedColumns+` FROM perimeter_seeds WHERE id=? AND tenant_id=?`, id, ts.scope.id).Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return PerimeterSeed{}, ErrNotFound
	}
	if err != nil {
		return PerimeterSeed{}, err
	}
	return seed, nil
}

// ListJobSilenceReferences returns, by job ID, for each unarchived job of the
// unit, the later of its job_silence_state.eligible_at and last_success_at,
// which is the reference the job-silent watchdog measures the job from
// besides the job's created_at (see jobSilenceReferenceQuery). Creating,
// resuming or restoring a job sets eligible_at; each successful scan sets
// last_success_at to its finish, so it stands for the latest successful scan
// that the watchdog also reads, even after retention removes that scan. A job
// without silence state, or whose state holds neither time, is absent. The
// map is never nil without an error.
func (ts *TenantStore) ListJobSilenceReferences(ctx context.Context) (map[string]time.Time, error) {
	if err := ts.ready(); err != nil {
		return nil, err
	}
	rows, err := ts.store.reader().QueryContext(ctx, `SELECT s.job_id,s.eligible_at,s.last_success_at FROM job_silence_state AS s JOIN jobs AS j ON j.id=s.job_id AND j.tenant_id=? WHERE j.archived=0`, ts.scope.id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	references := map[string]time.Time{}
	for rows.Next() {
		var jobID, eligible, lastSuccess string
		if err := rows.Scan(&jobID, &eligible, &lastSuccess); err != nil {
			return nil, err
		}
		reference := scanTime(eligible)
		if success := scanTime(lastSuccess); success.After(reference) {
			reference = success
		}
		if !reference.IsZero() {
			references[jobID] = reference
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return references, nil
}

// perimeterSeedDraft is a distinct range of a declaration.
type perimeterSeedDraft struct {
	kind, value, label string
}

// perimeterDeclaration is a validated declaration.
type perimeterDeclaration struct {
	// seeds holds each distinct range once, in the order of its first entry,
	// with that entry's label.
	seeds []perimeterSeedDraft
	// indexes maps each canonical value to the entries that declare it.
	indexes map[string][]int
	// submitted holds each entry's value as submitted, trimmed.
	submitted []string
	// requested counts the entries of each kind.
	requested map[string]int
}

// validatePerimeterEntries canonicalizes the entries and refuses every
// invalid one, in the order of the declaration: an unknown kind or an ASN, a
// value that is not an allowed IP address or CIDR, an invalid label, and a
// value that an earlier entry declares under the other kind. Repeats under
// the same kind are not refused; they are skipped when the declaration is
// written.
func validatePerimeterEntries(entries []PerimeterEntry) (perimeterDeclaration, []PerimeterLineError) {
	declaration := perimeterDeclaration{indexes: map[string][]int{}, submitted: make([]string, len(entries)), requested: map[string]int{}}
	// kinds holds the kind of the first entry with each canonical value,
	// refused or not, so a conflict is reported even beside another refusal.
	kinds := map[string]string{}
	var refused []PerimeterLineError
	for index, entry := range entries {
		value := strings.TrimSpace(entry.Value)
		declaration.submitted[index] = value
		refuse := func(reason string) {
			refused = append(refused, PerimeterLineError{Index: index, Value: perimeterLineValue(value), Reason: reason})
		}
		switch entry.Kind {
		case PerimeterKindPrefix, PerimeterKindAuthorized:
		case PerimeterKindASN:
			refuse(perimeterReasonASN)
			continue
		default:
			refuse(perimeterReasonKind)
			continue
		}
		prefix, reason := parsePerimeterPrefix(value)
		if reason != "" {
			refuse(reason)
			continue
		}
		canonical := prefix.String()
		first, seen := kinds[canonical]
		if !seen {
			kinds[canonical] = entry.Kind
		}
		label := trimPerimeterLabelWhitespace(entry.Label)
		if reason := perimeterLabelReason(label); reason != "" {
			refuse(reason)
			continue
		}
		if seen && first != entry.Kind {
			refuse(perimeterDeclaredReason(first))
			continue
		}
		if _, added := declaration.indexes[canonical]; !added {
			declaration.seeds = append(declaration.seeds, perimeterSeedDraft{kind: entry.Kind, value: canonical, label: label})
		}
		declaration.indexes[canonical] = append(declaration.indexes[canonical], index)
		declaration.requested[entry.Kind]++
	}
	return declaration, refused
}

// parsePerimeterPrefix returns the canonical prefix of a declared value, or
// the reason it is refused. A bare address is a /32 or /128, and the host
// bits of a CIDR are masked.
func parsePerimeterPrefix(value string) (netip.Prefix, string) {
	address, _, hasBits := strings.Cut(value, "/")
	addr, err := netip.ParseAddr(address)
	if err != nil {
		return netip.Prefix{}, perimeterReasonValue
	}
	// net/netip accepts a zone on an IPv6 address, which neither the
	// scanner nor config validation does.
	if addr.Zone() != "" {
		return netip.Prefix{}, perimeterReasonZone
	}
	prefix := netip.PrefixFrom(addr, addr.BitLen())
	if hasBits {
		if prefix, err = netip.ParsePrefix(value); err != nil {
			return netip.Prefix{}, perimeterReasonValue
		}
	}
	prefix = prefix.Masked()
	// The special ranges come first, so a short prefix that also covers one,
	// such as 224.0.0.0/4 or fe80::/10, gets the more specific reason.
	for _, special := range perimeterSpecialRanges {
		if prefix.Overlaps(special.prefix) {
			return netip.Prefix{}, special.reason
		}
	}
	switch {
	case prefix.Addr().Is4() && prefix.Bits() < 8:
		return netip.Prefix{}, perimeterReasonIPv4Short
	case prefix.Addr().Is6() && prefix.Bits() < 16:
		return netip.Prefix{}, perimeterReasonIPv6Short
	case prefix.Overlaps(perimeterMappedPrefix):
		return netip.Prefix{}, perimeterReasonMapped
	}
	return prefix, ""
}

// trimPerimeterLabelWhitespace preserves control characters the label
// validator must reject while trimming other leading and trailing Unicode
// whitespace.
func trimPerimeterLabelWhitespace(label string) string {
	return strings.TrimFunc(label, func(r rune) bool {
		return unicode.IsSpace(r) && !unicode.IsControl(r)
	})
}

// perimeterLabelReason returns the reason a label is refused, or "".
func perimeterLabelReason(label string) string {
	switch {
	case !utf8.ValidString(label):
		return perimeterReasonLabelEncoding
	case utf8.RuneCountInString(label) > MaxPerimeterLabelRunes:
		return perimeterReasonLabelLength
	case strings.ContainsFunc(label, unicode.IsControl):
		return perimeterReasonLabelControl
	}
	return ""
}

// perimeterDeclaredReason refuses a value that is declared under kind.
func perimeterDeclaredReason(kind string) string {
	if kind == PerimeterKindAuthorized {
		return perimeterReasonAuthorized
	}
	return perimeterReasonOwned
}

// perimeterLineValue cuts a refused value to perimeterLineValueBytes, at
// the start of a character, so a refusal never echoes a long value.
func perimeterLineValue(value string) string {
	if len(value) <= perimeterLineValueBytes {
		return value
	}
	cut := perimeterLineValueBytes
	for cut > 0 && !utf8.RuneStart(value[cut]) {
		cut--
	}
	return value[:cut]
}

// DeclarePerimeterSeeds adds ranges to the unit's perimeter, all or nothing:
//
//  1. a declaration of no entries or more than MaxPerimeterEntriesPerRequest
//     is a *PerimeterEntryCountError;
//  2. every entry is canonicalized and validated;
//  3. a value that the unit holds under the other kind refuses each entry
//     that declares it, read in the write transaction when step 2 refused
//     nothing; the refusals of steps 2 and 3 are merged into one
//     *PerimeterValidationError that lists every refused entry in the order
//     of the declaration;
//  4. each distinct range is inserted once; a range the unit already holds
//     under the same kind, like a repeat within the declaration, is
//     skipped, and keeps its own label;
//  5. when the declaration created ranges and the unit then holds more than
//     MaxPerimeterRanges prefix and authorized ranges, the transaction rolls
//     back with a *PerimeterLimitError;
//  6. one audit record, with the counts by kind, is written in the same
//     transaction, so a range is never stored without it.
//
// A declaration whose entries were all skipped changes no range but still
// writes its audit record, as every accepted write of the console does; the
// record's counts show that nothing was added. The record's action and
// detail are set here; the caller's entry names the actor, whose username is
// also stored as each range's created_by.
func (ts *TenantStore) DeclarePerimeterSeeds(ctx context.Context, entries []PerimeterEntry, audit AuditEntry) (PerimeterDeclareResult, error) {
	if err := ts.ready(); err != nil {
		return PerimeterDeclareResult{}, err
	}
	if len(entries) == 0 || len(entries) > MaxPerimeterEntriesPerRequest {
		return PerimeterDeclareResult{}, &PerimeterEntryCountError{Count: len(entries), Limit: MaxPerimeterEntriesPerRequest}
	}
	declaration, refused := validatePerimeterEntries(entries)
	if len(refused) > 0 {
		// Nothing is written, so the stored conflicts of the entries that
		// passed are read without the write lock, to report every refusal at
		// once. Only those entries are in declaration.indexes, so no entry is
		// refused twice.
		stored, err := ts.storedPerimeterConflicts(ctx, ts.store.reader(), declaration)
		if err != nil {
			return PerimeterDeclareResult{}, err
		}
		refused = append(refused, stored...)
		slices.SortFunc(refused, func(a, b PerimeterLineError) int { return cmp.Compare(a.Index, b.Index) })
		return PerimeterDeclareResult{}, &PerimeterValidationError{Entries: refused}
	}
	tx, err := beginWriteTx(ctx, ts.store.DB)
	if err != nil {
		return PerimeterDeclareResult{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if err := requireActiveTenantTx(ctx, tx, ts.scope.id); err != nil {
		return PerimeterDeclareResult{}, err
	}
	refused, err = ts.storedPerimeterConflicts(ctx, tx, declaration)
	if err != nil {
		return PerimeterDeclareResult{}, err
	}
	if len(refused) > 0 {
		return PerimeterDeclareResult{}, &PerimeterValidationError{Entries: refused}
	}
	now := time.Now().UTC()
	stamp := sqliteTimestamp(now)
	insert, err := tx.PrepareContext(ctx, `INSERT INTO perimeter_seeds(id,tenant_id,kind,value,label,source,created_at,created_by) VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(tenant_id,kind,value) DO NOTHING`)
	if err != nil {
		return PerimeterDeclareResult{}, err
	}
	defer insert.Close()
	created := map[string]int{}
	for _, seed := range declaration.seeds {
		outcome, err := insert.ExecContext(ctx, uuid.NewString(), ts.scope.id, seed.kind, seed.value, seed.label, perimeterSourceDeclared, stamp, audit.ActorUsername)
		if err != nil {
			return PerimeterDeclareResult{}, err
		}
		inserted, err := outcome.RowsAffected()
		if err != nil {
			return PerimeterDeclareResult{}, err
		}
		created[seed.kind] += int(inserted)
	}
	result := PerimeterDeclareResult{Created: created[PerimeterKindPrefix] + created[PerimeterKindAuthorized]}
	result.Skipped = len(entries) - result.Created
	var held int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM perimeter_seeds WHERE tenant_id=? AND kind IN (?,?)`, ts.scope.id, PerimeterKindPrefix, PerimeterKindAuthorized).Scan(&held); err != nil {
		return PerimeterDeclareResult{}, err
	}
	if result.Created > 0 && held > MaxPerimeterRanges {
		return PerimeterDeclareResult{}, &PerimeterLimitError{Limit: MaxPerimeterRanges, Held: held - result.Created, New: result.Created}
	}
	audit.Action = auditPerimeterSeedsAdded
	audit.Detail = fmt.Sprintf("perimeter ranges declared: prefix %d added, %d skipped; authorized %d added, %d skipped",
		created[PerimeterKindPrefix], declaration.requested[PerimeterKindPrefix]-created[PerimeterKindPrefix],
		created[PerimeterKindAuthorized], declaration.requested[PerimeterKindAuthorized]-created[PerimeterKindAuthorized])
	if err := ts.insertAuditEntry(ctx, tx, audit, now); err != nil {
		return PerimeterDeclareResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return PerimeterDeclareResult{}, err
	}
	return result, nil
}

// storedPerimeterConflicts refuses each entry of the declaration whose value
// the unit already holds under the other kind, in the order of the
// declaration. The values of a validated declaration each have one kind.
func (ts *TenantStore) storedPerimeterConflicts(ctx context.Context, queryer interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}, declaration perimeterDeclaration) ([]PerimeterLineError, error) {
	declared := make(map[string]string, len(declaration.seeds))
	values := make([]string, 0, len(declaration.seeds))
	for _, seed := range declaration.seeds {
		declared[seed.value] = seed.kind
		values = append(values, seed.value)
	}
	raw, err := json.Marshal(values)
	if err != nil {
		return nil, err
	}
	rows, err := queryer.QueryContext(ctx, `SELECT p.kind,p.value FROM perimeter_seeds AS p WHERE p.tenant_id=? AND p.kind IN (?,?) AND p.value IN (SELECT j.value FROM json_each(?) AS j)`, ts.scope.id, PerimeterKindPrefix, PerimeterKindAuthorized, string(raw))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var refused []PerimeterLineError
	for rows.Next() {
		var kind, value string
		if err := rows.Scan(&kind, &value); err != nil {
			return nil, err
		}
		if declared[value] == kind {
			continue
		}
		for _, index := range declaration.indexes[value] {
			refused = append(refused, PerimeterLineError{Index: index, Value: perimeterLineValue(declaration.submitted[index]), Reason: perimeterDeclaredReason(kind)})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	slices.SortFunc(refused, func(a, b PerimeterLineError) int { return cmp.Compare(a.Index, b.Index) })
	return refused, nil
}

// DeletePerimeterSeed removes one of the unit's declared ranges and writes
// one audit record with its kind and canonical value in the same
// transaction. An unknown ID and another unit's ID are both ErrNotFound,
// and change nothing. The record's action and detail are set here; the
// caller's entry names the actor.
func (ts *TenantStore) DeletePerimeterSeed(ctx context.Context, id string, audit AuditEntry) error {
	if err := ts.ready(); err != nil {
		return err
	}
	tx, err := ts.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var kind, value string
	err = tx.QueryRowContext(ctx, `DELETE FROM perimeter_seeds WHERE id=? AND tenant_id=? RETURNING kind,value`, id, ts.scope.id).Scan(&kind, &value)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	audit.Action, audit.Detail = auditPerimeterSeedRemoved, fmt.Sprintf("perimeter range removed: %s %s", kind, value)
	if err := ts.insertAuditEntry(ctx, tx, audit, now); err != nil {
		return err
	}
	return tx.Commit()
}
