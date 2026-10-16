package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

// The ordered list is the schema contract for outbox transitions. Adding an
// outbox column requires a reviewed disposition in every named transition.
// TestOutboxTransitionContractCoversSchema binds this list to PRAGMA output.
var outboxTransitionColumns = []string{
	"id",
	"destination",
	"payload_json",
	"attempts",
	"next_at",
	"sent_at",
	"last_error",
	"claim_token",
	"claim_until",
	"deferrals",
	"terminal_at",
	"tenant_id",
	"event_type",
	"event_job_id",
	"change_window_id",
	"attempt_started_at",
	"coalesce_after_attempt",
	"coalesced_at",
}

type outboxTransitionName string

type outboxColumnDisposition string

const (
	outboxPreserve    outboxColumnDisposition = "preserve"
	outboxSet         outboxColumnDisposition = "set"
	outboxReset       outboxColumnDisposition = "reset"
	outboxConditional outboxColumnDisposition = "conditional"
)

type outboxTransitionContract struct {
	columns map[string]outboxColumnDisposition
	errors  []string
}

type outboxColumnChange struct {
	column      string
	disposition outboxColumnDisposition
	expression  string
	args        []any
}

const (
	outboxClaimDue            outboxTransitionName = "claim_due"
	outboxBeginAttempt        outboxTransitionName = "begin_attempt"
	outboxHoldInWindow        outboxTransitionName = "hold_in_window"
	outboxReleaseClaim        outboxTransitionName = "release_claim"
	outboxReleaseHeldClaim    outboxTransitionName = "release_held_claim"
	outboxCoalesceHeld        outboxTransitionName = "coalesce_held_change"
	outboxRecoverStartup      outboxTransitionName = "recover_startup_attempt"
	outboxRecoverExpired      outboxTransitionName = "recover_expired_attempt"
	outboxReleaseStartup      outboxTransitionName = "release_startup_claims"
	outboxRedeliverTerminal   outboxTransitionName = "redeliver_terminal"
	outboxAssignWindow        outboxTransitionName = "assign_pending_window"
	outboxClosePending        outboxTransitionName = "close_pending_window_row"
	outboxCloseInFlight       outboxTransitionName = "close_in_flight_window_row"
	outboxCloseOrphan         outboxTransitionName = "close_orphaned_window_row"
	outboxCancelPending       outboxTransitionName = "cancel_pending_window_row"
	outboxReleaseWindowAlerts outboxTransitionName = "release_alerts_without_summary_notification"
	outboxRenameDestination   outboxTransitionName = "rename_destination"
	outboxAgeLocked           outboxTransitionName = "age_locked_delivery"
	outboxWakeLocked          outboxTransitionName = "wake_locked_delivery"
	outboxInvalidPayload      outboxTransitionName = "invalid_payload_terminal"
	outboxCompleteSent        outboxTransitionName = "complete_sent_delivery"
	outboxCompleteCoalesced   outboxTransitionName = "complete_sent_after_coalesce"
	outboxCoalesceCompleted   outboxTransitionName = "coalesce_completed_attempt"
	outboxDeferIndeterminate  outboxTransitionName = "defer_indeterminate_delivery"
	outboxRecordSendFailure   outboxTransitionName = "record_send_failure"
	outboxCoalesceDeferred    outboxTransitionName = "coalesce_deferred_attempt"
	outboxKeepPending         outboxTransitionName = "keep_pending_after_credential_rotation"
	outboxMarkInflight        outboxTransitionName = "mark_in_flight_for_coalescing"
	outboxMoveTerminal        outboxTransitionName = "move_terminal_delivery_selector"
	outboxImportMerge         outboxTransitionName = "merge_imported_delivery_state"
	outboxImportMove          outboxTransitionName = "move_imported_delivery_selector"
)

// These identity and event-content columns do not change in any named delivery
// state transition. They are an explicit preserve group, not an implicit
// default: a new schema column must be classified in this group or separately
// in each transition before the schema contract can pass.
var outboxIdentityPreservedColumns = []string{
	"id",
	"payload_json",
	"tenant_id",
	"event_type",
	"event_job_id",
}

var outboxTransitionContracts = buildOutboxTransitionContracts()

func buildOutboxTransitionContracts() map[outboxTransitionName]outboxTransitionContract {
	contracts := map[outboxTransitionName]outboxTransitionContract{
		outboxClaimDue: transitionContractPreservingSentAt(
			[]string{"claim_token", "claim_until"}, nil, nil,
			[]string{"destination", "attempts", "next_at", "last_error", "deferrals", "terminal_at", "change_window_id", "attempt_started_at", "coalesce_after_attempt", "coalesced_at"},
		),
		outboxBeginAttempt: transitionContractPreservingSentAt(
			[]string{"attempt_started_at"}, nil, nil,
			[]string{"destination", "attempts", "next_at", "last_error", "claim_token", "claim_until", "deferrals", "terminal_at", "change_window_id", "coalesce_after_attempt", "coalesced_at"},
		),
		outboxHoldInWindow: transitionContractPreservingSentAt(
			[]string{"change_window_id", "next_at"}, []string{"last_error", "claim_token", "claim_until"}, nil,
			[]string{"destination", "attempts", "deferrals", "terminal_at", "attempt_started_at", "coalesce_after_attempt", "coalesced_at"},
		),
		outboxReleaseClaim: transitionContractPreservingSentAt(
			[]string{"next_at"}, []string{"claim_token", "claim_until", "attempt_started_at"}, nil,
			[]string{"destination", "attempts", "last_error", "deferrals", "terminal_at", "change_window_id", "coalesce_after_attempt", "coalesced_at"},
		),
		outboxReleaseHeldClaim: transitionContractPreservingSentAt(
			nil, []string{"last_error", "claim_token", "claim_until"}, nil,
			[]string{"destination", "attempts", "next_at", "deferrals", "terminal_at", "change_window_id", "attempt_started_at", "coalesce_after_attempt", "coalesced_at"},
		),
		outboxCoalesceHeld: transitionContractPreservingSentAt(
			nil, []string{"last_error", "claim_token", "claim_until"}, []string{"coalesced_at"},
			[]string{"destination", "attempts", "next_at", "deferrals", "terminal_at", "change_window_id", "attempt_started_at", "coalesce_after_attempt"},
		),
		outboxRecoverStartup: transitionContractPreservingSentAt(
			nil, []string{"claim_token", "claim_until"}, []string{"attempt_started_at", "coalesced_at", "last_error", "coalesce_after_attempt"},
			[]string{"destination", "attempts", "next_at", "deferrals", "terminal_at", "change_window_id"},
		),
		outboxRecoverExpired: transitionContractPreservingSentAt(
			nil, []string{"claim_token", "claim_until"}, []string{"attempt_started_at", "coalesced_at", "last_error", "coalesce_after_attempt"},
			[]string{"destination", "attempts", "next_at", "deferrals", "terminal_at", "change_window_id"},
		),
		outboxReleaseStartup: transitionContractPreservingSentAt(
			nil, []string{"claim_token", "claim_until"}, nil,
			[]string{"destination", "attempts", "next_at", "last_error", "deferrals", "terminal_at", "change_window_id", "attempt_started_at", "coalesce_after_attempt", "coalesced_at"},
		),
		outboxRedeliverTerminal: transitionContractPreservingSentAt(
			[]string{"destination", "next_at"}, []string{"attempts", "last_error", "claim_token", "claim_until", "deferrals", "terminal_at", "change_window_id", "attempt_started_at", "coalesce_after_attempt"}, nil,
			[]string{"coalesced_at"},
		),
		outboxAssignWindow: transitionContractPreservingSentAt(
			[]string{"change_window_id"}, nil, nil,
			[]string{"destination", "attempts", "next_at", "last_error", "claim_token", "claim_until", "deferrals", "terminal_at", "attempt_started_at", "coalesce_after_attempt", "coalesced_at"},
		),
		outboxClosePending: transitionContractPreservingSentAt(
			[]string{"coalesced_at"}, []string{"last_error", "claim_token", "claim_until"}, nil,
			[]string{"destination", "attempts", "next_at", "deferrals", "terminal_at", "change_window_id", "attempt_started_at", "coalesce_after_attempt"},
		),
		outboxCloseInFlight: transitionContractPreservingSentAt(
			[]string{"coalesce_after_attempt"}, nil, nil,
			[]string{"destination", "attempts", "next_at", "last_error", "claim_token", "claim_until", "deferrals", "terminal_at", "change_window_id", "attempt_started_at", "coalesced_at"},
		),
		outboxCloseOrphan: transitionContractPreservingSentAt(
			[]string{"coalesced_at"}, []string{"attempt_started_at", "coalesce_after_attempt", "last_error"}, nil,
			[]string{"destination", "attempts", "next_at", "claim_token", "claim_until", "deferrals", "terminal_at", "change_window_id"},
		),
		outboxCancelPending: transitionContractPreservingSentAt(
			nil, nil, []string{"change_window_id"},
			[]string{"destination", "attempts", "next_at", "last_error", "claim_token", "claim_until", "deferrals", "terminal_at", "coalesced_at", "attempt_started_at", "coalesce_after_attempt"},
		),
		outboxReleaseWindowAlerts: transitionContractPreservingSentAt(
			nil, nil, []string{"change_window_id", "claim_token", "claim_until"},
			[]string{"destination", "attempts", "next_at", "last_error", "deferrals", "terminal_at", "attempt_started_at", "coalesce_after_attempt", "coalesced_at"},
		),
		outboxRenameDestination: transitionContractPreservingSentAt(
			[]string{"destination"}, nil, nil,
			[]string{"attempts", "next_at", "last_error", "claim_token", "claim_until", "deferrals", "terminal_at", "change_window_id", "attempt_started_at", "coalesce_after_attempt", "coalesced_at"},
		),
		outboxAgeLocked: transitionContractPreservingSentAt(
			[]string{"deferrals", "next_at", "last_error", "terminal_at"}, []string{"claim_token", "claim_until"}, nil,
			[]string{"destination", "attempts", "coalesce_after_attempt", "change_window_id", "attempt_started_at", "coalesced_at"},
		),
		outboxWakeLocked: transitionContractPreservingSentAt(
			[]string{"next_at"}, nil, nil,
			[]string{"destination", "attempts", "last_error", "claim_token", "claim_until", "deferrals", "terminal_at", "change_window_id", "attempt_started_at", "coalesce_after_attempt", "coalesced_at"},
		),
		outboxInvalidPayload: transitionContractPreservingSentAt(
			[]string{"terminal_at", "last_error"}, []string{"claim_token", "claim_until"}, nil,
			[]string{"destination", "attempts", "next_at", "deferrals", "change_window_id", "attempt_started_at", "coalesce_after_attempt", "coalesced_at"},
		),
		outboxCompleteSent: transitionContract(
			[]string{"sent_at"}, []string{"last_error", "claim_token", "claim_until", "attempt_started_at"}, nil,
			[]string{"destination", "attempts", "next_at", "deferrals", "terminal_at", "change_window_id", "coalesce_after_attempt", "coalesced_at"},
		),
		outboxCompleteCoalesced: transitionContract(
			[]string{"sent_at"}, []string{"last_error", "claim_token", "claim_until", "attempt_started_at", "coalesce_after_attempt"}, nil,
			[]string{"destination", "attempts", "next_at", "deferrals", "terminal_at", "change_window_id", "coalesced_at"},
		),
		outboxCoalesceCompleted: transitionContractPreservingSentAt(
			[]string{"coalesced_at"}, []string{"last_error", "claim_token", "claim_until", "attempt_started_at", "coalesce_after_attempt"}, nil,
			[]string{"destination", "attempts", "next_at", "deferrals", "terminal_at", "change_window_id"},
		),
		outboxDeferIndeterminate: transitionContractPreservingSentAt(
			[]string{"deferrals", "next_at", "last_error", "terminal_at"}, []string{"claim_token", "claim_until", "attempt_started_at"}, nil,
			[]string{"destination", "attempts", "change_window_id", "coalesce_after_attempt", "coalesced_at"},
		),
		outboxRecordSendFailure: transitionContractPreservingSentAt(
			[]string{"attempts", "next_at", "last_error", "terminal_at"}, []string{"claim_token", "claim_until", "attempt_started_at"}, nil,
			[]string{"destination", "deferrals", "change_window_id", "coalesce_after_attempt", "coalesced_at"},
		),
		outboxCoalesceDeferred: transitionContractPreservingSentAt(
			[]string{"coalesced_at"}, []string{"last_error", "claim_token", "claim_until", "attempt_started_at", "coalesce_after_attempt"}, nil,
			[]string{"destination", "attempts", "next_at", "deferrals", "terminal_at", "change_window_id"},
		),
		outboxKeepPending: transitionContractPreservingSentAt(
			[]string{"destination", "next_at"}, []string{"attempts", "deferrals", "last_error", "claim_token", "claim_until", "attempt_started_at"}, nil,
			[]string{"terminal_at", "change_window_id", "coalesce_after_attempt", "coalesced_at"},
		),
		outboxMarkInflight: transitionContractPreservingSentAt(
			[]string{"coalesce_after_attempt"}, nil, nil,
			[]string{"destination", "attempts", "next_at", "last_error", "claim_token", "claim_until", "deferrals", "terminal_at", "change_window_id", "attempt_started_at", "coalesced_at"},
		),
		outboxMoveTerminal: transitionContractPreservingSentAt(
			[]string{"destination"}, nil, nil,
			[]string{"attempts", "next_at", "last_error", "claim_token", "claim_until", "deferrals", "terminal_at", "change_window_id", "attempt_started_at", "coalesce_after_attempt", "coalesced_at"},
		),
		outboxImportMerge: transitionContractPreservingSentAt(
			[]string{"attempts", "deferrals", "next_at"}, nil, nil,
			[]string{"destination", "last_error", "claim_token", "claim_until", "terminal_at", "change_window_id", "attempt_started_at", "coalesce_after_attempt", "coalesced_at"},
		),
		outboxImportMove: transitionContractPreservingSentAt(
			[]string{"destination"}, nil, nil,
			[]string{"attempts", "next_at", "last_error", "claim_token", "claim_until", "deferrals", "terminal_at", "change_window_id", "attempt_started_at", "coalesce_after_attempt", "coalesced_at"},
		),
	}
	return contracts
}

func transitionContract(set, reset, conditional, preserve []string) outboxTransitionContract {
	columns := make(map[string]outboxColumnDisposition, len(outboxTransitionColumns))
	var contractErrors []string
	add := func(names []string, disposition outboxColumnDisposition) {
		for _, name := range names {
			if _, duplicate := columns[name]; duplicate {
				contractErrors = append(contractErrors, fmt.Sprintf("column %q has more than one disposition", name))
				continue
			}
			columns[name] = disposition
		}
	}
	add(outboxIdentityPreservedColumns, outboxPreserve)
	add(preserve, outboxPreserve)
	add(set, outboxSet)
	add(reset, outboxReset)
	add(conditional, outboxConditional)
	return outboxTransitionContract{columns: columns, errors: contractErrors}
}

// transitionContractPreservingSentAt names the common case for a delivery
// transition that does not finish the provider send. Transitions that set
// sent_at use transitionContract directly and classify that outcome column
// with their set list.
func transitionContractPreservingSentAt(set, reset, conditional, preserve []string) outboxTransitionContract {
	preserved := append(append([]string(nil), preserve...), "sent_at")
	return transitionContract(set, reset, conditional, preserved)
}

func outboxTransitionContractError(actualColumns []string) error {
	actual := make(map[string]struct{}, len(actualColumns))
	for _, column := range actualColumns {
		actual[column] = struct{}{}
	}
	for _, column := range outboxTransitionColumns {
		if _, ok := actual[column]; !ok {
			return fmt.Errorf("outbox schema is missing classified column %q", column)
		}
		delete(actual, column)
	}
	for column := range actual {
		return fmt.Errorf("outbox schema column %q has no transition classification", column)
	}
	return validateOutboxTransitionContracts(outboxTransitionColumns, outboxTransitionContracts)
}

func validateOutboxTransitionContracts(columns []string, contracts map[outboxTransitionName]outboxTransitionContract) error {
	if len(contracts) == 0 {
		return fmt.Errorf("outbox transition contract has no named transitions")
	}
	validDisposition := map[outboxColumnDisposition]bool{
		outboxPreserve: true, outboxSet: true, outboxReset: true, outboxConditional: true,
	}
	for name, contract := range contracts {
		if len(contract.errors) != 0 {
			return fmt.Errorf("outbox transition %q has an invalid classification: %s", name, strings.Join(contract.errors, "; "))
		}
		for _, column := range columns {
			disposition, ok := contract.columns[column]
			if !ok {
				return fmt.Errorf("outbox transition %q does not classify column %q", name, column)
			}
			if !validDisposition[disposition] {
				return fmt.Errorf("outbox transition %q has invalid disposition %q for column %q", name, disposition, column)
			}
		}
		for column := range contract.columns {
			found := false
			for _, expected := range columns {
				if column == expected {
					found = true
					break
				}
			}
			if !found {
				return fmt.Errorf("outbox transition %q classifies unknown column %q", name, column)
			}
		}
	}
	return nil
}

func outboxChange(column string, disposition outboxColumnDisposition, expression string, args ...any) outboxColumnChange {
	return outboxColumnChange{column: column, disposition: disposition, expression: expression, args: args}
}

// buildOutboxTransitionStatement validates assignments against the explicit
// per-transition classifications before assembling a production UPDATE.
func buildOutboxTransitionStatement(name outboxTransitionName, where string, whereArgs []any, changes ...outboxColumnChange) (string, []any, error) {
	contract, ok := outboxTransitionContracts[name]
	if !ok {
		return "", nil, fmt.Errorf("unknown outbox transition %q", name)
	}
	if strings.TrimSpace(where) == "" {
		return "", nil, fmt.Errorf("outbox transition %q requires a fenced predicate", name)
	}
	if len(changes) == 0 {
		return "", nil, fmt.Errorf("outbox transition %q has no assignments", name)
	}
	if err := validateOutboxTransitionChanges(name, contract, changes); err != nil {
		return "", nil, err
	}
	assignments := make([]string, 0, len(changes))
	args := make([]any, 0, len(whereArgs)+len(changes))
	for _, change := range changes {
		assignments = append(assignments, change.column+"="+change.expression)
		args = append(args, change.args...)
	}
	args = append(args, whereArgs...)
	query := "UPDATE outbox SET " + strings.Join(assignments, ",") + " WHERE " + where
	return query, args, nil
}

func validateOutboxTransitionChanges(name outboxTransitionName, contract outboxTransitionContract, changes []outboxColumnChange) error {
	seen := make(map[string]struct{}, len(changes))
	for _, change := range changes {
		if _, duplicate := seen[change.column]; duplicate {
			return fmt.Errorf("outbox transition %q assigns %q more than once", name, change.column)
		}
		seen[change.column] = struct{}{}
		classified, classifiedColumn := contract.columns[change.column]
		if !classifiedColumn || classified != change.disposition || change.disposition == outboxPreserve {
			return fmt.Errorf("outbox transition %q cannot %s column %q", name, change.disposition, change.column)
		}
		if strings.TrimSpace(change.expression) == "" {
			return fmt.Errorf("outbox transition %q has an empty expression for %q", name, change.column)
		}
	}
	for column, disposition := range contract.columns {
		if disposition == outboxPreserve {
			continue
		}
		if _, assigned := seen[column]; !assigned {
			return fmt.Errorf("outbox transition %q classifies %q as %s but does not provide its transition expression", name, column, disposition)
		}
	}
	return nil
}

// applyOutboxTransition is the only path used by named state transitions in
// this subsystem to execute an UPDATE. Unassigned columns are explicitly
// preserved by the named contract.
func applyOutboxTransition(ctx context.Context, execer contextExecer, name outboxTransitionName, where string, whereArgs []any, changes ...outboxColumnChange) (sql.Result, error) {
	query, args, err := buildOutboxTransitionStatement(name, where, whereArgs, changes...)
	if err != nil {
		return nil, err
	}
	return execer.ExecContext(ctx, query, args...)
}
