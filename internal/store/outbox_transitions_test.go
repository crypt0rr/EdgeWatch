package store

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestOutboxTransitionContractCoversSchema(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)
	rows, err := s.DB.QueryContext(context.Background(), `PRAGMA table_info(outbox)`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var actual []string
	for rows.Next() {
		var ordinal, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err := rows.Scan(&ordinal, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			t.Fatal(err)
		}
		actual = append(actual, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual, outboxTransitionColumns) {
		t.Fatalf("outbox schema columns = %v; contract columns = %v", actual, outboxTransitionColumns)
	}
	if err := outboxTransitionContractError(actual); err != nil {
		t.Fatalf("outbox transition contract is incomplete: %v", err)
	}
	if err := outboxTransitionContractError(append(append([]string(nil), actual...), "future_delivery_marker")); err == nil {
		t.Fatal("an outbox column added without a transition classification passed the contract")
	}
}

func TestOutboxTransitionContractRequiresIntentForNewColumns(t *testing.T) {
	columns := append(append([]string(nil), outboxTransitionColumns...), "future_delivery_marker")
	contracts := buildOutboxTransitionContracts()
	if err := validateOutboxTransitionContracts(columns, contracts); err == nil {
		t.Fatal("adding a schema-registry column without classifying it in every transition passed")
	}
}

func TestOutboxTransitionBuilderRejectsPreservedAndUnfencedWrites(t *testing.T) {
	if _, _, err := buildOutboxTransitionStatement(outboxClaimDue, `id=?`, []any{1},
		outboxChange("tenant_id", outboxSet, "?", DefaultTenantID),
	); err == nil {
		t.Fatal("claim transition wrote a tenant column classified as preserved")
	}
	if _, _, err := buildOutboxTransitionStatement(outboxClaimDue, `id=?`, []any{1},
		outboxChange("future_delivery_marker", outboxSet, "?", "x"),
	); err == nil {
		t.Fatal("transition builder accepted a column absent from the reviewed schema")
	}
	if _, _, err := buildOutboxTransitionStatement(outboxClaimDue, ``, nil,
		outboxChange("claim_token", outboxSet, "?", "owner"),
	); err == nil {
		t.Fatal("transition builder accepted an unfenced update")
	}
	if _, _, err := buildOutboxTransitionStatement(outboxClaimDue, `id=?`, []any{1},
		outboxChange("claim_token", outboxSet, "?", "owner"),
	); err == nil || !strings.Contains(err.Error(), "does not provide its transition expression") {
		t.Fatalf("transition builder omitted a classified assignment without error: %v", err)
	}
}

func TestOutboxTransitionBuilderRequiresExpressionForNewSetDisposition(t *testing.T) {
	contract := outboxTransitionContract{columns: map[string]outboxColumnDisposition{
		"future_delivery_marker": outboxSet,
	}}
	if err := validateOutboxTransitionChanges("future_transition", contract, nil); err == nil {
		t.Fatal("a new set disposition without a production assignment passed validation")
	}
}
