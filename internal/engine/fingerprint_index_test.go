package engine

import (
	"reflect"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/model"
)

func TestBaselineIndexesPreserveLinearLookupAndMutationSemantics(t *testing.T) {
	baseline := model.Snapshot{
		Scopes: []model.Scope{
			{Target: "edge.example", Protocol: "tcp", Ports: "80,443"},
			{Target: "edge.example", Protocol: "tcp", Ports: "443", ServiceDetection: true},
			{Target: "edge.example", Protocol: "udp", Ports: "443", ServiceDetection: true},
			{Target: "other.example", Protocol: "tcp", Ports: "443", ServiceDetection: true},
		},
		Units: []model.Unit{
			{Target: "edge.example", Protocol: "tcp", Ports: []model.PortState{
				{Port: 443, State: "open"},
				{Port: 443, State: "closed", Service: "later-port"},
			}},
			{Target: "edge.example", Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: "filtered", Service: "later-unit"}}},
			{Target: "edge.example", Protocol: "udp", Ports: []model.PortState{{Port: 443, State: "open", Service: "udp-service"}}},
		},
	}
	index := newBaselineIndex(baseline)

	for _, query := range []struct {
		target, protocol string
		port             int
		service          bool
	}{
		{"edge.example", "tcp", 80, false},
		{"edge.example", "tcp", 443, false},
		{"edge.example", "tcp", 443, true},
		{"edge.example", "tcp", 53, true},
		{"edge.example", "udp", 443, true},
		{"edge.example", "UDP", 443, true},
		{"other.example", "tcp", 443, true},
		{"missing.example", "tcp", 443, true},
	} {
		want := scopeAllows(baseline, query.target, query.protocol, query.port, query.service)
		if got := index.scopes.allows(query.target, query.protocol, query.port, query.service); got != want {
			t.Errorf("scope lookup (%q, %q, %d, service=%t) = %t, want %t", query.target, query.protocol, query.port, query.service, got, want)
		}
	}

	for _, query := range []struct {
		target, protocol string
		port             int
	}{
		{"edge.example", "tcp", 443},
		{"edge.example", "udp", 443},
		{"edge.example", "tcp", 80},
		{"other.example", "tcp", 443},
	} {
		want, wantOK := baselinePort(baseline, query.target, query.protocol, query.port)
		got, gotOK := index.baselinePort(baseline, query.target, query.protocol, query.port)
		if gotOK != wantOK || !reflect.DeepEqual(got, want) {
			t.Errorf("baseline lookup (%q, %q, %d) = %#v, %t; want %#v, %t", query.target, query.protocol, query.port, got, gotOK, want, wantOK)
		}
	}

	indexedMutation := cloneSnapshot(baseline)
	linearMutation := cloneSnapshot(baseline)
	for _, mutation := range []struct {
		target, protocol string
		port             int
		service          string
	}{
		{"edge.example", "tcp", 443, "learned"},
		// The first TCP port now has this value; first-match behavior means a
		// later duplicate is not changed merely because it differs.
		{"edge.example", "tcp", 443, "learned"},
		{"edge.example", "udp", 443, "udp-learned"},
		{"edge.example", "tcp", 80, "absent"},
	} {
		got := index.setBaselineService(&indexedMutation, mutation.target, mutation.protocol, mutation.port, mutation.service)
		want := setBaselineService(&linearMutation, mutation.target, mutation.protocol, mutation.port, mutation.service)
		if got != want {
			t.Errorf("mutation (%q, %q, %d) changed = %t, want %t", mutation.target, mutation.protocol, mutation.port, got, want)
		}
	}
	if !reflect.DeepEqual(indexedMutation, linearMutation) {
		t.Fatalf("indexed mutation differs from first-match linear mutation:\nindexed: %#v\nlinear: %#v", indexedMutation, linearMutation)
	}
}

func TestIndexedFingerprintLearningKeepsOverlappingScopeAndProtocolSemantics(t *testing.T) {
	baseline := model.Snapshot{
		Scopes: []model.Scope{
			{Target: "edge.example", Protocol: "tcp", Ports: "443", ServiceDetection: false},
			{Target: "edge.example", Protocol: "tcp", Ports: "443", ServiceDetection: true},
			{Target: "edge.example", Protocol: "udp", Ports: "443", ServiceDetection: true},
		},
		Units: []model.Unit{
			{Target: "edge.example", Protocol: "tcp", Ports: []model.PortState{
				{Port: 443, State: "open"},
				{Port: 443, State: "open", Service: "duplicate-port"},
			}},
			{Target: "edge.example", Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: "open", Service: "duplicate-unit"}}},
			{Target: "edge.example", Protocol: "udp", Ports: []model.PortState{{Port: 443, State: "open"}}},
		},
	}
	current := model.Snapshot{Units: []model.Unit{
		{Target: "edge.example", Protocol: "tcp", Ports: []model.PortState{{Port: 443, State: "open", Service: "https"}}},
		{Target: "edge.example", Protocol: "udp", Ports: []model.PortState{{Port: 443, State: "open", Service: "dns-tls"}}},
	}}
	tcpKey := fingerprintKey("edge.example", "tcp", 443)
	udpKey := fingerprintKey("edge.example", "udp", 443)
	state := model.JobState{
		Baseline:                &baseline,
		FingerprintCandidates:   map[string]model.ValueCount{tcpKey: {Value: "https", Count: 1}, udpKey: {Value: "dns-tls", Count: 1}},
		Incidents:               map[string]model.Incident{},
		Suppressed:              map[string]int{},
		ServiceDecisionRequired: map[string]bool{},
	}
	index := newBaselineIndex(baseline)
	if !fingerprintLearnableWithIndex(&state, "edge.example", "tcp", 443, index) || !fingerprintLearnableWithIndex(&state, "edge.example", "udp", 443, index) {
		t.Fatal("overlapping TCP service scope or separate UDP scope was not retained")
	}
	if fingerprintLearnableWithIndex(&state, "edge.example", "sctp", 443, index) {
		t.Fatal("fingerprint lookup crossed protocol scope")
	}

	learning := learnMissingFingerprintsWithIndex(&state, current, 2, index)
	if len(learning) != 0 {
		t.Fatalf("stable fingerprints remain in learning: %#v", learning)
	}
	if got := baselineService(*state.Baseline, "edge.example", "tcp", 443); got != "https" {
		t.Fatalf("first TCP baseline duplicate service = %q, want https", got)
	}
	if got := baselineService(*state.Baseline, "edge.example", "udp", 443); got != "dns-tls" {
		t.Fatalf("UDP baseline service = %q, want dns-tls", got)
	}
	if got := state.Baseline.Units[0].Ports[1].Service; got != "duplicate-port" {
		t.Fatalf("later duplicate TCP port changed to %q", got)
	}
	if got := state.Baseline.Units[1].Ports[0].Service; got != "duplicate-unit" {
		t.Fatalf("later duplicate TCP unit changed to %q", got)
	}
	if !state.BaselineModified {
		t.Fatal("learning the first matching baseline entries did not mark the baseline modified")
	}
}
