package scanner

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/crypt0rr/edgewatch/internal/config"
	"github.com/crypt0rr/edgewatch/internal/model"
)

type mappedResolver struct {
	answers map[string][]net.IP
	errors  map[string]error
}

func (r mappedResolver) LookupIP(_ context.Context, _, host string) ([]net.IP, error) {
	if err := r.errors[host]; err != nil {
		return r.answers[host], err
	}
	return r.answers[host], nil
}

func TestPlanRetainsResolvableTargetsWhenAnotherDNSLookupFails(t *testing.T) {
	n := New("missing-nmap")
	if err := n.SetTargetExclusions([]string{}); err != nil {
		t.Fatal(err)
	}
	n.Resolver = mappedResolver{
		answers: map[string][]net.IP{"good.example": {net.ParseIP("192.0.2.1")}},
		errors:  map[string]error{"missing.example": errors.New("temporary DNS failure")},
	}
	job := config.NormalizeJob(config.Job{
		Name: "mixed-dns", Targets: []string{"good.example", "missing.example"}, MaxExpandedHosts: 4,
		TCP: &config.Protocol{Ports: "443", Mode: "connect"},
	})

	plan, err := n.Plan(context.Background(), job)
	if err != nil {
		t.Fatalf("partial DNS failure prevented planning resolvable targets: %v", err)
	}
	if len(plan.Units) != 1 || !reflect.DeepEqual(plan.Units[0].Addresses, []string{"192.0.2.1"}) {
		t.Fatalf("planned units = %#v, want only the resolvable address", plan.Units)
	}
	if !reflect.DeepEqual(plan.TargetFailures, []model.TargetCoverageFailure{{Target: "missing.example", Reason: "lookup-failed"}}) {
		t.Fatalf("plan target failures = %#v", plan.TargetFailures)
	}
	if !reflect.DeepEqual(plan.Scopes, []model.Scope{
		{Target: "good.example", Protocol: "tcp", Ports: "443"},
		{Target: "missing.example", Protocol: "tcp", Ports: "443"},
	}) {
		t.Fatalf("plan scopes = %#v, want successful and unresolved configured targets", plan.Scopes)
	}
}

func TestNaabuPlanRetainsResolvableTargetsAndResolutionFailure(t *testing.T) {
	n := NewWithNaabu("missing-nmap", "missing-naabu")
	if err := n.SetTargetExclusions([]string{}); err != nil {
		t.Fatal(err)
	}
	n.Resolver = mappedResolver{
		answers: map[string][]net.IP{"good.example": {net.ParseIP("192.0.2.1")}},
		errors:  map[string]error{"missing.example": errors.New("temporary DNS failure")},
	}
	job := config.NormalizeJob(config.Job{
		Name: "mixed-naabu-plan", Targets: []string{"good.example", "missing.example"}, MaxExpandedHosts: 4,
		TCP: &config.Protocol{Engine: config.EngineNaabuNmap, Ports: config.NaabuFullPortExpression, Naabu: &config.NaabuOptions{ScanType: "connect"}},
	})

	plan, err := n.Plan(context.Background(), job)
	if err != nil {
		t.Fatalf("partial DNS failure prevented Naabu planning: %v", err)
	}
	if len(plan.Units) != 1 || plan.Units[0].Engine != config.EngineNaabuNmap || !reflect.DeepEqual(plan.Units[0].Addresses, []string{"192.0.2.1"}) {
		t.Fatalf("Naabu plan units = %#v", plan.Units)
	}
	if !reflect.DeepEqual(plan.TargetFailures, []model.TargetCoverageFailure{{Target: "missing.example", Reason: "lookup-failed"}}) {
		t.Fatalf("Naabu plan target failures = %#v", plan.TargetFailures)
	}
	if len(plan.Scopes) != 2 {
		t.Fatalf("Naabu plan scopes = %#v", plan.Scopes)
	}
}

func TestNaabuPipelineScansResolvableTargetsAndRetainsDNSFailure(t *testing.T) {
	dir := t.TempDir()
	naabuPath := filepath.Join(dir, "naabu")
	if err := os.WriteFile(naabuPath, []byte("#!/bin/sh\nprintf '%s\\n' '{\"ip\":\"192.0.2.1\",\"port\":22,\"protocol\":\"tcp\"}'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	nmapPath := filepath.Join(dir, "nmap")
	if err := os.WriteFile(nmapPath, []byte("#!/bin/sh\nprintf '%s' '"+sampleXML+"'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	n := NewWithNaabu(nmapPath, naabuPath)
	if err := n.SetTargetExclusions([]string{}); err != nil {
		t.Fatal(err)
	}
	n.Resolver = mappedResolver{
		answers: map[string][]net.IP{"good.example": {net.ParseIP("192.0.2.1")}},
		errors:  map[string]error{"missing.example": errors.New("temporary DNS failure")},
	}
	job := config.NormalizeJob(config.Job{
		Name: "mixed-naabu-dns", Targets: []string{"good.example", "missing.example"}, MaxExpandedHosts: 4,
		TCP: &config.Protocol{Engine: config.EngineNaabuNmap, Ports: config.NaabuFullPortExpression, Naabu: &config.NaabuOptions{ScanType: "connect"}},
	})

	snapshot, err := n.ScanWithProgress(context.Background(), job, nil)
	if err != nil {
		t.Fatalf("Naabu/Nmap pipeline did not scan the resolvable target: %v", err)
	}
	if len(snapshot.TargetFailures) != 1 || snapshot.TargetFailures[0].Target != "missing.example" {
		t.Fatalf("pipeline target failures = %#v", snapshot.TargetFailures)
	}
	if len(snapshot.Scopes) != 2 || len(snapshot.Units) != 1 || snapshot.Units[0].Target != "good.example" {
		t.Fatalf("pipeline result scopes/units = %#v / %#v", snapshot.Scopes, snapshot.Units)
	}
}

func TestNmapScansResolvableTargetAndRetainsDNSFailure(t *testing.T) {
	dir := t.TempDir()
	nmapPath := filepath.Join(dir, "nmap")
	if err := os.WriteFile(nmapPath, []byte("#!/bin/sh\nprintf '%s' '"+sampleXML+"'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	n := New(nmapPath)
	if err := n.SetTargetExclusions([]string{}); err != nil {
		t.Fatal(err)
	}
	n.Resolver = mappedResolver{
		answers: map[string][]net.IP{"good.example": {net.ParseIP("192.0.2.1")}},
		errors:  map[string]error{"missing.example": errors.New("temporary DNS failure")},
	}
	job := config.NormalizeJob(config.Job{
		Name: "mixed-dns", Targets: []string{"good.example", "missing.example"}, MaxExpandedHosts: 4,
		TCP: &config.Protocol{Ports: "22,443", Mode: "connect"},
	})

	snapshot, err := n.ScanWithProgress(context.Background(), job, nil)
	if err != nil {
		t.Fatalf("resolvable target was not scanned: %v", err)
	}
	if len(snapshot.Units) != 1 || snapshot.Units[0].Target != "good.example" || len(snapshot.Units[0].Ports) != 1 {
		t.Fatalf("partial scan units = %#v", snapshot.Units)
	}
	if len(snapshot.Scopes) != 2 || snapshot.Scopes[0].Target != "good.example" || snapshot.Scopes[1].Target != "missing.example" {
		t.Fatalf("partial scan scopes = %#v", snapshot.Scopes)
	}
}
