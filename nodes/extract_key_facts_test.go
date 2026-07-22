package nodes_test

import (
	"context"
	"testing"

	gen "christiangeorgelucas/whois-tools/gen"
	"christiangeorgelucas/whois-tools/nodes"
)

func TestExtractKeyFacts_WithAsOf(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)

	record := &gen.RegistrationRecord{
		DomainName:     "example.com",
		ExpirationDate: "2026-08-01T00:00:00Z",
		NameServers:    []string{"ns1.example.com", "ns2.example.com"},
		Registrar:      &gen.Contact{Name: "Example Registrar"},
	}

	got, err := nodes.ExtractKeyFacts(ctx, ax, &gen.ExtractKeyFactsInput{Record: record, AsOf: "2026-07-22"})
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if got.GetError() != nil {
		t.Fatalf("unexpected structured error: %+v", got.GetError())
	}

	if got.GetDomainName() != "example.com" {
		t.Errorf("DomainName = %q", got.GetDomainName())
	}
	if got.GetRegistrarName() != "Example Registrar" {
		t.Errorf("RegistrarName = %q", got.GetRegistrarName())
	}
	if len(got.GetNameServers()) != 2 {
		t.Errorf("NameServers = %v", got.GetNameServers())
	}
	if !got.GetHasExpiryComputation() {
		t.Fatal("HasExpiryComputation = false, want true")
	}
	// Independent hand computation: 2026-07-22 -> 2026-08-01 is exactly
	// 10 days (9 days to reach Jul 31, +1 more to Aug 1).
	if got.GetDaysUntilExpiry() != 10 {
		t.Errorf("DaysUntilExpiry = %d, want 10", got.GetDaysUntilExpiry())
	}
	if got.GetIsExpired() {
		t.Errorf("IsExpired = true, want false")
	}
}

func TestExtractKeyFacts_Expired(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)

	record := &gen.RegistrationRecord{DomainName: "expired.example", ExpirationDate: "2020-01-01"}
	got, err := nodes.ExtractKeyFacts(ctx, ax, &gen.ExtractKeyFactsInput{Record: record, AsOf: "2026-07-22"})
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if !got.GetHasExpiryComputation() {
		t.Fatal("HasExpiryComputation = false, want true")
	}
	if !got.GetIsExpired() {
		t.Errorf("IsExpired = false, want true for a domain that expired in 2020")
	}
	if got.GetDaysUntilExpiry() >= 0 {
		t.Errorf("DaysUntilExpiry = %d, want negative", got.GetDaysUntilExpiry())
	}
}

// TestExtractKeyFacts_NoAsOf proves this node never reads the wall clock:
// omitting as_of yields every fact except the two that need "now", not an
// error and not a value computed from real time.
func TestExtractKeyFacts_NoAsOf(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)

	record := &gen.RegistrationRecord{DomainName: "example.com", ExpirationDate: "2026-08-01"}
	got, err := nodes.ExtractKeyFacts(ctx, ax, &gen.ExtractKeyFactsInput{Record: record})
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if got.GetError() != nil {
		t.Fatalf("unexpected structured error: %+v", got.GetError())
	}
	if got.GetHasExpiryComputation() {
		t.Errorf("HasExpiryComputation = true, want false when as_of is omitted")
	}
	if got.GetDomainName() != "example.com" || got.GetExpirationDate() != "2026-08-01" {
		t.Errorf("unexpected base facts: %+v", got)
	}
}

func TestExtractKeyFacts_UnparseableAsOf(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)

	record := &gen.RegistrationRecord{DomainName: "example.com", ExpirationDate: "2026-08-01"}
	got, err := nodes.ExtractKeyFacts(ctx, ax, &gen.ExtractKeyFactsInput{Record: record, AsOf: "not-a-date"})
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if got.GetError() != nil {
		t.Fatalf("an unparseable as_of should degrade gracefully, not error: %+v", got.GetError())
	}
	if got.GetHasExpiryComputation() {
		t.Errorf("HasExpiryComputation = true, want false for an unparseable as_of")
	}
}

func TestExtractKeyFacts_EmptyRecord(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)

	got, err := nodes.ExtractKeyFacts(ctx, ax, &gen.ExtractKeyFactsInput{Record: &gen.RegistrationRecord{}})
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if got.GetError() == nil || got.GetError().GetCode() != "EMPTY_INPUT" {
		t.Fatalf("Error = %+v, want EMPTY_INPUT", got.GetError())
	}
}

func TestExtractKeyFacts_NilRecord(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)

	got, err := nodes.ExtractKeyFacts(ctx, ax, &gen.ExtractKeyFactsInput{})
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if got.GetError() == nil || got.GetError().GetCode() != "EMPTY_INPUT" {
		t.Fatalf("Error = %+v, want EMPTY_INPUT", got.GetError())
	}
}
