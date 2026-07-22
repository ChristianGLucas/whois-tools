package nodes_test

import (
	"context"
	"strings"
	"testing"

	gen "christiangeorgelucas/whois-tools/gen"
	"christiangeorgelucas/whois-tools/nodes"
)

// googleComWhois is the real WHOIS response for google.com, taken verbatim
// from likexian/whois-parser's own test fixture
// (testdata/noterror/com_google.com) — chosen because it is real registry
// output, not a fixture we invented, and every field asserted below was
// independently re-read off this raw text by hand (not just copied from
// the library's expected-output fixture) to serve as an oracle independent
// of the library's own implementation.
const googleComWhois = `Domain Name: google.com
Registry Domain ID: 2138514_DOMAIN_COM-VRSN
Registrar WHOIS Server: whois.markmonitor.com
Registrar URL: http://www.markmonitor.com
Updated Date: 2019-09-09T08:39:04-0700
Creation Date: 1997-09-15T00:00:00-0700
Registrar Registration Expiration Date: 2028-09-13T00:00:00-0700
Registrar: MarkMonitor, Inc.
Registrar IANA ID: 292
Registrar Abuse Contact Email: abusecomplaints@markmonitor.com
Registrar Abuse Contact Phone: +1.2083895740
Domain Status: clientUpdateProhibited (https://www.icann.org/epp#clientUpdateProhibited)
Domain Status: clientTransferProhibited (https://www.icann.org/epp#clientTransferProhibited)
Domain Status: clientDeleteProhibited (https://www.icann.org/epp#clientDeleteProhibited)
Domain Status: serverUpdateProhibited (https://www.icann.org/epp#serverUpdateProhibited)
Domain Status: serverTransferProhibited (https://www.icann.org/epp#serverTransferProhibited)
Domain Status: serverDeleteProhibited (https://www.icann.org/epp#serverDeleteProhibited)
Registrant Organization: Google LLC
Registrant State/Province: CA
Registrant Country: US
Admin Organization: Google LLC
Admin State/Province: CA
Admin Country: US
Tech Organization: Google LLC
Tech State/Province: CA
Tech Country: US
Name Server: ns2.google.com
Name Server: ns3.google.com
Name Server: ns4.google.com
Name Server: ns1.google.com
DNSSEC: unsigned
URL of the ICANN WHOIS Data Problem Reporting System: http://wdprs.internic.net/
>>> Last update of WHOIS database: 2019-09-30T07:22:02-0700 <<<
`

func TestParseWhois_Golden(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)

	got, err := nodes.ParseWhois(ctx, ax, &gen.ParseWhoisInput{RawWhois: googleComWhois})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.GetError() != nil {
		t.Fatalf("unexpected structured error: %+v", got.GetError())
	}

	if got.GetDomainName() != "google.com" {
		t.Errorf("DomainName = %q, want google.com", got.GetDomainName())
	}
	if got.GetSource() != "whois" {
		t.Errorf("Source = %q, want whois", got.GetSource())
	}
	wantNS := []string{"ns2.google.com", "ns3.google.com", "ns4.google.com", "ns1.google.com"}
	if strings.Join(got.GetNameServers(), ",") != strings.Join(wantNS, ",") {
		t.Errorf("NameServers = %v, want %v", got.GetNameServers(), wantNS)
	}
	if got.GetDnssec() {
		t.Errorf("Dnssec = true, want false (text says \"unsigned\")")
	}
	if !strings.HasPrefix(got.GetCreatedDate(), "1997-09-15") {
		t.Errorf("CreatedDate = %q, want prefix 1997-09-15", got.GetCreatedDate())
	}
	if !strings.HasPrefix(got.GetExpirationDate(), "2028-09-13") {
		t.Errorf("ExpirationDate = %q, want prefix 2028-09-13", got.GetExpirationDate())
	}
	if got.GetWhoisServer() != "whois.markmonitor.com" {
		t.Errorf("WhoisServer = %q, want whois.markmonitor.com", got.GetWhoisServer())
	}

	if got.GetRegistrar() == nil || got.GetRegistrar().GetName() != "MarkMonitor, Inc." {
		t.Errorf("Registrar.Name = %v, want MarkMonitor, Inc.", got.GetRegistrar())
	}
	if got.GetRegistrar().GetEmail() != "abusecomplaints@markmonitor.com" {
		t.Errorf("Registrar.Email = %q", got.GetRegistrar().GetEmail())
	}

	if got.GetRegistrant() == nil || got.GetRegistrant().GetOrganization() != "Google LLC" {
		t.Errorf("Registrant.Organization = %v, want Google LLC", got.GetRegistrant())
	}

	if len(got.GetStatuses()) != 6 {
		t.Fatalf("len(Statuses) = %d, want 6", len(got.GetStatuses()))
	}
	if len(got.GetNormalizedStatuses()) != 6 {
		t.Fatalf("len(NormalizedStatuses) = %d, want 6", len(got.GetNormalizedStatuses()))
	}
	first := got.GetNormalizedStatuses()[0]
	if first.GetCode() != "clientUpdateProhibited" || first.GetCategory() != "update" || !first.GetIsClientStatus() {
		t.Errorf("NormalizedStatuses[0] = %+v, want code clientUpdateProhibited/category update/client=true", first)
	}
}

func TestParseWhois_EmptyInput(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)

	got, err := nodes.ParseWhois(ctx, ax, &gen.ParseWhoisInput{RawWhois: ""})
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if got.GetError() == nil || got.GetError().GetCode() != "EMPTY_INPUT" {
		t.Fatalf("Error = %+v, want code EMPTY_INPUT", got.GetError())
	}
}

// TestParseWhois_Malformed proves malformed/nonsense input returns a
// structured error rather than a panic — the error-path gate.
func TestParseWhois_Malformed(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)

	got, err := nodes.ParseWhois(ctx, ax, &gen.ParseWhoisInput{RawWhois: "this is not whois output at all, just some prose."})
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if got.GetError() == nil {
		t.Fatalf("expected a structured error for nonsense input, got %+v", got)
	}
	if got.GetError().GetCode() != "INVALID_WHOIS" {
		t.Errorf("Error.Code = %q, want INVALID_WHOIS", got.GetError().GetCode())
	}
}

// TestParseWhois_TooLarge proves the 10 MiB cap is enforced rather than
// handed to the parser (and, downstream, the deployed 16 MiB invoke limit).
func TestParseWhois_TooLarge(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)

	huge := strings.Repeat("Domain Name: example.com\n", 450000) // well over 10 MiB
	got, err := nodes.ParseWhois(ctx, ax, &gen.ParseWhoisInput{RawWhois: huge})
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if got.GetError() == nil || got.GetError().GetCode() != "INPUT_TOO_LARGE" {
		t.Fatalf("Error = %+v, want code INPUT_TOO_LARGE", got.GetError())
	}
}
