package nodes_test

import (
	"context"
	"strings"
	"testing"

	gen "christiangeorgelucas/whois-tools/gen"
	"christiangeorgelucas/whois-tools/nodes"
)

// exampleDomainRdap is hand-composed from the entity, adr/tel/org vCard,
// event, and "IANA Registrar ID" publicId examples published in RFC 9083
// (Figures 23, 34, and 36) — real IETF-specified shapes, not invented
// ones. Every expected field below was worked out by hand from RFC 9083's
// own field semantics (an oracle independent of this package's mapping
// code), not copied from any parser's output.
const exampleDomainRdap = `{
  "objectClassName": "domain",
  "handle": "2138514_DOMAIN_COM-VRSN",
  "ldhName": "example.com",
  "status": [
    "https://icann.org/epp#clientTransferProhibited",
    "https://icann.org/epp#clientUpdateProhibited"
  ],
  "nameservers": [
    {"objectClassName": "nameserver", "ldhName": "ns1.example.com"},
    {"objectClassName": "nameserver", "ldhName": "ns2.example.com"}
  ],
  "secureDNS": {"delegationSigned": true},
  "events": [
    {"eventAction": "registration", "eventDate": "1997-09-15T00:00:00Z"},
    {"eventAction": "expiration", "eventDate": "2028-09-13T00:00:00Z"},
    {"eventAction": "last changed", "eventDate": "2019-09-09T08:39:04Z"}
  ],
  "entities": [
    {
      "objectClassName": "entity",
      "handle": "REG-1",
      "vcardArray": ["vcard", [
        ["version", {}, "text", "4.0"],
        ["fn", {}, "text", "Joe's Fish, Chips, and Domains"],
        ["org", {}, "text", "Example Registrar Inc."],
        ["adr", {"type":"work"}, "text", ["", "Suite 1234", "4321 Rue Somewhere", "Quebec", "QC", "G1V 2M2", "Canada"]],
        ["tel", {"type":["work","voice"]}, "uri", "tel:+1-555-555-1234"],
        ["email", {"type":"work"}, "text", "abuse@example-registrar.example"]
      ]],
      "roles": ["registrar"],
      "publicIds": [{"type": "IANA Registrar ID", "identifier": "9999"}]
    },
    {
      "objectClassName": "entity",
      "handle": "REGISTRANT-1",
      "vcardArray": ["vcard", [
        ["version", {}, "text", "4.0"],
        ["fn", {}, "text", "Joe User"],
        ["org", {}, "text", "Example LLC"],
        ["email", {}, "text", "joe.user@example.com"]
      ]],
      "roles": ["registrant", "administrative"]
    }
  ]
}`

func TestParseRdapDomain_Golden(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)

	got, err := nodes.ParseRdapDomain(ctx, ax, &gen.ParseRdapInput{RdapJson: exampleDomainRdap})
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if got.GetError() != nil {
		t.Fatalf("unexpected structured error: %+v", got.GetError())
	}

	if got.GetDomainName() != "example.com" {
		t.Errorf("DomainName = %q, want example.com", got.GetDomainName())
	}
	if got.GetSource() != "rdap" {
		t.Errorf("Source = %q, want rdap", got.GetSource())
	}
	wantNS := []string{"ns1.example.com", "ns2.example.com"}
	if strings.Join(got.GetNameServers(), ",") != strings.Join(wantNS, ",") {
		t.Errorf("NameServers = %v, want %v", got.GetNameServers(), wantNS)
	}
	if !got.GetDnssec() {
		t.Errorf("Dnssec = false, want true")
	}
	if got.GetCreatedDate() != "1997-09-15T00:00:00Z" {
		t.Errorf("CreatedDate = %q", got.GetCreatedDate())
	}
	if got.GetExpirationDate() != "2028-09-13T00:00:00Z" {
		t.Errorf("ExpirationDate = %q", got.GetExpirationDate())
	}
	if got.GetUpdatedDate() != "2019-09-09T08:39:04Z" {
		t.Errorf("UpdatedDate = %q", got.GetUpdatedDate())
	}

	if len(got.GetNormalizedStatuses()) != 2 {
		t.Fatalf("len(NormalizedStatuses) = %d, want 2", len(got.GetNormalizedStatuses()))
	}
	if c := got.GetNormalizedStatuses()[0]; c.GetCode() != "clientTransferProhibited" || c.GetCategory() != "transfer" {
		t.Errorf("NormalizedStatuses[0] = %+v", c)
	}
	if c := got.GetNormalizedStatuses()[1]; c.GetCode() != "clientUpdateProhibited" || c.GetCategory() != "update" {
		t.Errorf("NormalizedStatuses[1] = %+v", c)
	}

	reg := got.GetRegistrar()
	if reg == nil {
		t.Fatal("Registrar is nil")
	}
	if reg.GetName() != "Joe's Fish, Chips, and Domains" {
		t.Errorf("Registrar.Name = %q", reg.GetName())
	}
	if reg.GetOrganization() != "Example Registrar Inc." {
		t.Errorf("Registrar.Organization = %q", reg.GetOrganization())
	}
	if reg.GetStreet() != "4321 Rue Somewhere" || reg.GetCity() != "Quebec" || reg.GetProvince() != "QC" || reg.GetPostalCode() != "G1V 2M2" || reg.GetCountry() != "Canada" {
		t.Errorf("Registrar address = street=%q city=%q province=%q postal=%q country=%q",
			reg.GetStreet(), reg.GetCity(), reg.GetProvince(), reg.GetPostalCode(), reg.GetCountry())
	}
	if reg.GetPhone() != "tel:+1-555-555-1234" {
		t.Errorf("Registrar.Phone = %q", reg.GetPhone())
	}
	if reg.GetEmail() != "abuse@example-registrar.example" {
		t.Errorf("Registrar.Email = %q", reg.GetEmail())
	}
	if reg.GetId() != "REG-1" {
		t.Errorf("Registrar.Id = %q", reg.GetId())
	}
	if got.GetRegistrarIanaId() != "9999" {
		t.Errorf("RegistrarIanaId = %q, want 9999", got.GetRegistrarIanaId())
	}

	if got.GetRegistrant() == nil || got.GetRegistrant().GetName() != "Joe User" || got.GetRegistrant().GetOrganization() != "Example LLC" {
		t.Errorf("Registrant = %+v", got.GetRegistrant())
	}
	if got.GetAdministrative() == nil || got.GetAdministrative().GetEmail() != "joe.user@example.com" {
		t.Errorf("Administrative = %+v", got.GetAdministrative())
	}
}

func TestParseRdapDomain_EmptyInput(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)
	got, err := nodes.ParseRdapDomain(ctx, ax, &gen.ParseRdapInput{RdapJson: ""})
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if got.GetError() == nil || got.GetError().GetCode() != "EMPTY_INPUT" {
		t.Fatalf("Error = %+v, want EMPTY_INPUT", got.GetError())
	}
}

func TestParseRdapDomain_InvalidJSON(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)
	got, err := nodes.ParseRdapDomain(ctx, ax, &gen.ParseRdapInput{RdapJson: "{not valid json"})
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if got.GetError() == nil || got.GetError().GetCode() != "INVALID_RDAP_JSON" {
		t.Fatalf("Error = %+v, want INVALID_RDAP_JSON", got.GetError())
	}
}

// TestParseRdapDomain_UnrecognizedShape proves valid-but-irrelevant JSON
// (parses fine, but has none of a domain object's identifying fields)
// yields a structured error rather than a silently-empty "success".
func TestParseRdapDomain_UnrecognizedShape(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)
	got, err := nodes.ParseRdapDomain(ctx, ax, &gen.ParseRdapInput{RdapJson: `{"hello":"world"}`})
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if got.GetError() == nil || got.GetError().GetCode() != "INVALID_RDAP_JSON" {
		t.Fatalf("Error = %+v, want INVALID_RDAP_JSON", got.GetError())
	}
}

// TestParseRdapDomain_DeeplyNested is the deep-recursion regression test:
// a payload built purely from bracket nesting must be rejected quickly by
// the byte-scan depth guard, never handed to json.Unmarshal (which would
// recurse once per level and risk a fatal, unrecoverable stack overflow on
// sufficiently adversarial input).
func TestParseRdapDomain_DeeplyNested(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)

	nested := strings.Repeat("[", 5000) + strings.Repeat("]", 5000)
	got, err := nodes.ParseRdapDomain(ctx, ax, &gen.ParseRdapInput{RdapJson: nested})
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if got.GetError() == nil || got.GetError().GetCode() != "INVALID_RDAP_JSON" {
		t.Fatalf("Error = %+v, want INVALID_RDAP_JSON (nesting cap)", got.GetError())
	}
}

func TestParseRdapDomain_TooLarge(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)

	huge := `{"ldhName":"` + strings.Repeat("a", 11*1024*1024) + `"}`
	got, err := nodes.ParseRdapDomain(ctx, ax, &gen.ParseRdapInput{RdapJson: huge})
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if got.GetError() == nil || got.GetError().GetCode() != "INPUT_TOO_LARGE" {
		t.Fatalf("Error = %+v, want INPUT_TOO_LARGE", got.GetError())
	}
}
