package nodes_test

import (
	"context"
	"strings"
	"testing"

	gen "christiangeorgelucas/whois-tools/gen"
	"christiangeorgelucas/whois-tools/nodes"
)

// registrarEntityRdap is RFC 9083 Figure 36 verbatim (the documented
// example of a registrar entity, "Joe's Fish, Chips, and Domains") —
// expected fields below were read by hand straight off the RFC figure.
const registrarEntityRdap = `{
  "objectClassName": "entity",
  "handle": "XXXX",
  "vcardArray": ["vcard", [
    ["version", {}, "text", "4.0"],
    ["fn", {}, "text", "Joe's Fish, Chips, and Domains"],
    ["kind", {}, "text", "org"],
    ["org", {"type":"work"}, "text", "Example"],
    ["adr", {"type":"work"}, "text", ["", "Suite 1234", "4321 Rue Somewhere", "Quebec", "QC", "G1V 2M2", "Canada"]],
    ["tel", {"type":["work","voice"], "pref":"1"}, "uri", "tel:+1-555-555-1234;ext=102"],
    ["email", {"type":"work"}, "text", "joes_fish_chips_and_domains@example.com"]
  ]],
  "roles": ["registrar"],
  "publicIds": [{"type": "IANA Registrar ID", "identifier": "1"}]
}`

func TestParseRdapEntity_Golden(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)

	got, err := nodes.ParseRdapEntity(ctx, ax, &gen.ParseRdapInput{RdapJson: registrarEntityRdap})
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if got.GetError() != nil {
		t.Fatalf("unexpected structured error: %+v", got.GetError())
	}

	if got.GetId() != "XXXX" {
		t.Errorf("Id = %q, want XXXX", got.GetId())
	}
	if len(got.GetRoles()) != 1 || got.GetRoles()[0] != "registrar" {
		t.Errorf("Roles = %v, want [registrar]", got.GetRoles())
	}
	if got.GetName() != "Joe's Fish, Chips, and Domains" {
		t.Errorf("Name = %q", got.GetName())
	}
	if got.GetOrganization() != "Example" {
		t.Errorf("Organization = %q", got.GetOrganization())
	}
	if got.GetStreet() != "4321 Rue Somewhere" {
		t.Errorf("Street = %q", got.GetStreet())
	}
	if got.GetCity() != "Quebec" || got.GetProvince() != "QC" || got.GetPostalCode() != "G1V 2M2" || got.GetCountry() != "Canada" {
		t.Errorf("address = city=%q province=%q postal=%q country=%q", got.GetCity(), got.GetProvince(), got.GetPostalCode(), got.GetCountry())
	}
	if got.GetPhone() != "tel:+1-555-555-1234;ext=102" {
		t.Errorf("Phone = %q", got.GetPhone())
	}
	if got.GetEmail() != "joes_fish_chips_and_domains@example.com" {
		t.Errorf("Email = %q", got.GetEmail())
	}
}

func TestParseRdapEntity_HandleOnly(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)

	got, err := nodes.ParseRdapEntity(ctx, ax, &gen.ParseRdapInput{RdapJson: `{"objectClassName":"entity","handle":"H-1","roles":["technical"]}`})
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if got.GetError() != nil {
		t.Fatalf("unexpected structured error: %+v", got.GetError())
	}
	if got.GetId() != "H-1" {
		t.Errorf("Id = %q, want H-1", got.GetId())
	}
	if len(got.GetRoles()) != 1 || got.GetRoles()[0] != "technical" {
		t.Errorf("Roles = %v", got.GetRoles())
	}
}

func TestParseRdapEntity_EmptyInput(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)
	got, err := nodes.ParseRdapEntity(ctx, ax, &gen.ParseRdapInput{RdapJson: ""})
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if got.GetError() == nil || got.GetError().GetCode() != "EMPTY_INPUT" {
		t.Fatalf("Error = %+v, want EMPTY_INPUT", got.GetError())
	}
}

func TestParseRdapEntity_InvalidJSON(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)
	got, err := nodes.ParseRdapEntity(ctx, ax, &gen.ParseRdapInput{RdapJson: "{{{"})
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if got.GetError() == nil || got.GetError().GetCode() != "INVALID_RDAP_JSON" {
		t.Fatalf("Error = %+v, want INVALID_RDAP_JSON", got.GetError())
	}
}

func TestParseRdapEntity_DeeplyNested(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)

	nested := strings.Repeat("[", 5000)
	got, err := nodes.ParseRdapEntity(ctx, ax, &gen.ParseRdapInput{RdapJson: nested})
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if got.GetError() == nil || got.GetError().GetCode() != "INVALID_RDAP_JSON" {
		t.Fatalf("Error = %+v, want INVALID_RDAP_JSON", got.GetError())
	}
}
