package nodes_test

import (
	"context"
	"strings"
	"testing"

	gen "christiangeorgelucas/whois-tools/gen"
	"christiangeorgelucas/whois-tools/nodes"
)

// exampleIpNetworkRdap is adapted from RFC 9083 Figure 23's embedded
// "network" object (the reverse-DNS delegation example), with a
// cidr0_cidrs block added using the shape documented for the RDAP CIDR
// extension (v4prefix + length). Expected values below were worked out by
// hand from the source RFC field semantics.
const exampleIpNetworkRdap = `{
  "objectClassName": "ip network",
  "handle": "XXXX-RIR",
  "startAddress": "192.0.2.0",
  "endAddress": "192.0.2.255",
  "ipVersion": "v4",
  "name": "NET-RTR-1",
  "type": "DIRECT ALLOCATION",
  "country": "AU",
  "parentHandle": "YYYY-RIR",
  "status": ["active"],
  "cidr0_cidrs": [{"v4prefix": "192.0.2.0", "length": 24}],
  "events": [{"eventAction": "registration", "eventDate": "1990-12-31T23:59:59Z"}],
  "entities": [
    {
      "objectClassName": "entity",
      "handle": "XXXX",
      "roles": ["administrative"],
      "vcardArray": ["vcard", [
        ["version", {}, "text", "4.0"],
        ["fn", {}, "text", "Net Admin"],
        ["email", {}, "text", "admin@example.net"]
      ]]
    }
  ]
}`

func TestParseRdapIpNetwork_Golden(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)

	got, err := nodes.ParseRdapIpNetwork(ctx, ax, &gen.ParseRdapInput{RdapJson: exampleIpNetworkRdap})
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if got.GetError() != nil {
		t.Fatalf("unexpected structured error: %+v", got.GetError())
	}

	if got.GetHandle() != "XXXX-RIR" {
		t.Errorf("Handle = %q", got.GetHandle())
	}
	if got.GetStartAddress() != "192.0.2.0" || got.GetEndAddress() != "192.0.2.255" {
		t.Errorf("start/end = %q/%q", got.GetStartAddress(), got.GetEndAddress())
	}
	if got.GetVersion() != 4 {
		t.Errorf("Version = %d, want 4", got.GetVersion())
	}
	if got.GetName() != "NET-RTR-1" || got.GetType() != "DIRECT ALLOCATION" || got.GetCountry() != "AU" || got.GetParentHandle() != "YYYY-RIR" {
		t.Errorf("name/type/country/parent = %q/%q/%q/%q", got.GetName(), got.GetType(), got.GetCountry(), got.GetParentHandle())
	}
	if want := []string{"192.0.2.0/24"}; strings.Join(got.GetCidrs(), ",") != strings.Join(want, ",") {
		t.Errorf("Cidrs = %v, want %v", got.GetCidrs(), want)
	}

	// "active" is a real RDAP ip-network status but not part of the EPP
	// vocabulary — proves an unrecognized status normalizes to an empty
	// code rather than erroring or being dropped.
	if len(got.GetNormalizedStatuses()) != 1 || got.GetNormalizedStatuses()[0].GetCode() != "" {
		t.Errorf("NormalizedStatuses = %+v, want one entry with empty Code", got.GetNormalizedStatuses())
	}
	if got.GetNormalizedStatuses()[0].GetRaw() != "active" {
		t.Errorf("NormalizedStatuses[0].Raw = %q, want active", got.GetNormalizedStatuses()[0].GetRaw())
	}

	if len(got.GetEntities()) != 1 {
		t.Fatalf("len(Entities) = %d, want 1", len(got.GetEntities()))
	}
	e := got.GetEntities()[0]
	if e.GetName() != "Net Admin" || e.GetEmail() != "admin@example.net" {
		t.Errorf("Entities[0] = %+v", e)
	}
	if len(e.GetRoles()) != 1 || e.GetRoles()[0] != "administrative" {
		t.Errorf("Entities[0].Roles = %v", e.GetRoles())
	}
}

func TestParseRdapIpNetwork_EmptyInput(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)
	got, err := nodes.ParseRdapIpNetwork(ctx, ax, &gen.ParseRdapInput{RdapJson: ""})
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if got.GetError() == nil || got.GetError().GetCode() != "EMPTY_INPUT" {
		t.Fatalf("Error = %+v, want EMPTY_INPUT", got.GetError())
	}
}

func TestParseRdapIpNetwork_InvalidJSON(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)
	got, err := nodes.ParseRdapIpNetwork(ctx, ax, &gen.ParseRdapInput{RdapJson: "not json at all"})
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if got.GetError() == nil || got.GetError().GetCode() != "INVALID_RDAP_JSON" {
		t.Fatalf("Error = %+v, want INVALID_RDAP_JSON", got.GetError())
	}
}

func TestParseRdapIpNetwork_DeeplyNested(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)

	nested := strings.Repeat("{\"a\":", 5000) + "1" + strings.Repeat("}", 5000)
	got, err := nodes.ParseRdapIpNetwork(ctx, ax, &gen.ParseRdapInput{RdapJson: nested})
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if got.GetError() == nil || got.GetError().GetCode() != "INVALID_RDAP_JSON" {
		t.Fatalf("Error = %+v, want INVALID_RDAP_JSON", got.GetError())
	}
}
