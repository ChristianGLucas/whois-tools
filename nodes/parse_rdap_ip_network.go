package nodes

import (
	"context"

	"christiangeorgelucas/whois-tools/axiom"
	gen "christiangeorgelucas/whois-tools/gen"
)

// ParseRdapIpNetwork parses an RDAP JSON response for an "ip network"
// object (RFC 9083 §5.4 — objectClassName "ip network") into the canonical
// IpRegistrationRecord: handle, start/end address, CIDR blocks
// (cidr0_cidrs), IP version, allocation type, country, parent handle,
// normalized statuses, events, and entities (each entity's jCard contact
// tagged by RDAP role). This is the IP-registration counterpart to
// ParseRdapDomain — legacy IP WHOIS text is intentionally out of scope for
// structured parsing (ARIN/RIPE/APNIC/LACNIC/AfriNIC each use a distinct
// free-text vocabulary; RDAP standardizes all five under this one schema).
// Text that is not a recognizable ip-network object returns a structured
// error.
func ParseRdapIpNetwork(ctx context.Context, ax axiom.Context, input *gen.ParseRdapInput) (*gen.IpRegistrationRecord, error) {
	if errOut := checkRdapInput(input.GetRdapJson()); errOut != nil {
		return &gen.IpRegistrationRecord{Error: errOut}, nil
	}
	record, err := parseRdapIPNetworkJSON(input.GetRdapJson())
	if err != nil {
		return &gen.IpRegistrationRecord{Error: &gen.Error{Code: "INVALID_RDAP_JSON", Message: err.Error()}}, nil
	}
	return record, nil
}
