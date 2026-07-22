package nodes

import (
	"context"

	"christiangeorgelucas/whois-tools/axiom"
	gen "christiangeorgelucas/whois-tools/gen"
)

// ParseRdapEntity parses a single RDAP "entity" object (RFC 9083 §5.1) on
// its own — the shape RDAP search endpoints (e.g. /entities) return, or
// whatever a caller has already pulled out of a larger response — into a
// Contact: decodes its jCard (RFC 7095 vcardArray: fn, org, adr, tel,
// email) plus its handle and roles. Use ParseRdapDomain/ParseRdapIpNetwork
// instead when you have the whole containing object; this node is for
// working with one entity in isolation. Input over 640 KiB, JSON nested
// past 64 levels, or text that is not valid JSON returns a structured
// error; a vcardArray with no recognized properties yields a Contact with
// only id/roles set rather than an error (the entity may legitimately
// carry only a handle).
func ParseRdapEntity(ctx context.Context, ax axiom.Context, input *gen.ParseRdapInput) (*gen.Contact, error) {
	if errOut := checkRdapInput(input.GetRdapJson()); errOut != nil {
		return &gen.Contact{Error: errOut}, nil
	}
	contact, err := parseRdapEntityJSON(input.GetRdapJson())
	if err != nil {
		return &gen.Contact{Error: &gen.Error{Code: "INVALID_RDAP_JSON", Message: err.Error()}}, nil
	}
	return contact, nil
}
