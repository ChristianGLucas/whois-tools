package nodes

import (
	"context"

	"christiangeorgelucas/whois-tools/axiom"
	gen "christiangeorgelucas/whois-tools/gen"
)

// ParseRdapDomain parses an RDAP JSON response for a domain object (RFC
// 9083 §5.3 — objectClassName "domain") into the same canonical
// RegistrationRecord ParseWhois produces, so a flow can treat a domain
// record identically regardless of which source it came from. Maps
// ldhName/unicodeName, status (normalized against the same EPP table
// NormalizeEppStatus uses), nameservers, secureDNS.delegationSigned,
// registration/expiration/last-changed events, the IANA registrar ID
// public ID, and every entity's jCard contact tagged by RDAP role
// (registrar/registrant/administrative/technical/billing). Implemented
// directly against the RFC 9083 JSON schema rather than a third-party
// library — RDAP is already a fully specified, self-describing JSON
// format, so there is no parsing algorithm to wrap the way legacy WHOIS
// free text needs one. Input over 640 KiB, JSON nested past 64 levels, or
// text that is not valid JSON / not a recognizable domain object returns a
// structured error instead of a crash.
func ParseRdapDomain(ctx context.Context, ax axiom.Context, input *gen.ParseRdapInput) (*gen.RegistrationRecord, error) {
	if errOut := checkRdapInput(input.GetRdapJson()); errOut != nil {
		return &gen.RegistrationRecord{Error: errOut}, nil
	}
	record, err := parseRdapDomainJSON(input.GetRdapJson())
	if err != nil {
		return &gen.RegistrationRecord{Error: &gen.Error{Code: "INVALID_RDAP_JSON", Message: err.Error()}}, nil
	}
	return record, nil
}
