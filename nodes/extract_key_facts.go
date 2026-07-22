package nodes

import (
	"context"

	"christiangeorgelucas/whois-tools/axiom"
	gen "christiangeorgelucas/whois-tools/gen"
)

// ExtractKeyFacts flattens an already-parsed RegistrationRecord (the
// output of ParseWhois or ParseRdapDomain) down to the handful of facts
// almost every caller actually wants: domain name, registrar name,
// expiration date, and name servers. When `as_of` (an ISO 8601 date the
// caller considers "now") is supplied, also computes days_until_expiry and
// is_expired — deterministically, from the two input dates, never from the
// wall clock, so this node never reads real time itself; omit `as_of` to
// get every other field with has_expiry_computation left false. A record
// with no domain_name and no expiration_date returns a structured error
// (nothing to extract); an unparseable `as_of` or expiration_date leaves
// has_expiry_computation false rather than erroring, since every other
// fact is still valid output.
func ExtractKeyFacts(ctx context.Context, ax axiom.Context, input *gen.ExtractKeyFactsInput) (*gen.KeyFacts, error) {
	record := input.GetRecord()
	if record == nil || (record.GetDomainName() == "" && record.GetExpirationDate() == "") {
		return &gen.KeyFacts{Error: &gen.Error{
			Code:    "EMPTY_INPUT",
			Message: "record must be a parsed RegistrationRecord with at least domain_name or expiration_date set",
		}}, nil
	}

	facts := &gen.KeyFacts{
		DomainName:     record.GetDomainName(),
		ExpirationDate: record.GetExpirationDate(),
		NameServers:    record.GetNameServers(),
	}
	if r := record.GetRegistrar(); r != nil {
		facts.RegistrarName = firstNonEmpty(r.GetName(), r.GetOrganization())
	}

	asOf := input.GetAsOf()
	if asOf == "" || facts.ExpirationDate == "" {
		return facts, nil
	}
	asOfTime, ok1 := parseFlexibleDate(asOf)
	expTime, ok2 := parseFlexibleDate(facts.ExpirationDate)
	if !ok1 || !ok2 {
		return facts, nil
	}

	days := int32(expTime.Sub(asOfTime).Hours() / 24)
	facts.DaysUntilExpiry = days
	facts.IsExpired = days < 0
	facts.HasExpiryComputation = true
	return facts, nil
}
