package nodes

import (
	"context"

	"christiangeorgelucas/whois-tools/axiom"
	gen "christiangeorgelucas/whois-tools/gen"
)

// ParseWhois parses a raw legacy-WHOIS text response (as returned by a
// WHOIS server on port 43, or a caller's own WHOIS client — this node
// never performs the network query itself) into the canonical
// RegistrationRecord: registrar/registrant/admin/tech/billing contacts,
// name servers, DNSSEC flag, created/updated/expiration dates, and
// normalized EPP status codes. Wraps likexian/whois-parser (Apache-2.0),
// which recognizes the free-text formats of hundreds of TLD registries.
// Input over 10 MiB or text the library cannot make sense of returns a
// structured error instead of a crash.
func ParseWhois(ctx context.Context, ax axiom.Context, input *gen.ParseWhoisInput) (*gen.RegistrationRecord, error) {
	if input.GetRawWhois() == "" {
		return &gen.RegistrationRecord{Error: errEmptyInput("raw_whois")}, nil
	}
	if len(input.GetRawWhois()) > maxInputBytes {
		return &gen.RegistrationRecord{Error: errTooLarge(len(input.GetRawWhois()))}, nil
	}

	record, err := parseWhoisText(input.GetRawWhois())
	if err != nil {
		return &gen.RegistrationRecord{Error: &gen.Error{Code: "INVALID_WHOIS", Message: err.Error()}}, nil
	}
	return record, nil
}
