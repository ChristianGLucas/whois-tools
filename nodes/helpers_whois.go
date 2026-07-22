package nodes

import (
	"fmt"

	whoisparser "github.com/likexian/whois-parser"

	gen "christiangeorgelucas/whois-tools/gen"
)

func errEmptyInput(field string) *gen.Error {
	return &gen.Error{Code: "EMPTY_INPUT", Message: fmt.Sprintf("%s must not be empty", field)}
}

// parseWhoisText parses raw legacy-WHOIS text via likexian/whois-parser and
// maps it onto the canonical RegistrationRecord. Never panics: a library
// panic (malformed/adversarial text hitting an edge case the library
// itself does not guard) is recovered and returned as a structured
// INVALID_WHOIS error rather than crashing the node.
func parseWhoisText(raw string) (record *gen.RegistrationRecord, recErr error) {
	defer func() {
		if r := recover(); r != nil {
			record = &gen.RegistrationRecord{
				Error: &gen.Error{Code: "INVALID_WHOIS", Message: fmt.Sprintf("whois text could not be parsed: %v", r)},
			}
			recErr = nil
		}
	}()

	info, err := whoisparser.Parse(raw)
	if err != nil {
		return &gen.RegistrationRecord{
			Error: &gen.Error{Code: "INVALID_WHOIS", Message: err.Error()},
		}, nil
	}

	rec := &gen.RegistrationRecord{Source: "whois"}

	if info.Domain != nil {
		d := info.Domain
		rec.DomainName = firstNonEmpty(d.Domain, d.Name)
		rec.NameServers = d.NameServers
		rec.Dnssec = d.DNSSec
		rec.WhoisServer = d.WhoisServer

		rec.CreatedDate = bestDate(d.CreatedDate, d.CreatedDateInTime)
		rec.UpdatedDate = bestDate(d.UpdatedDate, d.UpdatedDateInTime)
		rec.ExpirationDate = bestDate(d.ExpirationDate, d.ExpirationDateInTime)

		for _, s := range d.Status {
			rec.Statuses = append(rec.Statuses, s)
			rec.NormalizedStatuses = append(rec.NormalizedStatuses, normalizeEppStatusText(s))
		}

		if rec.CreatedDate != "" {
			rec.Events = append(rec.Events, &gen.RegistrationEvent{Action: "registration", Date: rec.CreatedDate})
		}
		if rec.UpdatedDate != "" {
			rec.Events = append(rec.Events, &gen.RegistrationEvent{Action: "last changed", Date: rec.UpdatedDate})
		}
		if rec.ExpirationDate != "" {
			rec.Events = append(rec.Events, &gen.RegistrationEvent{Action: "expiration", Date: rec.ExpirationDate})
		}
	}

	rec.Registrar = whoisContact(info.Registrar)
	rec.Registrant = whoisContact(info.Registrant)
	rec.Administrative = whoisContact(info.Administrative)
	rec.Technical = whoisContact(info.Technical)
	rec.Billing = whoisContact(info.Billing)

	return rec, nil
}

func whoisContact(c *whoisparser.Contact) *gen.Contact {
	if c == nil {
		return nil
	}
	return &gen.Contact{
		Id:           c.ID,
		Name:         c.Name,
		Organization: c.Organization,
		Street:       c.Street,
		City:         c.City,
		Province:     c.Province,
		PostalCode:   c.PostalCode,
		Country:      c.Country,
		Phone:        c.Phone,
		PhoneExt:     c.PhoneExt,
		Fax:          c.Fax,
		FaxExt:       c.FaxExt,
		Email:        c.Email,
		ReferralUrl:  c.ReferralURL,
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
