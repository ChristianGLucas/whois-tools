package nodes

import "time"

// bestDate prefers the library's parsed *time.Time (formatted RFC 3339, the
// same convention RDAP JSON already uses) over the raw source string, so
// WHOIS- and RDAP-sourced RegistrationRecords carry dates in a consistent
// format. Falls back to the raw string as-is when the library could not
// parse a time (some registries use formats likexian/whois-parser does not
// recognize) — never fabricates a date.
func bestDate(raw string, t *time.Time) string {
	if t != nil && !t.IsZero() {
		return t.UTC().Format(time.RFC3339)
	}
	return raw
}
