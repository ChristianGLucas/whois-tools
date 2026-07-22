package nodes

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	gen "christiangeorgelucas/whois-tools/gen"
)

// maxJSONNestingDepth bounds how deeply nested caller-supplied RDAP JSON
// may be before we refuse to decode it. RDAP objects never legitimately
// nest more than ~10 levels (domain -> entities -> entities -> vcardArray
// -> property -> value); a bound of 64 is generous headroom. This check
// runs as a cheap linear byte scan BEFORE any json.Unmarshal, because
// Go's decoder recurses once per nesting level and unbounded nesting (a
// payload of nothing but "[[[[...]]]]") can exhaust the goroutine stack —
// a fatal, unrecoverable crash that a deferred recover() cannot catch, so
// it must be prevented rather than caught.
const maxJSONNestingDepth = 64

// jsonNestingDepth returns the maximum bracket/brace nesting depth of a
// JSON text, ignoring bytes inside string literals, without ever building
// a parsed representation. Bails out early (returning a depth already over
// maxJSONNestingDepth) rather than scanning the whole input once the limit
// is exceeded.
func jsonNestingDepth(data []byte) int {
	depth, max := 0, 0
	inString := false
	escaped := false
	for _, b := range data {
		if inString {
			switch {
			case escaped:
				escaped = false
			case b == '\\':
				escaped = true
			case b == '"':
				inString = false
			}
			continue
		}
		switch b {
		case '"':
			inString = true
		case '{', '[':
			depth++
			if depth > max {
				max = depth
			}
			if max > maxJSONNestingDepth {
				return max
			}
		case '}', ']':
			depth--
		}
	}
	return max
}

// checkRdapInput applies the shared size and nesting-depth bounds every
// RDAP-parsing node enforces before it does any real work.
func checkRdapInput(raw string) *gen.Error {
	if raw == "" {
		return errEmptyInput("rdap_json")
	}
	if len(raw) > maxInputBytes {
		return errTooLarge(len(raw))
	}
	if jsonNestingDepth([]byte(raw)) > maxJSONNestingDepth {
		return &gen.Error{
			Code:    "INVALID_RDAP_JSON",
			Message: fmt.Sprintf("input JSON nests deeper than the %d level cap this node accepts", maxJSONNestingDepth),
		}
	}
	return nil
}

// --- RFC 9083 RDAP response shapes (only the fields this package maps) ---

type rdapPublicID struct {
	Type       string `json:"type"`
	Identifier string `json:"identifier"`
}

type rdapEntity struct {
	ObjectClassName string          `json:"objectClassName"`
	Handle          string          `json:"handle"`
	Roles           []string        `json:"roles"`
	VcardArray      json.RawMessage `json:"vcardArray"`
	Entities        []rdapEntity    `json:"entities"`
	PublicIds       []rdapPublicID  `json:"publicIds"`
	Status          []string        `json:"status"`
}

type rdapEvent struct {
	EventAction string `json:"eventAction"`
	EventDate   string `json:"eventDate"`
	EventActor  string `json:"eventActor"`
}

type rdapNameserver struct {
	LdhName     string `json:"ldhName"`
	UnicodeName string `json:"unicodeName"`
}

type rdapSecureDNS struct {
	DelegationSigned bool `json:"delegationSigned"`
}

type rdapDomain struct {
	ObjectClassName string           `json:"objectClassName"`
	Handle          string           `json:"handle"`
	LdhName         string           `json:"ldhName"`
	UnicodeName     string           `json:"unicodeName"`
	Status          []string         `json:"status"`
	Entities        []rdapEntity     `json:"entities"`
	Nameservers     []rdapNameserver `json:"nameservers"`
	SecureDNS       *rdapSecureDNS   `json:"secureDNS"`
	Events          []rdapEvent      `json:"events"`
	PublicIds       []rdapPublicID   `json:"publicIds"`
}

type rdapCidr struct {
	V4Prefix string      `json:"v4prefix"`
	V6Prefix string      `json:"v6prefix"`
	Length   json.Number `json:"length"`
}

type rdapIPNetwork struct {
	ObjectClassName string       `json:"objectClassName"`
	Handle          string       `json:"handle"`
	StartAddress    string       `json:"startAddress"`
	EndAddress      string       `json:"endAddress"`
	IPVersion       string       `json:"ipVersion"`
	Name            string       `json:"name"`
	Type            string       `json:"type"`
	Country         string       `json:"country"`
	ParentHandle    string       `json:"parentHandle"`
	Status          []string     `json:"status"`
	Entities        []rdapEntity `json:"entities"`
	Events          []rdapEvent  `json:"events"`
	Cidr0Cidrs      []rdapCidr   `json:"cidr0_cidrs"`
}

// parseRdapDomainJSON decodes an RDAP domain-object JSON response (RFC 9083
// §5.3) into the canonical RegistrationRecord. Guarded by checkRdapInput
// before this is ever called; also recovers from any unexpected panic in
// our own mapping code and turns it into a structured error.
func parseRdapDomainJSON(raw string) (record *gen.RegistrationRecord, err error) {
	defer func() {
		if r := recover(); r != nil {
			record = &gen.RegistrationRecord{Error: &gen.Error{Code: "INVALID_RDAP_JSON", Message: fmt.Sprintf("could not map rdap domain object: %v", r)}}
		}
	}()

	var d rdapDomain
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	if decErr := dec.Decode(&d); decErr != nil {
		return &gen.RegistrationRecord{Error: &gen.Error{Code: "INVALID_RDAP_JSON", Message: decErr.Error()}}, nil
	}
	if d.LdhName == "" && d.Handle == "" && len(d.Entities) == 0 {
		return &gen.RegistrationRecord{Error: &gen.Error{Code: "INVALID_RDAP_JSON", Message: "no domain fields (ldhName/handle/entities) found — not a recognizable RDAP domain object"}}, nil
	}

	rec := &gen.RegistrationRecord{
		Source:      "rdap",
		DomainName:  d.LdhName,
		UnicodeName: d.UnicodeName,
	}
	if rec.DomainName == "" {
		rec.DomainName = d.Handle
	}
	for _, ns := range d.Nameservers {
		host := ns.LdhName
		if host == "" {
			host = ns.UnicodeName
		}
		if host != "" {
			rec.NameServers = append(rec.NameServers, host)
		}
	}
	if d.SecureDNS != nil {
		rec.Dnssec = d.SecureDNS.DelegationSigned
	}
	for _, s := range d.Status {
		rec.Statuses = append(rec.Statuses, s)
		rec.NormalizedStatuses = append(rec.NormalizedStatuses, normalizeEppStatusText(s))
	}
	for _, ev := range d.Events {
		rec.Events = append(rec.Events, &gen.RegistrationEvent{Action: ev.EventAction, Date: ev.EventDate, Actor: ev.EventActor})
		switch strings.ToLower(ev.EventAction) {
		case "registration":
			rec.CreatedDate = ev.EventDate
		case "last changed", "last update of rdap database":
			if rec.UpdatedDate == "" || strings.ToLower(ev.EventAction) == "last changed" {
				rec.UpdatedDate = ev.EventDate
			}
		case "expiration":
			rec.ExpirationDate = ev.EventDate
		}
	}
	for _, pid := range d.PublicIds {
		if strings.EqualFold(pid.Type, "IANA Registrar ID") {
			rec.RegistrarIanaId = pid.Identifier
		}
	}

	for _, e := range d.Entities {
		c := entityToContact(e)
		if c == nil {
			continue
		}
		assigned := false
		for _, role := range e.Roles {
			switch strings.ToLower(role) {
			case "registrar":
				rec.Registrar = c
				assigned = true
				// The IANA Registrar ID is commonly carried as a publicId
				// on the registrar entity itself (RFC 9083 Appendix A.2);
				// some registry implementations instead (or additionally)
				// put it on the top-level domain object, handled below.
				for _, pid := range e.PublicIds {
					if strings.EqualFold(pid.Type, "IANA Registrar ID") && rec.RegistrarIanaId == "" {
						rec.RegistrarIanaId = pid.Identifier
					}
				}
			case "registrant":
				rec.Registrant = c
				assigned = true
			case "administrative":
				rec.Administrative = c
				assigned = true
			case "technical":
				rec.Technical = c
				assigned = true
			case "billing":
				rec.Billing = c
				assigned = true
			}
		}
		_ = assigned
	}

	return rec, nil
}

// parseRdapIPNetworkJSON decodes an RDAP "ip network" object (RFC 9083
// §5.4) into the canonical IpRegistrationRecord.
func parseRdapIPNetworkJSON(raw string) (record *gen.IpRegistrationRecord, err error) {
	defer func() {
		if r := recover(); r != nil {
			record = &gen.IpRegistrationRecord{Error: &gen.Error{Code: "INVALID_RDAP_JSON", Message: fmt.Sprintf("could not map rdap ip network object: %v", r)}}
		}
	}()

	var n rdapIPNetwork
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	if decErr := dec.Decode(&n); decErr != nil {
		return &gen.IpRegistrationRecord{Error: &gen.Error{Code: "INVALID_RDAP_JSON", Message: decErr.Error()}}, nil
	}
	if n.StartAddress == "" && n.EndAddress == "" && n.Handle == "" {
		return &gen.IpRegistrationRecord{Error: &gen.Error{Code: "INVALID_RDAP_JSON", Message: "no ip-network fields (startAddress/endAddress/handle) found — not a recognizable RDAP ip network object"}}, nil
	}

	rec := &gen.IpRegistrationRecord{
		Handle:       n.Handle,
		Name:         n.Name,
		StartAddress: n.StartAddress,
		EndAddress:   n.EndAddress,
		Type:         n.Type,
		Country:      n.Country,
		ParentHandle: n.ParentHandle,
	}
	switch strings.ToLower(n.IPVersion) {
	case "v4":
		rec.Version = 4
	case "v6":
		rec.Version = 6
	}
	for _, c := range n.Cidr0Cidrs {
		prefix := c.V4Prefix
		if prefix == "" {
			prefix = c.V6Prefix
		}
		if prefix == "" {
			continue
		}
		length := "0"
		if c.Length != "" {
			length = c.Length.String()
		}
		rec.Cidrs = append(rec.Cidrs, prefix+"/"+length)
	}
	for _, s := range n.Status {
		rec.Statuses = append(rec.Statuses, s)
		rec.NormalizedStatuses = append(rec.NormalizedStatuses, normalizeEppStatusText(s))
	}
	for _, ev := range n.Events {
		rec.Events = append(rec.Events, &gen.RegistrationEvent{Action: ev.EventAction, Date: ev.EventDate, Actor: ev.EventActor})
	}
	for _, e := range n.Entities {
		if c := entityToContact(e); c != nil {
			rec.Entities = append(rec.Entities, c)
		}
	}

	return rec, nil
}

// parseRdapEntityJSON decodes a single RDAP "entity" object (RFC 9083
// §5.1) — a registrant/contact/registrar record on its own, not nested
// inside a domain or ip-network response.
func parseRdapEntityJSON(raw string) (contact *gen.Contact, err error) {
	defer func() {
		if r := recover(); r != nil {
			contact = &gen.Contact{}
			err = fmt.Errorf("could not map rdap entity object: %v", r)
		}
	}()

	var e rdapEntity
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()
	if decErr := dec.Decode(&e); decErr != nil {
		return nil, decErr
	}
	c := entityToContact(e)
	if c == nil {
		c = &gen.Contact{}
	}
	c.Roles = e.Roles
	if c.Id == "" {
		c.Id = e.Handle
	}
	return c, nil
}

// entityToContact maps one RDAP entity's jCard (vcardArray) plus its
// handle/roles onto the canonical Contact shape. Returns nil only when the
// entity carries no vcard and no handle (nothing to represent).
func entityToContact(e rdapEntity) *gen.Contact {
	c := parseJCard(e.VcardArray)
	if c == nil {
		if e.Handle == "" {
			return nil
		}
		c = &gen.Contact{}
	}
	c.Id = e.Handle
	c.Roles = e.Roles
	return c
}

// parseJCard decodes an RFC 7095 jCard array
// (["vcard", [[name, params, type, value], ...]]) into a Contact. Returns
// nil if `raw` is empty or not a well-formed jCard array — never panics on
// malformed vcard data (a caller-controlled RDAP field), it just yields a
// Contact with whatever fields it could recognize.
func parseJCard(raw json.RawMessage) *gen.Contact {
	if len(raw) == 0 {
		return nil
	}
	var top []json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil || len(top) < 2 {
		return nil
	}
	var props []json.RawMessage
	if err := json.Unmarshal(top[1], &props); err != nil {
		return nil
	}

	c := &gen.Contact{}
	found := false
	for _, p := range props {
		var fields []json.RawMessage
		if err := json.Unmarshal(p, &fields); err != nil || len(fields) < 4 {
			continue
		}
		var propName string
		if err := json.Unmarshal(fields[0], &propName); err != nil {
			continue
		}
		propName = strings.ToLower(propName)

		switch propName {
		case "fn":
			c.Name = jcardScalar(fields[3])
			found = true
		case "org":
			c.Organization = jcardJoinedValue(fields[3])
			found = true
		case "email":
			c.Email = jcardScalar(fields[3])
			found = true
		case "tel":
			num := jcardScalar(fields[3])
			if jcardHasParamValue(fields[1], "type", "fax") {
				c.Fax = num
			} else {
				c.Phone = num
			}
			found = true
		case "adr":
			jcardFillAddress(fields[3], c)
			found = true
		}
	}
	if !found {
		return nil
	}
	return c
}

// jcardScalar reads a jCard property value that is a plain string. Returns
// "" for any other JSON shape (never panics on an unexpected array/number).
func jcardScalar(v json.RawMessage) string {
	var s string
	if err := json.Unmarshal(v, &s); err == nil {
		return s
	}
	// tel values are sometimes URIs like "tel:+1-702-555-0100"; still a
	// plain string in that case, so this fallback rarely triggers. Any
	// other shape (number, object) is not a value this package uses.
	return ""
}

// jcardJoinedValue reads a jCard value that may be a single string or an
// array of strings (e.g. "org" with a department component), joining an
// array with "; ".
func jcardJoinedValue(v json.RawMessage) string {
	if s := jcardScalar(v); s != "" {
		return s
	}
	var arr []string
	if err := json.Unmarshal(v, &arr); err == nil {
		return strings.Join(nonEmpty(arr), "; ")
	}
	return ""
}

// jcardFillAddress reads an RFC 6350 §6.3.1 structured ADR value — a
// 7-element array [pobox, ext, street, locality, region, postalCode,
// country] — onto a Contact's address fields. Any component may itself be
// an array (multi-value component); those are joined with ", ". A
// malformed/short array leaves the fields it can't reach untouched.
func jcardFillAddress(v json.RawMessage, c *gen.Contact) {
	var arr []json.RawMessage
	if err := json.Unmarshal(v, &arr); err != nil {
		return
	}
	get := func(i int) string {
		if i >= len(arr) {
			return ""
		}
		if s := jcardScalar(arr[i]); s != "" {
			return s
		}
		var sub []string
		if err := json.Unmarshal(arr[i], &sub); err == nil {
			return strings.Join(nonEmpty(sub), ", ")
		}
		return ""
	}
	street := strings.TrimSpace(get(2))
	if pobox := get(0); pobox != "" {
		street = strings.TrimSpace(pobox + " " + street)
	}
	if street != "" {
		c.Street = street
	}
	if v := get(3); v != "" {
		c.City = v
	}
	if v := get(4); v != "" {
		c.Province = v
	}
	if v := get(5); v != "" {
		c.PostalCode = v
	}
	if v := get(6); v != "" {
		c.Country = v
	}
}

// jcardHasParamValue reports whether a jCard property's parameter object
// (fields[1], e.g. {"type": "fax"} or {"type": ["fax", "voice"]}) contains
// the given value for the given key, case-insensitively.
func jcardHasParamValue(params json.RawMessage, key, value string) bool {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(params, &m); err != nil {
		return false
	}
	raw, ok := m[key]
	if !ok {
		return false
	}
	if s := jcardScalar(raw); strings.EqualFold(s, value) {
		return true
	}
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil {
		for _, s := range arr {
			if strings.EqualFold(s, value) {
				return true
			}
		}
	}
	return false
}

func nonEmpty(ss []string) []string {
	out := make([]string, 0, len(ss))
	for _, s := range ss {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// rdapNumberToInt32 is a small helper kept for symmetry with the other
// numeric conversions in this file; used where an RDAP-sourced number
// needs to become a proto int32 defensively (never panics on overflow —
// clamps instead).
func rdapNumberToInt32(n json.Number) int32 {
	i, err := strconv.ParseInt(n.String(), 10, 32)
	if err != nil {
		return 0
	}
	return int32(i)
}
