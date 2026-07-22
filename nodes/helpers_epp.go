package nodes

import (
	"regexp"
	"strings"

	gen "christiangeorgelucas/whois-tools/gen"
)

// eppStatusDef is one row of the ICANN EPP (RFC 5731) status vocabulary
// (icann.org/epp): the bare status code plus a human-readable description
// and category, written independently of any wrapped library — this is a
// static reference table, not parsed from anywhere.
type eppStatusDef struct {
	description string
	category    string
}

// eppStatusTable is the complete EPP domain/host/contact status vocabulary
// (RFC 5731 domain statuses; the same words are reused for IP-network
// registry objects by RDAP). Keys are the bare lowerCamelCase EPP code.
var eppStatusTable = map[string]eppStatusDef{
	"ok":               {"No pending operations or restrictions; the object is in its normal state.", "general"},
	"inactive":         {"The object is missing information required for it to function (e.g. a domain with no delegated name servers).", "general"},
	"addPeriod":        {"Within the add grace period following initial creation; the object may be deleted for a full credit.", "general"},
	"autoRenewPeriod":  {"Within the grace period following an automatic (system) renewal; the object may be deleted for a credit.", "general"},
	"renewPeriod":      {"Within the grace period following an explicit renewal; the object may be deleted for a credit.", "general"},
	"transferPeriod":   {"Within the grace period following a transfer to a new sponsor; the object may be deleted for a credit.", "general"},
	"redemptionPeriod": {"The object has been deleted and is in its redemption grace period; it can still be restored by its sponsor.", "delete"},
	"pendingCreate":    {"A create request has been accepted but the create operation has not completed.", "general"},
	"pendingDelete":    {"A delete request has been accepted; unless restored, the object will be purged after the pending-delete period.", "delete"},
	"pendingRenew":     {"A renew request has been accepted but the renew operation has not completed.", "general"},
	"pendingRestore":   {"A restore request has been accepted but the registrar has not yet submitted the required restore report.", "delete"},
	"pendingTransfer":  {"A transfer request has been accepted but is awaiting approval, rejection, or auto-approval by the losing sponsor.", "transfer"},
	"pendingUpdate":    {"An update request has been accepted but the update operation has not completed.", "general"},

	"clientDeleteProhibited":   {"The sponsoring registrar has requested that the object not be deleted.", "delete"},
	"serverDeleteProhibited":   {"The registry has placed a hold preventing the object from being deleted.", "delete"},
	"clientHold":               {"The sponsoring registrar has requested that the domain be removed (held) from the zone.", "hold"},
	"serverHold":               {"The registry has removed (held) the domain from the zone.", "hold"},
	"clientRenewProhibited":    {"The sponsoring registrar has requested that the object not be renewed.", "renew"},
	"serverRenewProhibited":    {"The registry has placed a hold preventing the object from being renewed.", "renew"},
	"clientTransferProhibited": {"The sponsoring registrar has requested that the object not be transferred to another registrar.", "transfer"},
	"serverTransferProhibited": {"The registry has placed a hold preventing the object from being transferred.", "transfer"},
	"clientUpdateProhibited":   {"The sponsoring registrar has requested that the object not be updated.", "update"},
	"serverUpdateProhibited":   {"The registry has placed a hold preventing the object from being updated.", "update"},
}

// eppCodeExtract matches a bare EPP status token: an optional client/server
// prefix followed by a capitalized word, e.g. "clientTransferProhibited" or
// "pendingDelete" or "ok". Used to pull the code out of noisier source text
// ("Domain Status: clientTransferProhibited (https://icann.org/epp#...)").
var eppCodeExtract = regexp.MustCompile(`(?i)\b((?:client|server)?[a-zA-Z]+(?:Prohibited|Period|Create|Delete|Renew|Restore|Transfer|Update|Hold)|ok|inactive)\b`)

// eppCodeCanonical maps a lowercase code back to its canonical mixed-case
// spelling for table lookup (source text is not always consistently cased).
var eppCodeCanonical = buildEppCodeCanonical()

func buildEppCodeCanonical() map[string]string {
	m := make(map[string]string, len(eppStatusTable))
	for k := range eppStatusTable {
		m[strings.ToLower(k)] = k
	}
	return m
}

// normalizeEppStatusText extracts and normalizes a single EPP status token
// from arbitrary source text (a bare code, a "Domain Status:" line, or a
// full RDAP "https://icann.org/epp#code" URL). Always returns a non-nil
// EppStatus with `raw` set to the original text; `code`/`description`/
// `category` are left empty when no known EPP code is recognized.
func normalizeEppStatusText(raw string) *gen.EppStatus {
	out := &gen.EppStatus{Raw: raw}

	candidate := raw
	if idx := strings.LastIndex(raw, "#"); idx >= 0 && idx+1 < len(raw) {
		// RDAP form: "https://icann.org/epp#clientTransferProhibited"
		candidate = raw[idx+1:]
	}

	code := ""
	if canon, ok := eppCodeCanonical[strings.ToLower(strings.TrimSpace(candidate))]; ok {
		code = canon
	} else if m := eppCodeExtract.FindStringSubmatch(candidate); m != nil {
		if canon, ok := eppCodeCanonical[strings.ToLower(m[1])]; ok {
			code = canon
		}
	} else if m := eppCodeExtract.FindStringSubmatch(raw); m != nil {
		if canon, ok := eppCodeCanonical[strings.ToLower(m[1])]; ok {
			code = canon
		}
	}

	if code == "" {
		return out
	}

	def := eppStatusTable[code]
	out.Code = code
	out.Description = def.description
	out.Category = def.category
	out.IsClientStatus = strings.HasPrefix(code, "client")
	out.IsServerStatus = strings.HasPrefix(code, "server")
	return out
}
