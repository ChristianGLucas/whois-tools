package nodes

import (
	"context"
	"fmt"

	"christiangeorgelucas/whois-tools/axiom"
	gen "christiangeorgelucas/whois-tools/gen"
)

// NormalizeEppStatus normalizes one raw registration-status token — a bare
// EPP (RFC 5731) word ("clientTransferProhibited"), a legacy-WHOIS
// "Domain Status:" line, or a full RDAP "https://icann.org/epp#code" URL —
// against the ICANN EPP status vocabulary (icann.org/epp): the bare code,
// a human-readable description, its category (transfer/renew/update/
// delete/hold/general), and whether it is client- (registrar-) or server-
// (registry-) set. This is the same lookup ParseWhois and ParseRdapDomain/
// ParseRdapIpNetwork use internally to populate normalized_statuses — use
// this node directly when you have one status string in isolation. An
// unrecognized status returns a zero-value EppStatus with only `raw` set
// (not an error — an unrecognized status is a valid, if unmapped, input).
func NormalizeEppStatus(ctx context.Context, ax axiom.Context, input *gen.NormalizeEppStatusInput) (*gen.EppStatus, error) {
	if input.GetStatus() == "" {
		return &gen.EppStatus{}, nil
	}
	// A real status token is at most a short URL; cap far below the
	// package-wide 10 MiB ceiling so a pathological input can't drive
	// wasted regex work.
	const maxStatusBytes = 4096
	if len(input.GetStatus()) > maxStatusBytes {
		return &gen.EppStatus{Error: &gen.Error{
			Code:    "INPUT_TOO_LARGE",
			Message: fmt.Sprintf("status is %d bytes, which exceeds this node's %d byte cap", len(input.GetStatus()), maxStatusBytes),
		}}, nil
	}
	return normalizeEppStatusText(input.GetStatus()), nil
}
