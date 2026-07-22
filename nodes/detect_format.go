package nodes

import (
	"context"
	"strings"

	"christiangeorgelucas/whois-tools/axiom"
	gen "christiangeorgelucas/whois-tools/gen"
)

// DetectFormat is a routing helper for a flow that has a text blob of
// unknown origin and needs to decide whether to send it to ParseWhois or a
// ParseRdap* node: heuristically classifies the text as "rdap" (JSON
// starting with '{' or '[' that contains an RDAP marker key like
// "objectClassName"/"rdapConformance"), "whois" (colon-delimited-field
// text with a recognizable WHOIS marker like "Domain Name:"/"registrar:"),
// or "unknown". Pure string inspection — never parses the text as JSON.
func DetectFormat(ctx context.Context, ax axiom.Context, input *gen.DetectFormatInput) (*gen.DetectFormatResult, error) {
	text := input.GetText()
	if text == "" {
		return &gen.DetectFormatResult{Error: errEmptyInput("text")}, nil
	}

	trimmed := strings.TrimSpace(text)
	lowerHead := strings.ToLower(trimmed)

	looksLikeJSON := len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[')
	hasRdapMarker := strings.Contains(lowerHead, "objectclassname") ||
		strings.Contains(lowerHead, "rdapconformance") ||
		strings.Contains(lowerHead, "vcardarray")

	if looksLikeJSON && hasRdapMarker {
		return &gen.DetectFormatResult{Format: "rdap", Confidence: 0.95}, nil
	}
	if looksLikeJSON {
		return &gen.DetectFormatResult{Format: "rdap", Confidence: 0.55}, nil
	}

	whoisMarkers := []string{"domain name:", "registrar:", "registrar whois server:", "creation date:", "name server:", "whois server:", "registry domain id:"}
	hits := 0
	for _, m := range whoisMarkers {
		if strings.Contains(lowerHead, m) {
			hits++
		}
	}
	if hits > 0 {
		confidence := 0.5 + 0.1*float64(hits)
		if confidence > 0.95 {
			confidence = 0.95
		}
		return &gen.DetectFormatResult{Format: "whois", Confidence: confidence}, nil
	}
	// Fall back to a loose heuristic: WHOIS text is dominated by
	// "Label: value" lines; if most non-blank lines match that shape,
	// call it WHOIS at low confidence.
	lines := strings.Split(trimmed, "\n")
	nonBlank, colonLines := 0, 0
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		nonBlank++
		if strings.Contains(l, ":") {
			colonLines++
		}
	}
	if nonBlank >= 3 && float64(colonLines)/float64(nonBlank) > 0.6 {
		return &gen.DetectFormatResult{Format: "whois", Confidence: 0.4}, nil
	}

	return &gen.DetectFormatResult{Format: "unknown", Confidence: 0.0}, nil
}
