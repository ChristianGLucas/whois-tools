package nodes

import "time"

// flexibleDateLayouts covers the date/time forms this package's own output
// produces (RFC 3339, from bestDate) plus a bare calendar date, which is
// the natural form a caller supplies for `as_of`.
var flexibleDateLayouts = []string{
	time.RFC3339,
	"2006-01-02T15:04:05Z",
	"2006-01-02",
}

func parseFlexibleDate(s string) (time.Time, bool) {
	for _, layout := range flexibleDateLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}
