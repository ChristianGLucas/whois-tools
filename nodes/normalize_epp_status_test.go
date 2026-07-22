package nodes_test

import (
	"context"
	"strings"
	"testing"

	gen "christiangeorgelucas/whois-tools/gen"
	"christiangeorgelucas/whois-tools/nodes"
)

// TestNormalizeEppStatus_Table checks every input form a source expresses
// a status in against the ICANN EPP status vocabulary (icann.org/epp) —
// the independent oracle here is the published EPP registry itself: these
// code/category/client-vs-server facts are common domain-industry
// knowledge, not derived from this package's own code.
func TestNormalizeEppStatus_Table(t *testing.T) {
	cases := []struct {
		name         string
		status       string
		wantCode     string
		wantCategory string
		wantClient   bool
		wantServer   bool
	}{
		{"bare client code", "clientTransferProhibited", "clientTransferProhibited", "transfer", true, false},
		{"bare server code", "serverHold", "serverHold", "hold", false, true},
		{"rdap epp url", "https://icann.org/epp#pendingDelete", "pendingDelete", "delete", false, false},
		{"icann www epp url", "https://www.icann.org/epp#clientDeleteProhibited", "clientDeleteProhibited", "delete", true, false},
		{"whois domain status line", "Domain Status: serverUpdateProhibited (https://icann.org/epp#serverUpdateProhibited)", "serverUpdateProhibited", "update", false, true},
		{"ok status", "ok", "ok", "general", false, false},
		{"grace period", "addPeriod", "addPeriod", "general", false, false},
		{"unrecognized status", "totallyMadeUpStatus", "", "", false, false},
	}

	ctx := context.Background()
	ax := newTestContext(t)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := nodes.NormalizeEppStatus(ctx, ax, &gen.NormalizeEppStatusInput{Status: tc.status})
			if err != nil {
				t.Fatalf("unexpected go error: %v", err)
			}
			if got.GetError() != nil {
				t.Fatalf("unexpected structured error: %+v", got.GetError())
			}
			if got.GetCode() != tc.wantCode {
				t.Errorf("Code = %q, want %q", got.GetCode(), tc.wantCode)
			}
			if got.GetCategory() != tc.wantCategory {
				t.Errorf("Category = %q, want %q", got.GetCategory(), tc.wantCategory)
			}
			if got.GetIsClientStatus() != tc.wantClient {
				t.Errorf("IsClientStatus = %v, want %v", got.GetIsClientStatus(), tc.wantClient)
			}
			if got.GetIsServerStatus() != tc.wantServer {
				t.Errorf("IsServerStatus = %v, want %v", got.GetIsServerStatus(), tc.wantServer)
			}
			if got.GetRaw() != tc.status {
				t.Errorf("Raw = %q, want %q (must preserve original)", got.GetRaw(), tc.status)
			}
			if tc.wantCode != "" && got.GetDescription() == "" {
				t.Errorf("Description is empty for recognized code %q", tc.wantCode)
			}
		})
	}
}

func TestNormalizeEppStatus_EmptyInput(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)
	got, err := nodes.NormalizeEppStatus(ctx, ax, &gen.NormalizeEppStatusInput{Status: ""})
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if got.GetError() != nil {
		t.Fatalf("empty status should not itself be an error condition for this node: %+v", got.GetError())
	}
	if got.GetCode() != "" || got.GetRaw() != "" {
		t.Errorf("expected zero-value EppStatus, got %+v", got)
	}
}

func TestNormalizeEppStatus_TooLarge(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)
	got, err := nodes.NormalizeEppStatus(ctx, ax, &gen.NormalizeEppStatusInput{Status: strings.Repeat("x", 5000)})
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if got.GetError() == nil || got.GetError().GetCode() != "INPUT_TOO_LARGE" {
		t.Fatalf("Error = %+v, want INPUT_TOO_LARGE", got.GetError())
	}
}
