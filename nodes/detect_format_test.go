package nodes_test

import (
	"context"
	"strings"
	"testing"

	gen "christiangeorgelucas/whois-tools/gen"
	"christiangeorgelucas/whois-tools/nodes"
)

func TestDetectFormat_Whois(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)

	got, err := nodes.DetectFormat(ctx, ax, &gen.DetectFormatInput{Text: googleComWhois})
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if got.GetError() != nil {
		t.Fatalf("unexpected structured error: %+v", got.GetError())
	}
	if got.GetFormat() != "whois" {
		t.Errorf("Format = %q, want whois", got.GetFormat())
	}
	if got.GetConfidence() < 0.5 {
		t.Errorf("Confidence = %v, want >= 0.5", got.GetConfidence())
	}
}

func TestDetectFormat_Rdap(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)

	got, err := nodes.DetectFormat(ctx, ax, &gen.DetectFormatInput{Text: exampleDomainRdap})
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if got.GetError() != nil {
		t.Fatalf("unexpected structured error: %+v", got.GetError())
	}
	if got.GetFormat() != "rdap" {
		t.Errorf("Format = %q, want rdap", got.GetFormat())
	}
	if got.GetConfidence() < 0.9 {
		t.Errorf("Confidence = %v, want >= 0.9 (objectClassName marker present)", got.GetConfidence())
	}
}

func TestDetectFormat_Unknown(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)

	got, err := nodes.DetectFormat(ctx, ax, &gen.DetectFormatInput{Text: "just a plain sentence with no structure at all, nothing to see here"})
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if got.GetFormat() != "unknown" {
		t.Errorf("Format = %q, want unknown", got.GetFormat())
	}
}

func TestDetectFormat_EmptyInput(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)

	got, err := nodes.DetectFormat(ctx, ax, &gen.DetectFormatInput{Text: ""})
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if got.GetError() == nil || got.GetError().GetCode() != "EMPTY_INPUT" {
		t.Fatalf("Error = %+v, want EMPTY_INPUT", got.GetError())
	}
}

func TestDetectFormat_TooLarge(t *testing.T) {
	ctx := context.Background()
	ax := newTestContext(t)

	huge := strings.Repeat("a", 700*1024)
	got, err := nodes.DetectFormat(ctx, ax, &gen.DetectFormatInput{Text: huge})
	if err != nil {
		t.Fatalf("unexpected go error: %v", err)
	}
	if got.GetError() == nil || got.GetError().GetCode() != "INPUT_TOO_LARGE" {
		t.Fatalf("Error = %+v, want INPUT_TOO_LARGE", got.GetError())
	}
}
