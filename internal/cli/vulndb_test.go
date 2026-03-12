package cli

import "testing"

func TestSanitizeSourceLabel(t *testing.T) {
	if got := sanitizeSourceLabel("https://user:secret@example.com/feed.csv?token=abc#frag"); got != "https://example.com/feed.csv" {
		t.Fatalf("expected sanitized source label, got %q", got)
	}
	if got := sanitizeSourceLabel("/tmp/feed.csv"); got != "/tmp/feed.csv" {
		t.Fatalf("expected local path to remain unchanged, got %q", got)
	}
}
