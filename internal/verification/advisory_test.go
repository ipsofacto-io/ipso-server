package verification

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSanitizeAdvisoryTextAndReason(t *testing.T) {
	in := "Adds [MySQL](https://evil.example) www.evil.example javascript:alert(1) data:text/html,<b>x</b> vbscript:msgbox(1) <script> @alice\x00\u202e\nnext"
	got := SanitizeAdvisoryReason(in)
	for _, forbidden := range []string{"https://", "www.", "javascript:", "data:", "vbscript:", "<script>", "<b>", "@alice", "[MySQL]", "\x00", "\u202e", "\n"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("forbidden token %q survived SanitizeAdvisoryReason: %q", forbidden, got)
		}
	}
	if !strings.Contains(got, "Adds MySQL") || !strings.Contains(got, "[mention removed]") {
		t.Fatalf("unexpected sanitized output: %q", got)
	}

	// Scrubbing to empty falls back to a non-empty plain-text placeholder for OpenAPI minLength: 1.
	if fb := SanitizeAdvisoryReason("https://evil.example <>"); fb != "Advisory verdict." {
		t.Fatalf("fallback = %q, want %q", fb, "Advisory verdict.")
	}

	// Scrubbing that expands mentions stays capped within MaxReasonRunes (300).
	manyMentions := strings.Repeat("@a ", 80)
	capped := SanitizeAdvisoryReason(manyMentions)
	if n := utf8.RuneCountInString(capped); n == 0 || n > MaxReasonRunes {
		t.Fatalf("capped rune count = %d, want 1..%d", n, MaxReasonRunes)
	}

	if lbl := SanitizeAdvisoryLabel("mistral-<medium>\x00\n"); lbl != "mistral-medium" {
		t.Fatalf("label = %q, want %q", lbl, "mistral-medium")
	}
}
