package registry

import (
	"errors"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestSearchTermsTokenizesAndBoundsPrefixes(t *testing.T) {
	tests := []struct {
		name string
		q    string
		want []termRange
	}{
		{
			name: "empty and whitespace",
			q:    "   \t\n ",
			want: nil,
		},
		{
			name: "punctuation only",
			q:    "--- ... ??? !!! ()",
			want: nil,
		},
		{
			name: "single word lowercased",
			q:    "  Firewall? ",
			want: []termRange{{lo: "firewall", hi: "firewalm"}},
		},
		{
			name: "multi-word deduplicated preserving order",
			q:    "Prod fire PROD",
			want: []termRange{
				{lo: "prod", hi: "proe"},
				{lo: "fire", hi: "firf"},
			},
		},
		{
			name: "hyphenated slug and dotted host preserved, underscores and slashes split",
			q:    "deny-eg vault.int 0.0.0.0/0 pci_dss",
			want: []termRange{
				{lo: "deny-eg", hi: "deny-eh"},
				{lo: "vault.int", hi: "vault.inu"},
				{lo: "0.0.0.0", hi: "0.0.0.1"},
				{lo: "0", hi: "1"},
				{lo: "pci", hi: "pcj"},
				{lo: "dss", hi: "dst"},
			},
		},
		{
			name: "leading and trailing hyphens and dots trimmed",
			q:    "--deny-eg-- .tls.",
			want: []termRange{
				{lo: "deny-eg", hi: "deny-eh"},
				{lo: "tls", hi: "tlt"},
			},
		},
		{
			name: "non-ASCII UTF-8 produces valid UTF-8 upper bound",
			q:    "café über",
			want: []termRange{
				{lo: "café", hi: "cafê"},
				{lo: "über", hi: "übes"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := searchTerms(tc.q)
			if err != nil {
				t.Fatalf("searchTerms(%q) unexpected error: %v", tc.q, err)
			}
			if !slices.Equal(got, tc.want) {
				t.Fatalf("searchTerms(%q) = %+v, want %+v", tc.q, got, tc.want)
			}
			for _, tr := range got {
				if !utf8.ValidString(tr.lo) || !utf8.ValidString(tr.hi) {
					t.Fatalf("invalid UTF-8 bound: %+v", tr)
				}
				if tr.hi != "" && !(tr.lo < tr.hi) {
					t.Fatalf("expected lo < hi in byte order: %+v", tr)
				}
			}
		})
	}
}

func TestSearchTermsCapsLengthAndRejectsTooManyTerms(t *testing.T) {
	longTok := strings.Repeat("a", 200)
	got, err := searchTerms(longTok)
	if err != nil {
		t.Fatalf("unexpected error on long token: %v", err)
	}
	if len(got) != 1 || utf8.RuneCountInString(got[0].lo) != maxSearchTermRunes {
		t.Fatalf("expected single %d-rune term, got %+v", maxSearchTermRunes, got)
	}

	var exact []string
	for i := range maxSearchTerms {
		exact = append(exact, string(rune('a'+i%26))+strings.Repeat("x", i+1))
	}
	// Repeating already-seen tokens does not exceed the distinct-term limit.
	exactWithDup := append(exact, exact[0])
	gotExact, err := searchTerms(strings.Join(exactWithDup, " "))
	if err != nil || len(gotExact) != maxSearchTerms {
		t.Fatalf("exact cap with duplicate: got (%d, %v), want (%d, nil)", len(gotExact), err, maxSearchTerms)
	}

	tooMany := append(exact, "overflowtoken")
	if _, err := searchTerms(strings.Join(tooMany, " ")); !errors.Is(err, ErrInvalidQuery) {
		t.Fatalf("expected ErrInvalidQuery when exceeding %d terms, got %v", maxSearchTerms, err)
	}
}

func TestNextUTF8PrefixEdgeCases(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"a", "b"},
		{"\u007f", "\u0080"},
		{"\uD7FF", "\uE000"},
		{"a" + string(utf8.MaxRune), "b"},
		{string(utf8.MaxRune), ""},
		{string(utf8.MaxRune) + string(utf8.MaxRune), ""},
	}
	for _, tc := range tests {
		got := nextUTF8Prefix(tc.in)
		if got != tc.want {
			t.Errorf("nextUTF8Prefix(%q) = %q, want %q", tc.in, got, tc.want)
		}
		if !utf8.ValidString(got) {
			t.Errorf("nextUTF8Prefix(%q) produced invalid UTF-8", tc.in)
		}
		if got != "" {
			// Every string starting with tc.in must be strictly less than got in byte order.
			if !(tc.in < got) || !(tc.in+"z" < got) || !(tc.in+string(utf8.MaxRune) < got) {
				t.Errorf("bytewise bound violated for %q -> %q", tc.in, got)
			}
		}
	}
}
