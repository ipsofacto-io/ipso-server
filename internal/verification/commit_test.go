package verification

import (
	"errors"
	"strings"
	"testing"
)

// Commit returns the commit in the form an upload stores it and refuses anything else, so a caller checks a request
// before it reads (ADR-0124 decision 1).
func TestCommitReadsALowercaseOrUppercaseCommitAndRefusesAnythingElse(t *testing.T) {
	sha := strings.Repeat("ab", 20)
	long := strings.Repeat("0f", 32)
	for name, tc := range map[string]struct{ in, want string }{
		"sha-1":          {sha, sha},
		"sha-256":        {long, long},
		"upper case":     {strings.ToUpper(sha), sha},
		"mixed case":     {"AbAbAbAbAbAbAbAbAbAbAbAbAbAbAbAbAbAbAbAb", sha},
		"sha-256 upper":  {strings.ToUpper(long), long},
		"all zero digit": {strings.Repeat("0", 40), strings.Repeat("0", 40)},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := Commit(tc.in)
			if err != nil || got != tc.want {
				t.Errorf("Commit(%q) = %q, %v, want %q", tc.in, got, err, tc.want)
			}
		})
	}
	for name, in := range map[string]string{
		"empty":           "",
		"short":           sha[:39],
		"long":            sha + "a",
		"between lengths": strings.Repeat("ab", 25),
		"not hexadecimal": strings.Repeat("zz", 20),
		"a branch":        "main",
		"a short sha":     "abc1234",
		"padded":          " " + sha,
		"a newline":       sha + "\n",
		"a prefix":        "sha1:" + sha,
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := Commit(in); !errors.Is(err, ErrInvalid) || got != "" {
				t.Errorf("Commit(%q) = %q, %v, want ErrInvalid", in, got, err)
			}
		})
	}
}
