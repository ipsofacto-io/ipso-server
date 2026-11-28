package registry

import (
	"strings"
	"testing"
)

func TestValidPathAcceptsWhatResolvePathsAccepts(t *testing.T) {
	for p, want := range map[string]bool{
		"main.go":                        true,
		"docs/adr/0001-use-go.md":        true,
		"dir with space/a.go":            true,
		"":                               false,
		"/abs":                           false,
		"a//b":                           false,
		"a/./b":                          false,
		"../a":                           false,
		"a/b/":                           false,
		"tab\there":                      false,
		"\xff":                           false,
		strings.Repeat("a", 4097):        false,
		strings.Repeat("a/", 2047) + "a": true,
	} {
		if got := ValidPath(p); got != want {
			t.Errorf("ValidPath(%q) = %v, want %v", p, got, want)
		}
	}
}
