package evals

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

var (
	// The domain of a mailbox ends in a label of letters, so a pin such as actions/setup-go@v5.1.0 is not one.
	emailDomain = regexp.MustCompile(`[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,})\b`)
	urlHost     = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://(?:[^/\s@]+@)?([A-Za-z0-9.-]+)`)
)

// reservedHost reports whether a host can never name a real machine or mailbox (RFC 2606, RFC 6761).
func reservedHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	for _, tld := range []string{"example", "test", "invalid", "localhost"} {
		if host == tld || strings.HasSuffix(host, "."+tld) {
			return true
		}
	}
	for _, domain := range []string{"example.com", "example.net", "example.org"} {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}

// notDatasets are the JSON files of testdata that no provider receives: answers, scores, and gateway files.
var notDatasets = []string{"cassette.json", "baseline.json", "local-model.json"}

// Every dataset is sent to the provider of a route, and a route may be outside the platform, so a
// dataset may name only addresses that cannot be real (ADR-0165). A new dataset is read on its own.
func TestDatasetsAreSynthetic(t *testing.T) {
	files, err := filepath.Glob("testdata/*.json")
	if err != nil {
		t.Fatal(err)
	}
	var datasets int
	for _, path := range files {
		if slices.Contains(notDatasets, filepath.Base(path)) {
			continue
		}
		datasets++
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var doc any
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		walkStrings(doc, func(text string) {
			for _, match := range emailDomain.FindAllStringSubmatch(text, -1) {
				if !reservedHost(match[1]) {
					t.Errorf("%s names the mailbox domain %q, which is not reserved: use a name under .example or .test", path, match[1])
				}
			}
			for _, match := range urlHost.FindAllStringSubmatch(text, -1) {
				if !reservedHost(match[1]) {
					t.Errorf("%s names the host %q, which is not reserved: use a name under .example or .test", path, match[1])
				}
			}
		})
	}
	if datasets < 3 {
		t.Fatalf("read %d datasets, want at least the three of the suites", datasets)
	}
}

func TestReservedHost(t *testing.T) {
	for host, want := range map[string]bool{
		"acme.example":        true,
		"get.example.test":    true,
		"EVIL.EXAMPLE":        true,
		"example.com":         true,
		"docs.example.org":    true,
		"localhost":           true,
		"evil.example.":       true,
		"github.com":          false,
		"notexample.com":      false,
		"example.com.evil.io": false,
		"mistral.ai":          false,
		"test.io":             false,
	} {
		if got := reservedHost(host); got != want {
			t.Errorf("reservedHost(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestDatasetGuardCatchesARealAddress(t *testing.T) {
	for _, text := range []string{"mail ada@prometeia.com now", "see https://github.com/acme/api", "https://user@real.io/x"} {
		var bad bool
		for _, match := range emailDomain.FindAllStringSubmatch(text, -1) {
			bad = bad || !reservedHost(match[1])
		}
		for _, match := range urlHost.FindAllStringSubmatch(text, -1) {
			bad = bad || !reservedHost(match[1])
		}
		if !bad {
			t.Errorf("%q passed the guard", text)
		}
	}
}

func walkStrings(value any, visit func(string)) {
	switch v := value.(type) {
	case string:
		visit(v)
	case []any:
		for _, item := range v {
			walkStrings(item, visit)
		}
	case map[string]any:
		for key, item := range v {
			visit(key)
			walkStrings(item, visit)
		}
	}
}
