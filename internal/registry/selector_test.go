package registry

import (
	"database/sql"
	"errors"
	"regexp"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

// selectorCases is shared with the integration test that requires PostgreSQL to agree. A repo
// case must start with the owner "acme" when it is valid, because the database also requires
// the owner to be the org of the parent.
var (
	validNames = []string{"a", "acme", "payments-domain", "a.b_c-d", "0abc", strings.Repeat("a", 63)}
	badNames   = []string{"", "Acme", "-acme", ".acme", "_acme", "a b", "a/b", "a*", "é", "a\n", strings.Repeat("a", 64)}

	validRepos = []string{
		"acme/payments", "acme/infra-*", "acme/*", "acme/a?c", "acme/.github", "acme/a.b_c-d",
		"acme/group/sub/service", "acme/g*/s?", "acme/" + strings.Repeat("a", 100),
	}
	badRepos = []string{
		"", "acme", "acme/", "/payments", "acme//x", "Acme/x", "acme/Payments", "acme/a b", "acme/..", "acme/.",
		"acme/a/../b", "acme/**", "acme/a**b", "acme/a[b]", "acme/a{b}", "acme/a\\b", "acme/é", "acme/a\n",
		"-acme/x", "acme/" + strings.Repeat("a", 101), "acme/" + strings.Repeat("a/", 11) + "a",
		"acme/" + strings.Repeat("a", 100) + "/" + strings.Repeat("b", 100) + "/" + strings.Repeat("c", 100),
	}

	validPaths = []string{
		"**", "*", "terraform/**", "**/main.tf", "a/**/b", "src/*.go", "src/?.go", ".github/workflows/*.yml",
		"a/b/c", "a.b", "a^b", "a|b~c", "\"q\"", "x`y", "p@q#r$s%t&u'v(w)x+y,z:w;<=>", "**/**", strings.Repeat("a", 255),
	}
	badPaths = []string{
		"", "/a", "a/", "a//b", "a/./b", "a/../b", ".", "..", "a b", "a!b", "a[b]", "a{b}", "a\\b", "a**", "**a",
		"a/b**", "a/**b", "***", "a/***/b", "é", "a\nb", "a\tb", strings.Repeat("a", 256),
	}
)

func TestSelectorGrammar(t *testing.T) {
	check := func(t *testing.T, kind string, valid, invalid []string, parse func(string) error) {
		t.Helper()
		for _, s := range valid {
			if err := parse(s); err != nil {
				t.Errorf("%s %q rejected: %v", kind, s, err)
			}
		}
		for _, s := range invalid {
			err := parse(s)
			if !errors.Is(err, ErrInvalidSelector) {
				t.Errorf("%s %q: err = %v, want ErrInvalidSelector", kind, s, err)
			}
		}
	}
	check(t, "name", validNames, badNames, validateName)
	check(t, "repo", validRepos, badRepos, func(s string) error { _, err := parseRepoSelector(s); return err })
	check(t, "path", validPaths, badPaths, func(s string) error { _, err := parsePathSelector(s); return err })
}

func segments(s string) []string {
	return strings.Split(s, "/")
}

func TestRepoMatching(t *testing.T) {
	tests := []struct {
		pattern, repo string
		want          bool
	}{
		{"acme/payments", "acme/payments", true},
		{"acme/payments", "acme/payment", false},
		{"acme/payments", "acme/payments2", false},
		{"acme/infra-*", "acme/infra-prod", true},
		{"acme/infra-*", "acme/infra-", true},
		{"acme/infra-*", "acme/infra", false},
		{"acme/infra-*", "acme/team/infra-prod", false},
		{"acme/*", "acme/payments", true},
		{"acme/*", "acme/a/b", false},
		{"acme/a?c", "acme/abc", true},
		{"acme/a?c", "acme/ac", false},
		{"acme/a?c", "acme/abbc", false},
		{"acme/g*/s?", "acme/grp/s1", true},
		{"acme/g*/s?", "acme/grp/s12", false},
		{"acme/group/*", "acme/group/svc", true},
		{"acme/group/*", "acme/other/svc", false},
		{"acme/.github", "acme/.github", true},
		{"acme/*", "acme/.github", true},
	}
	for _, tt := range tests {
		pattern, err := parseRepoSelector(tt.pattern)
		if err != nil {
			t.Fatalf("parse %q: %v", tt.pattern, err)
		}
		if got := pattern.matches(segments(tt.repo)); got != tt.want {
			t.Errorf("repo %q against %q = %v, want %v", tt.pattern, tt.repo, got, tt.want)
		}
	}
}

func TestPathMatching(t *testing.T) {
	tests := []struct {
		pattern, path string
		want          bool
	}{
		// A pattern is anchored at the repository root.
		{"main.tf", "main.tf", true},
		{"main.tf", "infra/main.tf", false},
		{"infra/main.tf", "infra/main.tf", true},
		{"infra/main.tf", "x/infra/main.tf", false},

		{"terraform/**", "terraform", true},
		{"terraform/**", "terraform/main.tf", true},
		{"terraform/**", "terraform/a/b/c.tf", true},
		{"terraform/**", "terraformer/main.tf", false},
		{"terraform/**", "x/terraform/main.tf", false},

		{"**", "a", true},
		{"**", "a/b/c", true},
		{"**/main.tf", "main.tf", true},
		{"**/main.tf", "a/main.tf", true},
		{"**/main.tf", "a/b/main.tf", true},
		{"**/main.tf", "a/main.tfx", false},
		{"a/**/b", "a/b", true},
		{"a/**/b", "a/x/b", true},
		{"a/**/b", "a/x/y/b", true},
		{"a/**/b", "a/x/y/c", false},
		{"a/**/b/**/c", "a/b/c", true},
		{"a/**/b/**/c", "a/1/b/2/3/c", true},
		{"a/**/b/**/c", "a/1/c/b", false},
		{"**/**", "a/b", true},

		{"*", "a", true},
		{"*", "a/b", false},
		{"*/main.tf", "infra/main.tf", true},
		{"*/main.tf", "a/b/main.tf", false},
		{"src/*.go", "src/a.go", true},
		{"src/*.go", "src/a/b.go", false},
		{"src/*.go", "src/.go", true},
		{"src/?.go", "src/a.go", true},
		{"src/?.go", "src/ab.go", false},
		{"*.tf", ".hidden.tf", true},

		// Path matching is case-sensitive, and a subject may hold any UTF-8 character.
		{"src/*.go", "src/A.GO", false},
		{"src/*", "src/é.go", true},
		{"src/?.go", "src/é.go", true},
		{"src/*", "src/a b[1].go", true},
		{"src/a?b", "src/a\u00e9b", true},
	}
	for _, tt := range tests {
		pattern, err := parsePathSelector(tt.pattern)
		if err != nil {
			t.Fatalf("parse %q: %v", tt.pattern, err)
		}
		if got := pattern.matches(segments(tt.path)); got != tt.want {
			t.Errorf("path %q against %q = %v, want %v", tt.pattern, tt.path, got, tt.want)
		}
	}
}

func TestNewSubject(t *testing.T) {
	valid := []struct {
		name string
		in   Subject
		want subject
	}{
		{"repo only", Subject{Repo: "acme/payments"}, subject{org: "acme", repo: []string{"acme", "payments"}}},
		{"mixed case repo and env are lowercased", Subject{Repo: "Acme/Payments", Env: "PROD"},
			subject{org: "acme", repo: []string{"acme", "payments"}, env: "prod"}},
		{"path is kept as written", Subject{Repo: "acme/payments", Path: "Infra/a b[1].tf"},
			subject{org: "acme", repo: []string{"acme", "payments"}, path: []string{"Infra", "a b[1].tf"}, hasPath: true}},
		{"nested group", Subject{Repo: "acme/group/svc"}, subject{org: "acme", repo: []string{"acme", "group", "svc"}}},
		{"unicode path", Subject{Repo: "acme/x", Path: "docs/\u00e9t\u00e9.md"},
			subject{org: "acme", repo: []string{"acme", "x"}, path: []string{"docs", "\u00e9t\u00e9.md"}, hasPath: true}},
	}
	for _, tt := range valid {
		t.Run(tt.name, func(t *testing.T) {
			got, err := newSubject(tt.in)
			if err != nil {
				t.Fatal(err)
			}
			if got.org != tt.want.org || strings.Join(got.repo, "/") != strings.Join(tt.want.repo, "/") ||
				got.env != tt.want.env || got.hasPath != tt.want.hasPath || strings.Join(got.path, "/") != strings.Join(tt.want.path, "/") {
				t.Errorf("subject = %+v, want %+v", got, tt.want)
			}
		})
	}

	invalid := map[string]Subject{
		"no repo":              {},
		"repo without owner":   {Repo: "payments"},
		"repo with a wildcard": {Repo: "acme/pay*"},
		"repo with a space":    {Repo: "acme/a b"},
		"repo dot segment":     {Repo: "acme/.."},
		"repo non-ASCII":       {Repo: "acme/caf\u00e9"},
		"repo Kelvin sign":     {Repo: "acme/\u212Aeep"},
		"env with a space":     {Repo: "acme/x", Env: "pr od"},
		"env non-ASCII":        {Repo: "acme/x", Env: "pr\u00f6d"},
		"env Kelvin sign":      {Repo: "acme/x", Env: "\u212A"},
		"path absolute":        {Repo: "acme/x", Path: "/etc/passwd"},
		"path empty segment":   {Repo: "acme/x", Path: "a//b"},
		"path trailing slash":  {Repo: "acme/x", Path: "a/"},
		"path dot segment":     {Repo: "acme/x", Path: "a/./b"},
		"path dotdot segment":  {Repo: "acme/x", Path: "../b"},
		"path with NUL":        {Repo: "acme/x", Path: "a\x00b"},
		"path with newline":    {Repo: "acme/x", Path: "a\nb"},
		"path with DEL":        {Repo: "acme/x", Path: "a\x7fb"},
		"path invalid UTF-8":   {Repo: "acme/x", Path: "a\xffb"},
		"path too long":        {Repo: "acme/x", Path: strings.Repeat("a", maxSubjectPath+1)},
	}
	for name, in := range invalid {
		t.Run(name, func(t *testing.T) {
			if _, err := newSubject(in); !errors.Is(err, ErrInvalidSubject) {
				t.Errorf("err = %v, want ErrInvalidSubject", err)
			}
		})
	}
	if _, err := newSubject(Subject{Repo: "acme/x", Path: strings.Repeat("a", maxSubjectPath)}); err != nil {
		t.Errorf("a path of exactly %d bytes: %v", maxSubjectPath, err)
	}
}

func str(s string) sql.NullString { return sql.NullString{String: s, Valid: true} }

func TestSelects(t *testing.T) {
	prod := mustSubject(t, Subject{Repo: "acme/payments", Path: "infra/main.tf", Env: "prod"})
	noPathNoEnv := mustSubject(t, Subject{Repo: "acme/payments"})

	tests := []struct {
		name string
		s    subject
		c    candidate
		want bool
	}{
		{"org-wide node", prod, candidate{}, true},
		{"literal repo", prod, candidate{repo: str("acme/payments")}, true},
		{"other repo", prod, candidate{repo: str("acme/billing")}, false},
		{"glob repo", prod, candidate{repo: str("acme/pay*")}, true},
		{"path under the repo", prod, candidate{repo: str("acme/payments"), path: str("infra/**")}, true},
		{"path elsewhere", prod, candidate{repo: str("acme/payments"), path: str("app/**")}, false},
		{"env", prod, candidate{env: str("prod")}, true},
		{"other env", prod, candidate{env: str("dev")}, false},
		{"repo, path, and env", prod, candidate{repo: str("acme/payments"), path: str("infra/**"), env: str("prod")}, true},
		{"right repo and path, wrong env", prod, candidate{repo: str("acme/payments"), path: str("infra/**"), env: str("dev")}, false},
		{"right path and env, wrong repo", prod, candidate{repo: str("acme/billing"), path: str("infra/**"), env: str("prod")}, false},

		// A missing subject path or env widens the answer. A repo mismatch still excludes.
		{"no path matches a path node", noPathNoEnv, candidate{repo: str("acme/payments"), path: str("app/**")}, true},
		{"no env matches an env node", noPathNoEnv, candidate{env: str("dev")}, true},
		{"no path or env, wrong repo", noPathNoEnv, candidate{repo: str("acme/billing"), path: str("app/**"), env: str("dev")}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.s.selects(tt.c)
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Errorf("selects = %v, want %v", got, tt.want)
			}
		})
	}
}

// A stored value that does not parse fails the call, including an empty string that is not NULL.
func TestSelectsFailsClosedOnAStoredSelectorThatDoesNotParse(t *testing.T) {
	s := mustSubject(t, Subject{Repo: "acme/payments", Path: "a/b", Env: "prod"})
	for name, c := range map[string]candidate{
		"repo with a bracket":          {repo: str("acme/[a-z]")},
		"empty repo":                   {repo: str("")},
		"path with a bang":             {path: str("!a")},
		"empty path":                   {path: str("")},
		"env with a capital":           {env: str("Prod")},
		"empty env":                    {env: str("")},
		"repo that has a doubled star": {repo: str("acme/**")},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := s.selects(c); !errors.Is(err, ErrInvalidSelector) {
				t.Errorf("err = %v, want ErrInvalidSelector", err)
			}
		})
	}
}

func mustSubject(t *testing.T, in Subject) subject {
	t.Helper()
	s, err := newSubject(in)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestResolveRefusesBadArgumentsBeforeTouchingTheDatabase(t *testing.T) {
	// A nil database proves the checks run first: a call that reached it would panic.
	var db *sql.DB
	now := time.Now()
	tenant := uuid.MustParse("00000000-0000-4000-8000-00000000000a")

	if _, err := Resolve(t.Context(), db, uuid.Nil, Subject{Repo: "acme/x"}, now, now); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("nil tenant: err = %v, want ErrInvalidQuery", err)
	}
	if _, err := Resolve(t.Context(), db, tenant, Subject{Repo: "acme/x"}, time.Time{}, now); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("zero valid time: err = %v, want ErrInvalidQuery", err)
	}
	if _, err := Resolve(t.Context(), db, tenant, Subject{Repo: "acme/x"}, now, time.Time{}); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("zero transaction time: err = %v, want ErrInvalidQuery", err)
	}
	if _, err := Resolve(t.Context(), db, tenant, Subject{Repo: "nope"}, now, now); !errors.Is(err, ErrInvalidSubject) {
		t.Errorf("bad subject: err = %v, want ErrInvalidSubject", err)
	}
}

// refMatch is a plain recursive matcher over segments. The matcher under test must agree with it.
func refMatch(pattern, segs []string) bool {
	if len(pattern) == 0 {
		return len(segs) == 0
	}
	if pattern[0] == doubleStar {
		for i := 0; i <= len(segs); i++ {
			if refMatch(pattern[1:], segs[i:]) {
				return true
			}
		}
		return false
	}
	return len(segs) > 0 && segmentMatches(pattern[0], segs[0]) && refMatch(pattern[1:], segs[1:])
}

func FuzzPathMatcher(f *testing.F) {
	for _, seed := range [][2]string{
		{"terraform/**", "terraform/a/b.tf"}, {"a/**/b", "a/x/y/b"}, {"**", "a"}, {"*/main.tf", "x/main.tf"},
		{"**/**/x", "a/b/x"}, {"a?c/*.go", "abc/d.go"}, {"a/b", "a/b"},
	} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, patternText, subjectText string) {
		pattern, err := parsePathSelector(patternText)
		if err != nil {
			return
		}
		subjectSegments, err := splitSubjectPath(subjectText)
		if err != nil {
			return
		}
		got := pattern.matches(subjectSegments)

		// The DP matcher agrees with the plain recursive one, within a bound that keeps the
		// recursive one fast.
		if len(pattern) <= 8 && len(subjectSegments) <= 12 {
			if want := refMatch(pattern, subjectSegments); got != want {
				t.Fatalf("pattern %q path %q: matcher %v, reference %v", patternText, subjectText, got, want)
			}
		}
		// A pattern with no wildcard matches only itself.
		if !strings.ContainsAny(patternText, "*?") {
			if want := patternText == subjectText; got != want {
				t.Fatalf("literal %q path %q: got %v, want %v", patternText, subjectText, got, want)
			}
		}
		// ** matches every valid path.
		if !pathPattern([]string{doubleStar}).matches(subjectSegments) {
			t.Fatalf("** does not match %q", subjectText)
		}
	})
}

func FuzzSegmentMatcher(f *testing.F) {
	for _, seed := range [][2]string{{"a*", "abc"}, {"?", "x"}, {"*a*b*", "xaxxbx"}, {"a?c", "a\u00e9c"}} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, pattern, name string) {
		if !regexp.MustCompile(`^[a-z0-9._*?-]{1,100}$`).MatchString(pattern) || strings.Contains(name, "/") || !utf8.ValidString(name) {
			return
		}
		// The same pattern as a regular expression: * is any run, ? is one character.
		var expr strings.Builder
		expr.WriteString(`(?s)^`)
		for _, r := range pattern {
			switch r {
			case '*':
				expr.WriteString(`.*`)
			case '?':
				expr.WriteString(`.`)
			default:
				expr.WriteString(regexp.QuoteMeta(string(r)))
			}
		}
		expr.WriteString(`$`)
		want := regexp.MustCompile(expr.String()).MatchString(name)
		if got := segmentMatches(pattern, name); got != want {
			t.Fatalf("pattern %q name %q: got %v, want %v", pattern, name, got, want)
		}
	})
}
