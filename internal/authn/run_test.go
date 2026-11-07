package authn

import (
	"strings"
	"testing"

	"github.com/ipsofacto-io/ipso-server/internal/authn/authntest"
)

const ciAudience = "https://ipso.example.test/ci"

// runToken is what a GitHub Actions job gets, with overrides.
func runToken(auth *authntest.Server, overrides map[string]any, remove ...string) string {
	claims := map[string]any{
		"repository":          "Acme/API",
		"repository_id":       "1296269",
		"repository_owner_id": "9919",
		"run_id":              "1658821493",
		"run_attempt":         "2",
		"sha":                 strings.Repeat("ab", 20),
		"ref":                 "refs/heads/main",
		"event_name":          "pull_request",
		"workflow_ref":        "Acme/API/.github/workflows/ci.yml@refs/heads/main",
	}
	for name, value := range overrides {
		claims[name] = value
	}
	for _, name := range remove {
		delete(claims, name)
	}
	var options []authntest.TokenOption
	for name, value := range claims {
		options = append(options, authntest.Claim(name, value))
	}
	return auth.Token(ciAudience, nil, options...)
}

func TestVerifyRunReadsTheClaimsThatNameTheRun(t *testing.T) {
	auth := authntest.NewServer(t)
	verifier, _, err := Discover(t.Context(), auth.Server.Client(), auth.Server.URL, ciAudience)
	if err != nil {
		t.Fatal(err)
	}
	got, err := verifier.VerifyRun(t.Context(), runToken(auth, nil))
	if err != nil {
		t.Fatalf("VerifyRun: %v", err)
	}
	want := RunClaims{
		Owner: "Acme", Name: "API", RepositoryID: 1296269, OwnerID: 9919, RunID: 1658821493, RunAttempt: 2,
		SHA: strings.Repeat("ab", 20), Ref: "refs/heads/main", Event: "pull_request",
		WorkflowRef: "Acme/API/.github/workflows/ci.yml@refs/heads/main",
	}
	if got != want {
		t.Errorf("claims = %+v, want %+v", got, want)
	}
}

func TestVerifyRunRefusesATokenThatDoesNotDescribeARun(t *testing.T) {
	auth := authntest.NewServer(t)
	verifier, _, err := Discover(t.Context(), auth.Server.Client(), auth.Server.URL, ciAudience)
	if err != nil {
		t.Fatal(err)
	}
	for name, token := range map[string]string{
		"no repository":          runToken(auth, nil, "repository"),
		"a repository, no owner": runToken(auth, map[string]any{"repository": "/api"}),
		"no name":                runToken(auth, map[string]any{"repository": "acme/"}),
		"a deeper path":          runToken(auth, map[string]any{"repository": "acme/api/x"}),
		"a long owner":           runToken(auth, map[string]any{"repository": strings.Repeat("a", 40) + "/api"}),
		"a space":                runToken(auth, map[string]any{"repository": "acme/a pi"}),
		"no repository id":       runToken(auth, nil, "repository_id"),
		"a number as an id":      runToken(auth, map[string]any{"repository_id": 1296269}),
		"a leading zero":         runToken(auth, map[string]any{"run_id": "0123"}),
		"a sign":                 runToken(auth, map[string]any{"run_id": "+5"}),
		"zero":                   runToken(auth, map[string]any{"repository_owner_id": "0"}),
		"too many digits":        runToken(auth, map[string]any{"run_id": strings.Repeat("9", 19)}),
		"no attempt":             runToken(auth, nil, "run_attempt"),
		"an attempt of letters":  runToken(auth, map[string]any{"run_attempt": "two"}),
		"an uppercase sha":       runToken(auth, map[string]any{"sha": strings.Repeat("AB", 20)}),
		"a short sha":            runToken(auth, map[string]any{"sha": "abc"}),
		"no ref":                 runToken(auth, nil, "ref"),
		"a ref with a newline":   runToken(auth, map[string]any{"ref": "refs/heads/a\nb"}),
		"a long workflow":        runToken(auth, map[string]any{"workflow_ref": strings.Repeat("w", 513)}),
		"a bidi event":           runToken(auth, map[string]any{"event_name": "push\u202e"}),
		"another audience":       auth.Token("https://elsewhere.test", nil),
	} {
		if _, err := verifier.VerifyRun(t.Context(), token); err == nil {
			t.Errorf("%s: VerifyRun accepted the token", name)
		}
	}
	if _, err := verifier.VerifyRun(t.Context(), "not.a.token"); err == nil {
		t.Error("VerifyRun accepted garbage")
	}
}
