package authn

import (
	"context"
	"errors"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// GitHubActionsIssuer is the issuer of the OIDC tokens a GitHub Actions job can request. GitHub
// Enterprise Server and enterprise-scoped issuers have other values and are not supported.
const GitHubActionsIssuer = "https://token.actions.githubusercontent.com"

var (
	repositoryName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)
	ownerName      = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,39}$`)
	// idClaim is a GitHub id as the token writes it: a positive decimal number with no sign, no
	// leading zero and no more digits than an int64 holds.
	idClaim   = regexp.MustCompile(`^[1-9][0-9]{0,17}$`)
	commitSHA = regexp.MustCompile(`^[0-9a-f]{40}$|^[0-9a-f]{64}$`)
)

// RunClaims is what a verified GitHub Actions token says about the job that requested it. The token is
// signed by GitHub, so each field is GitHub's word about the run and not the uploader's.
type RunClaims struct {
	// Owner and Name are the repository the job runs in, in the case GitHub writes them.
	Owner string
	Name  string
	// RepositoryID and OwnerID are GitHub's ids of the repository and of the account that owns it.
	RepositoryID int64
	OwnerID      int64
	RunID        int64
	RunAttempt   int
	SHA          string
	Ref          string
	Event        string
	// WorkflowRef is the workflow that requested the token, with its ref, as GitHub writes it.
	WorkflowRef string
}

// RunVerifier checks the token of a CI job.
type RunVerifier interface {
	VerifyRun(ctx context.Context, raw string) (RunClaims, error)
}

// VerifyRun checks the signature, issuer, audience and expiry of a GitHub Actions token, as Verify does,
// and then reads the claims that name the run. A claim that is missing, is not a string, or does not
// match its form is an error, so a token from a workflow that GitHub did not describe fully is refused.
// The error says nothing a caller should see.
func (v *JWTVerifier) VerifyRun(ctx context.Context, raw string) (RunClaims, error) {
	token, err := v.verified(ctx, raw, false)
	if err != nil {
		return RunClaims{}, err
	}
	text := func(name string) string {
		var value string
		if token.Get(name, &value) != nil {
			return ""
		}
		return value
	}
	var claims RunClaims
	claims.Owner, claims.Name, _ = strings.Cut(text("repository"), "/")
	if !ownerName.MatchString(claims.Owner) || !repositoryName.MatchString(claims.Name) {
		return RunClaims{}, errors.New("the token names no repository")
	}
	for _, id := range []struct {
		name string
		to   *int64
	}{
		{"repository_id", &claims.RepositoryID},
		{"repository_owner_id", &claims.OwnerID},
		{"run_id", &claims.RunID},
	} {
		value := text(id.name)
		if !idClaim.MatchString(value) {
			return RunClaims{}, errors.New("the token has a bad " + id.name)
		}
		*id.to, _ = strconv.ParseInt(value, 10, 64)
	}
	attempt := text("run_attempt")
	if !idClaim.MatchString(attempt) || len(attempt) > 9 {
		return RunClaims{}, errors.New("the token has a bad run_attempt")
	}
	n, _ := strconv.Atoi(attempt)
	claims.RunAttempt = n
	if claims.SHA = text("sha"); !commitSHA.MatchString(claims.SHA) {
		return RunClaims{}, errors.New("the token has a bad sha")
	}
	for _, name := range []struct {
		name string
		to   *string
		max  int
	}{
		{"ref", &claims.Ref, 512},
		{"event_name", &claims.Event, 64},
		{"workflow_ref", &claims.WorkflowRef, 512},
	} {
		value := text(name.name)
		if !plainText(value, name.max) {
			return RunClaims{}, errors.New("the token has a bad " + name.name)
		}
		*name.to = value
	}
	return claims, nil
}

// plainText holds for non-empty valid UTF-8 up to max bytes with no control or format character.
func plainText(text string, max int) bool {
	if text == "" || len(text) > max || !utf8.ValidString(text) {
		return false
	}
	for _, r := range text {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return false
		}
	}
	return true
}
