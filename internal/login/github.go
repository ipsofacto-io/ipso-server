package login

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"

	"golang.org/x/oauth2"
)

const (
	// githubIssuer is the issuer identity.login stores for a GitHub sign-in. GitHub has no ID token and
	// so no issuer claim, and this is the one place the string is made. A GitHub Enterprise Server
	// would need an issuer of its own, because its numeric ids repeat those of github.com.
	githubIssuer       = "https://github.com"
	githubAuthorizeURL = githubIssuer + "/login/oauth/authorize"
	githubTokenURL     = githubIssuer + "/login/oauth/access_token"
	githubUserURL      = "https://api.github.com/user"
	githubAPIVersion   = "2022-11-28"
	maxGitHubAnswer    = 1 << 20
)

// githubProvider is GitHub's OAuth 2.0 sign-in. It returns no ID token, so the subject is the numeric
// id that GET /user reports. The user name can be renamed and is never used. No scope is asked for:
// the id of the authenticated user needs none. The access token is used once and dropped.
type githubProvider struct {
	oauth   oauth2.Config
	userURL string
	client  *http.Client
}

func newGitHub(client *http.Client, cfg ProviderConfig, secret string) *githubProvider {
	return &githubProvider{
		oauth: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: secret,
			Endpoint:     oauth2.Endpoint{AuthURL: githubAuthorizeURL, TokenURL: githubTokenURL, AuthStyle: oauth2.AuthStyleInParams},
		},
		userURL: githubUserURL,
		client:  client,
	}
}

func (p *githubProvider) authorizeURL(redirectURI, state, _, verifier string) string {
	cfg := p.oauth
	cfg.RedirectURL = redirectURI
	return cfg.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
}

func (p *githubProvider) complete(ctx context.Context, redirectURI, code, verifier, _ string) (subject, error) {
	cfg := p.oauth
	cfg.RedirectURL = redirectURI
	token, err := cfg.Exchange(context.WithValue(ctx, oauth2.HTTPClient, p.client), code, oauth2.VerifierOption(verifier))
	if err != nil {
		return subject{}, exchangeFailure(err)
	}
	id, err := p.userID(ctx, token.AccessToken)
	if err != nil {
		return subject{}, &failure{phase: "user"}
	}
	return subject{issuer: githubIssuer, subject: strconv.FormatInt(id, 10)}, nil
}

func (p *githubProvider) userID(ctx context.Context, accessToken string) (int64, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.userURL, nil)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", githubAPIVersion)
	req.Header.Set("User-Agent", "ipso-server")
	resp, err := p.client.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return 0, &failure{phase: "user", code: strconv.Itoa(resp.StatusCode)}
	}
	// int64 refuses a float, and 0 is what an absent id decodes to.
	var user struct {
		ID int64 `json:"id"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxGitHubAnswer)).Decode(&user); err != nil {
		return 0, err
	}
	if user.ID <= 0 {
		return 0, &failure{phase: "user", code: "no_id"}
	}
	return user.ID, nil
}

func (p *githubProvider) issuerParameter() (string, bool) { return githubIssuer, false }
