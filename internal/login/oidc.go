package login

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"

	"golang.org/x/oauth2"

	"github.com/ipsofacto-io/ipso-server/internal/authn"
)

// subject is who a provider says signed in: the provider's issuer and its identifier for the person.
// Both are the key of a login (ADR-0093).
type subject struct{ issuer, subject string }

// provider is one way to sign in.
type provider interface {
	// authorizeURL is where the browser goes first. state, nonce, and the PKCE verifier are the
	// attempt's.
	authorizeURL(redirectURI, state, nonce, verifier string) string
	// complete turns the code of the callback into the subject. It returns a *failure, whose text is
	// safe to log: nothing a provider sent is in it.
	complete(ctx context.Context, redirectURI, code, verifier, nonce string) (subject, error)
	// issuerParameter is the iss the callback must carry when it carries one (RFC 9207), and whether
	// the provider promises one.
	issuerParameter() (expected string, required bool)
}

// failure names the step of a sign-in that failed. A provider's answer can hold a body, an error
// description, or a token, so none of it is kept.
type failure struct{ phase, code string }

func (f *failure) Error() string {
	if f.code == "" {
		return f.phase
	}
	return f.phase + ": " + f.code
}

var errorCodeText = regexp.MustCompile(`^[a-z_]{1,40}$`)

// exchangeFailure keeps the error code of a rejected code exchange when it is one of the short codes of
// RFC 6749, and nothing else.
func exchangeFailure(err error) *failure {
	f := &failure{phase: "exchange"}
	var rejected *oauth2.RetrieveError
	if errors.As(err, &rejected) && errorCodeText.MatchString(rejected.ErrorCode) {
		f.code = rejected.ErrorCode
	}
	return f
}

// idTokenVerifier is authn.JWTVerifier as the sign-in uses it.
type idTokenVerifier interface {
	VerifyIDToken(ctx context.Context, raw, nonce string) (authn.Claims, error)
}

// oidcProvider is an OpenID Connect provider: Google, Microsoft, or a self-hosted one.
type oidcProvider struct {
	oauth       oauth2.Config
	verifier    idTokenVerifier
	issuer      string
	issRequired bool
	client      *http.Client
}

// newOIDC discovers the provider. It fails when the provider cannot be reached, so a process with a
// provider it cannot use does not start.
func newOIDC(ctx context.Context, client *http.Client, cfg ProviderConfig, secret string) (*oidcProvider, error) {
	verifier, meta, err := authn.Discover(ctx, client, cfg.Issuer, cfg.ClientID)
	if err != nil {
		return nil, fmt.Errorf("login provider %q: %w", cfg.ID, err)
	}
	if !authn.IsHTTPS(meta.AuthorizationEndpoint) || !authn.IsHTTPS(meta.TokenEndpoint) {
		return nil, fmt.Errorf("login provider %q: the metadata names no https authorization endpoint and token endpoint", cfg.ID)
	}
	// Secret in the body when the provider accepts it, in the header otherwise. The library's own
	// detection retries every failed exchange with the other style.
	style := oauth2.AuthStyleInHeader
	if slices.Contains(meta.TokenEndpointAuthMethods, "client_secret_post") {
		style = oauth2.AuthStyleInParams
	}
	return &oidcProvider{
		oauth: oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: secret,
			Endpoint:     oauth2.Endpoint{AuthURL: meta.AuthorizationEndpoint, TokenURL: meta.TokenEndpoint, AuthStyle: style},
			Scopes:       []string{"openid"},
		},
		verifier:    verifier,
		issuer:      cfg.Issuer,
		issRequired: meta.IssuerResponseParameter,
		client:      client,
	}, nil
}

func (p *oidcProvider) authorizeURL(redirectURI, state, nonce, verifier string) string {
	cfg := p.oauth
	cfg.RedirectURL = redirectURI
	return cfg.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("nonce", nonce))
}

func (p *oidcProvider) complete(ctx context.Context, redirectURI, code, verifier, nonce string) (subject, error) {
	cfg := p.oauth
	cfg.RedirectURL = redirectURI
	token, err := cfg.Exchange(context.WithValue(ctx, oauth2.HTTPClient, p.client), code, oauth2.VerifierOption(verifier))
	if err != nil {
		return subject{}, exchangeFailure(err)
	}
	raw, _ := token.Extra("id_token").(string)
	if raw == "" {
		return subject{}, &failure{phase: "no_id_token"}
	}
	claims, err := p.verifier.VerifyIDToken(ctx, raw, nonce)
	if err != nil {
		return subject{}, &failure{phase: "id_token"}
	}
	return subject{issuer: claims.Issuer, subject: claims.Subject}, nil
}

func (p *oidcProvider) issuerParameter() (string, bool) { return p.issuer, p.issRequired }
