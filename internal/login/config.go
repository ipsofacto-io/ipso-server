// Package login signs a person in through an identity provider and holds the session that follows
// (ADR-0099). ipso-server is a relying party and nothing more: it runs the authorization code flow
// with PKCE, state, and a nonce, maps the provider's issuer and subject to a principal through
// identity.login (ADR-0093), and keeps a server-side session behind a __Host- cookie. It creates no
// person, mints no token, and stores no password and no profile.
package login

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strings"
)

const (
	// ProvidersEnv names the variable that holds the providers as a JSON array.
	ProvidersEnv = "IPSO_LOGIN_PROVIDERS"
	// PublicURLEnv names the variable that holds the origin people reach the control plane at.
	PublicURLEnv = "IPSO_PUBLIC_URL"

	// KindOIDC is a provider that returns an ID token: Google, Microsoft, or a self-hosted provider.
	KindOIDC = "oidc"
	// KindGitHub is GitHub's OAuth 2.0 sign-in, which returns no ID token.
	KindGitHub = "github"

	maxConfigSize = 1 << 20
	maxClientID   = 256
)

var (
	providerID   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	secretEnvVar = regexp.MustCompile(`^IPSO_LOGIN_[A-Z0-9_]{1,64}$`)
)

// ProviderConfig is one provider. The secret is named, never held: the process reads it from its
// environment, so the configuration can be logged and committed.
type ProviderConfig struct {
	// ID is the name in the redirect URI: /auth/callback/{id}.
	ID string `json:"id"`
	// Kind is KindOIDC or KindGitHub.
	Kind string `json:"kind"`
	// Issuer is the https issuer of an OIDC provider. GitHub has a fixed one and takes none.
	Issuer string `json:"issuer"`
	// ClientID is the id of the application registered with the provider.
	ClientID string `json:"client_id"`
	// ClientSecretEnv names the environment variable that holds the client secret.
	ClientSecretEnv string `json:"client_secret_env"`
}

// ParseProviders reads the providers strictly: an unknown field is an error.
func ParseProviders(r io.Reader) ([]ProviderConfig, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxConfigSize+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxConfigSize {
		return nil, errors.New("login providers are larger than 1 MiB")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var providers []ProviderConfig
	if err := decoder.Decode(&providers); err != nil {
		return nil, fmt.Errorf("login providers: %w", err)
	}
	if decoder.More() {
		return nil, errors.New("login providers hold more than one value")
	}
	return providers, nil
}

// validate checks the providers without a connection. forbidden are the audiences of the API and of
// remote MCP: a client id equal to one would make an ID token pass as a bearer token for it.
func validate(providers []ProviderConfig, forbidden []string, secret func(string) string) error {
	if len(providers) == 0 {
		return errors.New("at least one login provider is required")
	}
	ids, issuers := map[string]bool{}, map[string]bool{}
	github := false
	for i, p := range providers {
		where := fmt.Sprintf("login provider %d", i+1)
		if !providerID.MatchString(p.ID) {
			return fmt.Errorf("%s: id %q is not a lowercase name", where, p.ID)
		}
		where = fmt.Sprintf("login provider %q", p.ID)
		if ids[p.ID] {
			return fmt.Errorf("%s: the id is used twice", where)
		}
		ids[p.ID] = true
		switch p.Kind {
		case KindOIDC:
			parsed, err := url.Parse(p.Issuer)
			if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.RawQuery != "" || parsed.Fragment != "" {
				return fmt.Errorf("%s: the issuer must be an https URL", where)
			}
			if p.Issuer == githubIssuer {
				return fmt.Errorf("%s: that issuer is GitHub's, which has the kind %q", where, KindGitHub)
			}
			if issuers[p.Issuer] {
				return fmt.Errorf("%s: the issuer is used twice", where)
			}
			issuers[p.Issuer] = true
		case KindGitHub:
			if p.Issuer != "" {
				return fmt.Errorf("%s: GitHub has a fixed issuer and takes none", where)
			}
			if github {
				return fmt.Errorf("%s: only one GitHub provider is allowed", where)
			}
			github = true
		default:
			return fmt.Errorf("%s: kind must be %q or %q", where, KindOIDC, KindGitHub)
		}
		if p.ClientID == "" || len(p.ClientID) > maxClientID || strings.ContainsFunc(p.ClientID, isControl) {
			return fmt.Errorf("%s: client_id is empty, too long, or has a control character", where)
		}
		for _, audience := range forbidden {
			if audience != "" && p.ClientID == audience {
				return fmt.Errorf("%s: client_id equals the audience of the API or of remote MCP", where)
			}
		}
		if !secretEnvVar.MatchString(p.ClientSecretEnv) || p.ClientSecretEnv == ProvidersEnv {
			return fmt.Errorf("%s: client_secret_env must name an IPSO_LOGIN_ variable that holds a secret", where)
		}
		if strings.TrimSpace(secret(p.ClientSecretEnv)) == "" {
			return fmt.Errorf("%s: %s is not set", where, p.ClientSecretEnv)
		}
	}
	return nil
}

func isControl(r rune) bool { return r < 0x20 || r == 0x7f }

// CanonicalOrigin returns the origin of a public URL: https, or http for a loopback host only, with
// no user information, path, query, or fragment, a lowercase host, and no default port. The origin
// is what the redirect URI and the cross-origin check are built from, never a request header.
func CanonicalOrigin(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" || parsed.Opaque != "" {
		return "", errors.New("the public URL must be an origin such as https://ipso.example.com")
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.ForceQuery || (parsed.Path != "" && parsed.Path != "/") {
		return "", errors.New("the public URL must be an origin: no user, path, query, or fragment")
	}
	host := strings.ToLower(parsed.Hostname())
	switch parsed.Scheme {
	case "https":
	case "http":
		if host != "localhost" && host != "127.0.0.1" && host != "::1" {
			return "", errors.New("the public URL must be https; http is for localhost, 127.0.0.1, and [::1] only")
		}
	default:
		return "", errors.New("the public URL must be https; http is for localhost, 127.0.0.1, and [::1] only")
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	port := parsed.Port()
	if (parsed.Scheme == "https" && port == "443") || (parsed.Scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		host += ":" + port
	}
	return parsed.Scheme + "://" + host, nil
}
