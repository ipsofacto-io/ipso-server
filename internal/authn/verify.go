// Package authn checks the bearer tokens the control plane accepts: signed JWTs from one
// authorization server for one resource (RFC 8707). Which tenant and principal a token speaks for is
// decided by the stored logins (ADR-0093), so nothing here reads a tenant.
package authn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

const (
	// maxMetadataBytes bounds what the authorization server sends about itself.
	maxMetadataBytes = 1 << 20
	// maxTokenBytes bounds a bearer token before any parsing.
	maxTokenBytes = 16 << 10
	// clockSkew is the difference allowed between this server and the authorization server.
	clockSkew = 30 * time.Second
	// keyRefreshInterval limits how often an unknown key can make this server call out, so a stream
	// of bad tokens cannot turn into a stream of requests to the authorization server.
	keyRefreshInterval = time.Minute
)

// JWTVerifier checks signed access tokens from one authorization server for one resource.
type JWTVerifier struct {
	issuer   string
	audience string
	jwksURI  string
	client   *http.Client

	mu      sync.Mutex
	keys    jwk.Set
	fetched time.Time
}

// Claims is what a verified token says.
type Claims struct {
	// Issuer is the authorization server that signed the token. Verify checked it against the
	// configured one, so it is not the token's own word.
	Issuer string
	// Subject is the issuer's identifier for the user or client. It is unique only within the issuer.
	Subject string
	// Audiences is every resource the token names, not only the one that checked it.
	Audiences []string
	ClientID  string
	Scopes    []string
}

// Verifier checks a bearer token. JWTVerifier is the implementation.
type Verifier interface {
	Verify(ctx context.Context, raw string) (Claims, error)
}

// Exclusive returns a Verifier that also refuses a token whose audience names any of others. A token
// minted for two resources is valid at both, so each resource refuses one that names the other
// (ADR-0094). A token for one resource only is already refused by the other's audience check.
func Exclusive(verifier Verifier, others ...string) Verifier {
	return exclusive{verifier: verifier, others: others}
}

type exclusive struct {
	verifier Verifier
	others   []string
}

func (e exclusive) Verify(ctx context.Context, raw string) (Claims, error) {
	claims, err := e.verifier.Verify(ctx, raw)
	if err != nil {
		return Claims{}, err
	}
	for _, audience := range claims.Audiences {
		if slices.Contains(e.others, audience) {
			return Claims{}, errors.New("the token also names another resource")
		}
	}
	return claims, nil
}

// Metadata is what the authorization server says it offers clients. A resource server that needs
// more of it than a signed token, as remote MCP does, checks it after Discover.
type Metadata struct {
	CodeChallengeMethods      []string `json:"code_challenge_methods_supported"`
	ClientIDMetadataDocuments bool     `json:"client_id_metadata_document_supported"`
}

type authServerMetadata struct {
	Metadata
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

// Discover reads the authorization server's metadata (RFC 8414) and its keys. The issuer and its key
// URL must be https, and the metadata must name the issuer exactly. audience is the canonical URL of
// this resource (RFC 8707), and a token for anything else is refused.
func Discover(ctx context.Context, client *http.Client, issuer, audience string) (*JWTVerifier, Metadata, error) {
	if client == nil {
		return nil, Metadata{}, errors.New("an HTTP client is required")
	}
	noRedirects := *client
	noRedirects.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if err := requireHTTPS("issuer", issuer); err != nil {
		return nil, Metadata{}, err
	}
	meta, err := fetchMetadata(ctx, &noRedirects, issuer)
	if err != nil {
		return nil, Metadata{}, err
	}
	if meta.Issuer != issuer {
		return nil, Metadata{}, fmt.Errorf("the metadata names the issuer %q, want %q", meta.Issuer, issuer)
	}
	if err := requireHTTPS("jwks_uri", meta.JWKSURI); err != nil {
		return nil, Metadata{}, err
	}
	verifier := &JWTVerifier{issuer: issuer, audience: audience, jwksURI: meta.JWKSURI, client: &noRedirects}
	keys, err := verifier.fetchKeys(ctx)
	if err != nil {
		return nil, Metadata{}, err
	}
	verifier.keys, verifier.fetched = keys, time.Now()
	return verifier, meta.Metadata, nil
}

// Bearer returns the token of an Authorization header that uses the Bearer scheme. The header is the
// only place a token is read from, so a token cannot end up in a URL or a log.
func Bearer(header string) (string, bool) {
	scheme, token, found := strings.Cut(header, " ")
	if !found || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return "", false
	}
	return token, true
}

func requireHTTPS(name, value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return fmt.Errorf("%s must be an https URL", name)
	}
	return nil
}

// fetchMetadata tries RFC 8414, then OpenID Connect discovery, which some servers offer instead.
func fetchMetadata(ctx context.Context, client *http.Client, issuer string) (authServerMetadata, error) {
	parsed, err := url.Parse(issuer)
	if err != nil {
		return authServerMetadata{}, err
	}
	path := strings.TrimSuffix(parsed.Path, "/")
	candidates := []string{
		parsed.Scheme + "://" + parsed.Host + "/.well-known/oauth-authorization-server" + path,
		strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration",
	}
	var last error
	for _, candidate := range candidates {
		data, err := fetch(ctx, client, candidate)
		if err != nil {
			last = err
			continue
		}
		var meta authServerMetadata
		if err := json.Unmarshal(data, &meta); err != nil {
			return authServerMetadata{}, fmt.Errorf("read the authorization server metadata: %w", err)
		}
		return meta, nil
	}
	return authServerMetadata{}, fmt.Errorf("read the authorization server metadata: %w", last)
}

func fetch(ctx context.Context, client *http.Client, target string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered %d", target, resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxMetadataBytes {
		return nil, fmt.Errorf("%s answered more than %d bytes", target, maxMetadataBytes)
	}
	return data, nil
}

// fetchKeys refuses a symmetric key. Anyone holding the published key could then sign a token.
func (v *JWTVerifier) fetchKeys(ctx context.Context) (jwk.Set, error) {
	data, err := fetch(ctx, v.client, v.jwksURI)
	if err != nil {
		return nil, fmt.Errorf("read the keys: %w", err)
	}
	set, err := jwk.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("read the keys: %w", err)
	}
	if set.Len() == 0 {
		return nil, errors.New("the authorization server published no keys")
	}
	for i := range set.Len() {
		key, ok := set.Key(i)
		if ok && key.KeyType() == jwa.OctetSeq() {
			return nil, errors.New("the authorization server published a symmetric key")
		}
	}
	return set, nil
}

// Verify checks a token's signature, issuer, audience, and expiry and returns its claims. A signature
// that fails may be a rotated key, so the keys are read again, at most once per keyRefreshInterval.
// A token the current keys already verify is not a reason to call out: a new key cannot fix an
// issuer, an audience, or an expiry. The error says nothing a caller should see.
func (v *JWTVerifier) Verify(ctx context.Context, raw string) (Claims, error) {
	if raw == "" || len(raw) > maxTokenBytes {
		return Claims{}, errors.New("the token is empty or too large")
	}
	v.mu.Lock()
	keys := v.keys
	v.mu.Unlock()
	token, err := v.parse(raw, keys)
	if err != nil {
		if !errors.Is(err, jws.VerificationError()) {
			return Claims{}, err
		}
		fresh, ok := v.refresh(ctx)
		if !ok {
			return Claims{}, err
		}
		if token, err = v.parse(raw, fresh); err != nil {
			return Claims{}, err
		}
	}
	return claimsOf(token), nil
}

func (v *JWTVerifier) parse(raw string, keys jwk.Set) (jwt.Token, error) {
	return jwt.Parse([]byte(raw),
		jwt.WithKeySet(keys, jws.WithInferAlgorithmFromKey(true)),
		jwt.WithValidate(true),
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.audience),
		jwt.WithRequiredClaim("exp"),
		jwt.WithRequiredClaim("sub"),
		jwt.WithAcceptableSkew(clockSkew),
	)
}

func (v *JWTVerifier) refresh(ctx context.Context) (jwk.Set, bool) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if time.Since(v.fetched) < keyRefreshInterval {
		return nil, false
	}
	// A failed fetch still uses the interval. Rolling it back would let a stream of bad tokens
	// hammer the authorization server while it is down.
	v.fetched = time.Now()
	keys, err := v.fetchKeys(ctx)
	if err != nil {
		return nil, false
	}
	v.keys = keys
	return keys, true
}

func claimsOf(token jwt.Token) Claims {
	claims := Claims{}
	claims.Issuer, _ = token.Issuer()
	claims.Subject, _ = token.Subject()
	claims.Audiences, _ = token.Audience()
	_ = token.Get("client_id", &claims.ClientID)
	var scope string
	if err := token.Get("scope", &scope); err == nil {
		claims.Scopes = strings.Fields(scope)
		return claims
	}
	// Some servers send scp, as a list or as one string.
	var list []string
	if err := token.Get("scp", &list); err == nil {
		claims.Scopes = list
		return claims
	}
	if err := token.Get("scp", &scope); err == nil {
		claims.Scopes = strings.Fields(scope)
	}
	return claims
}
