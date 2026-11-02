package mcpremote

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

type authServerMetadata struct {
	Issuer                string   `json:"issuer"`
	JWKSURI               string   `json:"jwks_uri"`
	CodeChallengeMethods  []string `json:"code_challenge_methods_supported"`
	ClientIDMetadataDocOK bool     `json:"client_id_metadata_document_supported"`
}

// Discover reads the authorization server's metadata (RFC 8414) and its keys, and refuses a server
// MCP clients could not use: it must offer PKCE with S256 and Client ID Metadata Documents, which
// are that server's job. The issuer and its key URL must be https. audience is the canonical URL of
// this resource (RFC 8707), and a token for anything else is refused.
func Discover(ctx context.Context, client *http.Client, issuer, audience string) (*JWTVerifier, error) {
	if client == nil {
		return nil, errors.New("an HTTP client is required")
	}
	noRedirects := *client
	noRedirects.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if err := requireHTTPS("issuer", issuer); err != nil {
		return nil, err
	}
	meta, err := fetchMetadata(ctx, &noRedirects, issuer)
	if err != nil {
		return nil, err
	}
	if meta.Issuer != issuer {
		return nil, fmt.Errorf("the metadata names the issuer %q, want %q", meta.Issuer, issuer)
	}
	if !slices.Contains(meta.CodeChallengeMethods, "S256") {
		return nil, errors.New("the authorization server does not offer PKCE with S256")
	}
	if !meta.ClientIDMetadataDocOK {
		return nil, errors.New("the authorization server does not support Client ID Metadata Documents")
	}
	if err := requireHTTPS("jwks_uri", meta.JWKSURI); err != nil {
		return nil, err
	}
	verifier := &JWTVerifier{issuer: issuer, audience: audience, jwksURI: meta.JWKSURI, client: &noRedirects}
	keys, err := verifier.fetchKeys(ctx)
	if err != nil {
		return nil, err
	}
	verifier.keys, verifier.fetched = keys, time.Now()
	return verifier, nil
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

// Verify checks a token's signature, issuer, audience, and expiry and returns its claims. A token
// that fails may have been signed by a rotated key, so the keys are read again, at most once per
// keyRefreshInterval. The error says nothing a caller should see.
func (v *JWTVerifier) Verify(ctx context.Context, raw string) (Claims, error) {
	if raw == "" || len(raw) > maxTokenBytes {
		return Claims{}, errors.New("the token is empty or too large")
	}
	v.mu.Lock()
	keys := v.keys
	v.mu.Unlock()
	token, err := v.parse(raw, keys)
	if err != nil {
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
	claims.Subject, _ = token.Subject()
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
