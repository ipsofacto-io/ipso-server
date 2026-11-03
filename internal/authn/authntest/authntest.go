// Package authntest is an authorization server's public face for tests: metadata and keys over TLS,
// and tokens signed with its key.
package authntest

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Server serves Meta at the RFC 8414 path and Keys at /jwks. A test changes either before Discover
// reads them.
type Server struct {
	T       *testing.T
	Server  *httptest.Server
	Signing jwk.Key
	Meta    map[string]any
	Keys    func() any
}

// NewServer starts a server that offers what remote MCP needs: PKCE with S256 and Client ID Metadata
// Documents. It signs with a fresh ES256 key.
func NewServer(t *testing.T) *Server {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signing, err := jwk.Import(private)
	if err != nil {
		t.Fatal(err)
	}
	if err := signing.Set(jwk.KeyIDKey, "key-1"); err != nil {
		t.Fatal(err)
	}
	if err := signing.Set(jwk.AlgorithmKey, jwa.ES256()); err != nil {
		t.Fatal(err)
	}
	public, err := signing.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	auth := &Server{T: t, Signing: signing}
	auth.Keys = func() any { return map[string]any{"keys": []any{public}} }
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(auth.Meta)
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(auth.Keys())
	})
	auth.Server = httptest.NewTLSServer(mux)
	t.Cleanup(auth.Server.Close)
	auth.Meta = map[string]any{
		"issuer":                                auth.Server.URL,
		"jwks_uri":                              auth.Server.URL + "/jwks",
		"code_challenge_methods_supported":      []string{"S256"},
		"client_id_metadata_document_supported": true,
	}
	return auth
}

// TokenOption changes a token before it is signed.
type TokenOption func(*jwt.Builder) *jwt.Builder

// Token signs a token for audience from this server, with subject agent-1 and an hour to live.
func (a *Server) Token(audience string, scopes []string, options ...TokenOption) string {
	a.T.Helper()
	builder := jwt.NewBuilder().
		Issuer(a.Server.URL).
		Audience([]string{audience}).
		Subject("agent-1").
		Expiration(time.Now().Add(time.Hour)).
		Claim("scope", strings.Join(scopes, " "))
	for _, option := range options {
		builder = option(builder)
	}
	token, err := builder.Build()
	if err != nil {
		a.T.Fatal(err)
	}
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.ES256(), a.Signing))
	if err != nil {
		a.T.Fatal(err)
	}
	return string(signed)
}
