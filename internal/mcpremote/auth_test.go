package mcpremote

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
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

// fakeAuthServer is an authorization server's public face: metadata and keys over TLS.
type fakeAuthServer struct {
	t       *testing.T
	server  *httptest.Server
	signing jwk.Key
	meta    map[string]any
	keys    func() any
}

func newFakeAuthServer(t *testing.T) *fakeAuthServer {
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
	auth := &fakeAuthServer{t: t, signing: signing}
	auth.keys = func() any { return map[string]any{"keys": []any{public}} }
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(auth.meta)
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(auth.keys())
	})
	auth.server = httptest.NewTLSServer(mux)
	t.Cleanup(auth.server.Close)
	auth.meta = map[string]any{
		"issuer":                                auth.server.URL,
		"jwks_uri":                              auth.server.URL + "/jwks",
		"code_challenge_methods_supported":      []string{"S256"},
		"client_id_metadata_document_supported": true,
	}
	return auth
}

func (a *fakeAuthServer) verifier(audience string) *JWTVerifier {
	a.t.Helper()
	verifier, err := Discover(context.Background(), a.server.Client(), a.server.URL, audience)
	if err != nil {
		a.t.Fatal(err)
	}
	return verifier
}

type tokenOption func(*jwt.Builder) *jwt.Builder

func (a *fakeAuthServer) token(audience string, scopes []string, options ...tokenOption) string {
	a.t.Helper()
	builder := jwt.NewBuilder().
		Issuer(a.server.URL).
		Audience([]string{audience}).
		Subject("agent-1").
		Expiration(time.Now().Add(time.Hour)).
		Claim("scope", strings.Join(scopes, " "))
	for _, option := range options {
		builder = option(builder)
	}
	token, err := builder.Build()
	if err != nil {
		a.t.Fatal(err)
	}
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.ES256(), a.signing))
	if err != nil {
		a.t.Fatal(err)
	}
	return string(signed)
}

func encodeSegment(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
