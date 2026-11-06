package authn

import (
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/ipsofacto-io/ipso-server/internal/authn/authntest"
)

const testAudience = "https://api.example.test/v1"

func TestDiscoverRefusesAServerItCannotTrust(t *testing.T) {
	for name, tc := range map[string]struct {
		change func(*authntest.Server)
		want   string
	}{
		"another issuer": {func(a *authntest.Server) { a.Meta["issuer"] = "https://elsewhere.test" }, "names the issuer"},
		"keys over http": {func(a *authntest.Server) { a.Meta["jwks_uri"] = "http://elsewhere.test/jwks" }, "jwks_uri"},
		"no keys":        {func(a *authntest.Server) { a.Keys = func() any { return map[string]any{"keys": []any{}} } }, "no keys"},
		"a symmetric key": {func(a *authntest.Server) {
			key, err := jwk.Import([]byte("a shared secret that anyone could read"))
			if err != nil {
				a.T.Fatal(err)
			}
			a.Keys = func() any { return map[string]any{"keys": []any{key}} }
		}, "symmetric"},
	} {
		t.Run(name, func(t *testing.T) {
			auth := authntest.NewServer(t)
			tc.change(auth)
			_, _, err := Discover(t.Context(), auth.Server.Client(), auth.Server.URL, testAudience)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err %v", err)
			}
		})
	}
	if _, _, err := Discover(t.Context(), http.DefaultClient, "http://plain.example.test", testAudience); err == nil || !strings.Contains(err.Error(), "https") {
		t.Fatalf("err %v", err)
	}
	if _, _, err := Discover(t.Context(), nil, "https://x.test", testAudience); err == nil {
		t.Fatal("no client")
	}
}

// An OpenID provider such as Dex offers neither Client ID Metadata Documents nor, sometimes, PKCE.
// The control plane API accepts its tokens, so Discover reports that metadata and leaves the choice
// to the resource server.
func TestDiscoverReportsWhatTheServerOffers(t *testing.T) {
	auth := authntest.NewServer(t)
	delete(auth.Meta, "client_id_metadata_document_supported")
	auth.Meta["code_challenge_methods_supported"] = []string{"plain"}
	verifier, meta, err := Discover(t.Context(), auth.Server.Client(), auth.Server.URL, testAudience)
	if err != nil {
		t.Fatal(err)
	}
	if meta.ClientIDMetadataDocuments || len(meta.CodeChallengeMethods) != 1 || meta.CodeChallengeMethods[0] != "plain" {
		t.Fatalf("%+v", meta)
	}
	claims, err := verifier.Verify(t.Context(), auth.Token(testAudience, []string{"ipso.read"}))
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "agent-1" || len(claims.Scopes) != 1 {
		t.Fatalf("%+v", claims)
	}
	if _, err := verifier.Verify(t.Context(), auth.Token("https://other.example.test", nil)); err == nil {
		t.Fatal("a token for another audience was accepted")
	}
}

func TestVerifierPicksUpARotatedKeyOnlyWithinTheLimit(t *testing.T) {
	auth := authntest.NewServer(t)
	verifier, _, err := Discover(t.Context(), auth.Server.Client(), auth.Server.URL, testAudience)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	rotated := authntest.NewServer(t)
	rotated.Server.Close()
	public, err := rotated.Signing.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	auth.Keys = func() any {
		calls++
		return map[string]any{"keys": []any{public}}
	}
	token := auth.Token(testAudience, nil)
	auth.Signing = rotated.Signing
	newToken := auth.Token(testAudience, nil)

	if _, err := verifier.Verify(t.Context(), newToken); err == nil {
		t.Fatal("a key this server has not read yet was accepted")
	}
	if calls != 0 {
		t.Fatalf("a bad token made this server call out %d times", calls)
	}
	verifier.mu.Lock()
	verifier.fetched = time.Now().Add(-2 * keyRefreshInterval)
	verifier.mu.Unlock()
	if _, err := verifier.Verify(t.Context(), newToken); err != nil {
		t.Fatalf("a rotated key: %v", err)
	}
	if calls != 1 {
		t.Fatalf("calls %d", calls)
	}
	if _, err := verifier.Verify(t.Context(), token); err == nil {
		t.Fatal("the rotated-out key still works")
	}
	if calls != 1 {
		t.Fatalf("a bad token inside the limit called out: %d", calls)
	}
}

func TestVerifierDoesNotRefreshKeysForAClaimFailure(t *testing.T) {
	auth := authntest.NewServer(t)
	verifier, _, err := Discover(t.Context(), auth.Server.Client(), auth.Server.URL, testAudience)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	public, err := auth.Signing.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	auth.Keys = func() any {
		calls++
		return map[string]any{"keys": []any{public}}
	}
	verifier.mu.Lock()
	verifier.fetched = time.Now().Add(-2 * keyRefreshInterval)
	verifier.mu.Unlock()

	expired := auth.Token(testAudience, nil, func(b *jwt.Builder) *jwt.Builder {
		return b.Expiration(time.Now().Add(-time.Hour))
	})
	if _, err := verifier.Verify(t.Context(), expired); err == nil {
		t.Fatal("an expired token was accepted")
	}
	if _, err := verifier.Verify(t.Context(), auth.Token("https://other.example.test", nil)); err == nil {
		t.Fatal("a token for another audience was accepted")
	}
	if calls != 0 {
		t.Fatalf("a claim failure called out %d times", calls)
	}
}

func TestVerifierAFailedKeyFetchStillWaits(t *testing.T) {
	auth := authntest.NewServer(t)
	verifier, _, err := Discover(t.Context(), auth.Server.Client(), auth.Server.URL, testAudience)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	auth.Keys = func() any {
		calls++
		return map[string]any{"keys": []any{}}
	}
	other := authntest.NewServer(t)
	other.Server.Close()
	auth.Signing = other.Signing
	token := auth.Token(testAudience, nil)
	verifier.mu.Lock()
	verifier.fetched = time.Now().Add(-2 * keyRefreshInterval)
	verifier.mu.Unlock()

	if _, err := verifier.Verify(t.Context(), token); err == nil {
		t.Fatal("a token signed by an unpublished key was accepted")
	}
	if _, err := verifier.Verify(t.Context(), token); err == nil {
		t.Fatal("the second try was accepted")
	}
	if calls != 1 {
		t.Fatalf("a failed fetch was repeated: %d calls", calls)
	}
}

func TestBearerReadsOnlyTheBearerScheme(t *testing.T) {
	for header, want := range map[string]string{
		"Bearer abc":   "abc",
		"bearer abc":   "abc",
		"Bearer ":      "",
		"Bearer":       "",
		"Basic abc":    "",
		"":             "",
		"Token abc":    "",
		"Bearerabc":    "",
		"BEARER a.b.c": "a.b.c",
	} {
		got, ok := Bearer(header)
		if got != want || ok != (want != "") {
			t.Errorf("%q: %q %v", header, got, ok)
		}
	}
}

func TestVerifyReportsTheIssuerAndEveryAudience(t *testing.T) {
	auth := authntest.NewServer(t)
	verifier, _, err := Discover(t.Context(), auth.Server.Client(), auth.Server.URL, testAudience)
	if err != nil {
		t.Fatal(err)
	}
	both := auth.Token(testAudience, nil, func(b *jwt.Builder) *jwt.Builder {
		return b.Audience([]string{testAudience, "https://mcp.example.test/mcp"})
	})
	claims, err := verifier.Verify(t.Context(), both)
	if err != nil {
		t.Fatal(err)
	}
	if claims.Issuer != auth.Server.URL || claims.Subject != "agent-1" {
		t.Errorf("issuer %q subject %q", claims.Issuer, claims.Subject)
	}
	if len(claims.Audiences) != 2 {
		t.Errorf("audiences = %v, want both", claims.Audiences)
	}
}

func TestExclusiveRefusesATokenThatNamesAnotherResource(t *testing.T) {
	const other = "https://mcp.example.test/mcp"
	auth := authntest.NewServer(t)
	verifier, _, err := Discover(t.Context(), auth.Server.Client(), auth.Server.URL, testAudience)
	if err != nil {
		t.Fatal(err)
	}
	exclusive := Exclusive(verifier, other)

	if _, err := exclusive.Verify(t.Context(), auth.Token(testAudience, nil)); err != nil {
		t.Errorf("a token for this resource only was refused: %v", err)
	}
	both := auth.Token(testAudience, nil, func(b *jwt.Builder) *jwt.Builder {
		return b.Audience([]string{testAudience, other})
	})
	if _, err := verifier.Verify(t.Context(), both); err != nil {
		t.Fatalf("the plain verifier should accept a token that names this resource: %v", err)
	}
	if _, err := exclusive.Verify(t.Context(), both); err == nil {
		t.Error("a token for both resources was accepted")
	}
	if _, err := exclusive.Verify(t.Context(), auth.Token(other, nil)); err == nil {
		t.Error("a token for the other resource only was accepted")
	}
}

const testClient = "ipso-login-client"

func idToken(auth *authntest.Server, options ...authntest.TokenOption) string {
	base := []authntest.TokenOption{authntest.Subject("person-1"), authntest.Claim("nonce", "nonce-1")}
	return auth.Token(testClient, nil, append(base, options...)...)
}

func TestVerifyIDTokenChecksTheNonceAndTheAuthorizedParty(t *testing.T) {
	auth := authntest.NewServer(t)
	verifier, _, err := Discover(t.Context(), auth.Server.Client(), auth.Server.URL, testClient)
	if err != nil {
		t.Fatal(err)
	}

	claims, err := verifier.VerifyIDToken(t.Context(), idToken(auth), "nonce-1")
	if err != nil {
		t.Fatal(err)
	}
	if claims.Subject != "person-1" || claims.Issuer != auth.Server.URL {
		t.Fatalf("%+v", claims)
	}
	if _, err := verifier.VerifyIDToken(t.Context(), idToken(auth, authntest.Claim("azp", testClient)), "nonce-1"); err != nil {
		t.Errorf("azp equal to the client: %v", err)
	}
	if _, err := verifier.VerifyIDToken(t.Context(), idToken(auth, authntest.Audiences(testClient, "another-client"), authntest.Claim("azp", testClient)), "nonce-1"); err != nil {
		t.Errorf("several audiences with azp: %v", err)
	}

	for name, tc := range map[string]struct {
		token string
		nonce string
	}{
		"another nonce":                   {idToken(auth), "nonce-2"},
		"no nonce in the token":           {auth.Token(testClient, nil), "nonce-1"},
		"an empty nonce asked for":        {idToken(auth), ""},
		"a nonce that is not a string":    {idToken(auth, authntest.Claim("nonce", 1)), "1"},
		"azp for another client":          {idToken(auth, authntest.Claim("azp", "another-client")), "nonce-1"},
		"azp that is not a string":        {idToken(auth, authntest.Claim("azp", 7)), "nonce-1"},
		"several audiences and no azp":    {idToken(auth, authntest.Audiences(testClient, "another-client")), "nonce-1"},
		"another audience":                {auth.Token("another-client", nil, authntest.Claim("nonce", "nonce-1")), "nonce-1"},
		"another issuer":                  {idToken(auth, authntest.Issuer("https://elsewhere.example.test")), "nonce-1"},
		"the legacy Google issuer":        {idToken(auth, authntest.Issuer("accounts.google.com")), "nonce-1"},
		"an issuer that differs in case":  {idToken(auth, authntest.Issuer(strings.ToUpper(auth.Server.URL))), "nonce-1"},
		"a token with a trailing garbage": {idToken(auth) + "x", "nonce-1"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := verifier.VerifyIDToken(t.Context(), tc.token, tc.nonce); err == nil {
				t.Fatal("it was accepted")
			}
		})
	}
}

// An ID token is not a bearer token for the API: the API's audience is not a client id, and a token the
// API accepts has no nonce.
func TestAnAccessTokenIsNotAnIDTokenAndTheOtherWayRound(t *testing.T) {
	auth := authntest.NewServer(t)
	verifier, _, err := Discover(t.Context(), auth.Server.Client(), auth.Server.URL, testClient)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.VerifyIDToken(t.Context(), auth.Token(testClient, []string{"ipso.read"}), "nonce-1"); err == nil {
		t.Error("an access token with no nonce passed as an ID token")
	}
	// Verify (the bearer path) still holds the token to the configured issuer.
	if _, err := verifier.Verify(t.Context(), idToken(auth, authntest.Issuer("accounts.google.com"))); err == nil {
		t.Error("a bearer token with another issuer was accepted")
	}
}

// Microsoft publishes keys with no alg member. The algorithm is read from the token's header and must
// suit the key.
func TestAKeyWithNoAlgVerifiesAnIDToken(t *testing.T) {
	auth := authntest.NewServer(t, authntest.WithRSAKeyWithoutAlg())
	verifier, _, err := Discover(t.Context(), auth.Server.Client(), auth.Server.URL, testClient)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.VerifyIDToken(t.Context(), idToken(auth), "nonce-1"); err != nil {
		t.Fatal(err)
	}
}

// Google signs some tokens with the issuer "accounts.google.com". The claims still carry the issuer
// that was configured, because that is what identity.login stores.
func TestOnlyGoogleMayUseItsSecondIssuerForm(t *testing.T) {
	auth := authntest.NewServer(t)
	public, err := auth.Signing.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	keys := jwk.NewSet()
	if err := keys.AddKey(public); err != nil {
		t.Fatal(err)
	}
	for issuer, aliases := range map[string][]string{
		googleIssuer:               {googleIssuer, googleLegacy},
		"https://idp.example.test": {"https://idp.example.test"},
	} {
		verifier := &JWTVerifier{issuer: issuer, audience: testClient, keys: keys, fetched: time.Now(), idTokenIssuers: aliases}
		for _, form := range []string{googleIssuer, googleLegacy} {
			token := idToken(auth, authntest.Issuer(form))
			claims, err := verifier.VerifyIDToken(t.Context(), token, "nonce-1")
			wantOK := issuer == googleIssuer || form == issuer
			switch {
			case wantOK && err != nil:
				t.Errorf("%s with %s: %v", issuer, form, err)
			case wantOK && claims.Issuer != issuer:
				t.Errorf("%s with %s: the claims carry %q", issuer, form, claims.Issuer)
			case !wantOK && err == nil:
				t.Errorf("%s accepted the issuer form %s", issuer, form)
			}
		}
	}
}

func TestDiscoverReadsTheEndpointsALoginNeeds(t *testing.T) {
	auth := authntest.NewServer(t)
	auth.Meta["authorization_endpoint"] = auth.Server.URL + "/authorize"
	auth.Meta["token_endpoint"] = auth.Server.URL + "/token"
	auth.Meta["token_endpoint_auth_methods_supported"] = []string{"client_secret_post", "client_secret_basic"}
	auth.Meta["authorization_response_iss_parameter_supported"] = true
	_, meta, err := Discover(t.Context(), auth.Server.Client(), auth.Server.URL, testClient)
	if err != nil {
		t.Fatal(err)
	}
	if meta.AuthorizationEndpoint != auth.Server.URL+"/authorize" || meta.TokenEndpoint != auth.Server.URL+"/token" ||
		len(meta.TokenEndpointAuthMethods) != 2 || !meta.IssuerResponseParameter {
		t.Fatalf("%+v", meta)
	}
}
