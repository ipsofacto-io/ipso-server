package login

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/authn/authntest"
	"github.com/ipsofacto-io/ipso-server/internal/identity"
)

const (
	publicURL    = "https://ipso.example.test"
	clientID     = "ipso-login"
	clientSecret = "test-only-client-secret"
	secretEnv    = "IPSO_LOGIN_FAKE_SECRET"
	subjectOne   = "person-1"
)

var tenant = uuid.MustParse("00000000-0000-4000-8000-00000000000a")

// fakeStore is the database of a session, in memory. A login is bound to a person or to an agent.
type fakeStore struct {
	mu       sync.Mutex
	now      func() time.Time
	logins   map[[2]string]string
	sessions map[string]time.Time

	starts, lookups int
	previous        []byte
	err             error
}

func newFakeStore(now func() time.Time) *fakeStore {
	return &fakeStore{now: now, logins: map[[2]string]string{}, sessions: map[string]time.Time{}}
}

func (f *fakeStore) bind(issuer, subject, kind string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logins[[2]string{issuer, subject}] = kind
}

func (f *fakeStore) start(_ context.Context, issuer, subject string, hash, previous []byte) (time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.starts++
	f.previous = previous
	if f.err != nil {
		return time.Time{}, f.err
	}
	switch f.logins[[2]string{issuer, subject}] {
	case "":
		return time.Time{}, identity.ErrUnknownLogin
	case identity.KindAgent:
		return time.Time{}, identity.ErrNotHuman
	}
	if previous != nil {
		delete(f.sessions, string(previous))
	}
	expires := f.now().Add(8 * time.Hour)
	f.sessions[string(hash)] = expires
	return expires, nil
}

func (f *fakeStore) principal(_ context.Context, hash []byte) (uuid.UUID, time.Time, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lookups++
	if f.err != nil {
		return uuid.Nil, time.Time{}, f.err
	}
	expires, ok := f.sessions[string(hash)]
	if !ok || !f.now().Before(expires) {
		return uuid.Nil, time.Time{}, identity.ErrUnknownSession
	}
	return personID, expires, nil
}

func (f *fakeStore) end(_ context.Context, hash []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	delete(f.sessions, string(hash))
	return nil
}

func (f *fakeStore) sessionCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.sessions)
}

var personID = uuid.MustParse("00000000-0000-4000-8000-0000000000a1")

// rig is a service in front of a fake OpenID Connect provider.
type rig struct {
	t       *testing.T
	auth    *authntest.Server
	svc     *Service
	handler http.Handler
	store   *fakeStore
	logs    *bytes.Buffer
	now     time.Time

	// What the provider's token endpoint saw and answers with.
	mu         sync.Mutex
	tokenForms []url.Values
	challenge  string
	mint       func(nonce string) string
	reject     bool
	omitID     bool
	lastNonce  string
}

type rigOption func(*rigConfig)

type rigConfig struct {
	authOptions []authntest.Option
	meta        map[string]any
	rate        float64
	burst       int
}

func withMeta(key string, value any) rigOption {
	return func(c *rigConfig) { c.meta[key] = value }
}

func withLimits(rate float64, burst int) rigOption {
	return func(c *rigConfig) { c.rate, c.burst = rate, burst }
}

func withKeys(options ...authntest.Option) rigOption {
	return func(c *rigConfig) { c.authOptions = append(c.authOptions, options...) }
}

func newRig(t *testing.T, options ...rigOption) *rig {
	t.Helper()
	cfg := &rigConfig{meta: map[string]any{}}
	for _, option := range options {
		option(cfg)
	}
	auth := authntest.NewServer(t, cfg.authOptions...)
	r := &rig{t: t, auth: auth, logs: &bytes.Buffer{}, now: time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)}
	r.store = newFakeStore(func() time.Time { return r.now })
	r.mint = func(nonce string) string {
		return auth.Token(clientID, nil, authntest.Subject(subjectOne), authntest.Claim("nonce", nonce))
	}
	auth.Meta["authorization_endpoint"] = auth.Server.URL + "/authorize"
	auth.Meta["token_endpoint"] = auth.Server.URL + "/token"
	auth.Meta["token_endpoint_auth_methods_supported"] = []string{"client_secret_post"}
	for key, value := range cfg.meta {
		auth.Meta[key] = value
	}
	auth.Mux.HandleFunc("POST /token", r.token)

	svc, err := New(t.Context(), Options{
		store:     r.store,
		Tenant:    tenant,
		PublicURL: publicURL,
		Providers: []ProviderConfig{{ID: "fake", Kind: KindOIDC, Issuer: auth.Server.URL, ClientID: clientID, ClientSecretEnv: secretEnv}},
		Secret:    func(name string) string { return map[string]string{secretEnv: clientSecret}[name] },
		Forbidden: []string{"https://api.example.test/v1"},
		Client:    auth.Server.Client(),
		Rate:      limitOr(cfg.rate, 100),
		Burst:     int(limitOr(float64(cfg.burst), 100)),
		Log:       newLogger(r.logs),
		Now:       func() time.Time { return r.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	r.svc, r.handler = svc, svc.Handler()
	return r
}

func limitOr(value, fallback float64) rateLimit {
	if value == 0 {
		return rateLimit(fallback)
	}
	return rateLimit(value)
}

// token is the provider's token endpoint. It holds the client to what a real one holds it to.
func (r *rig) token(w http.ResponseWriter, req *http.Request) {
	_ = req.ParseForm()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tokenForms = append(r.tokenForms, req.PostForm)
	sum := sha256.Sum256([]byte(req.PostForm.Get("code_verifier")))
	switch {
	case r.reject,
		req.PostForm.Get("grant_type") != "authorization_code",
		req.PostForm.Get("code") != "good-code",
		req.PostForm.Get("client_id") != clientID,
		req.PostForm.Get("client_secret") != clientSecret,
		req.PostForm.Get("redirect_uri") != publicURL+"/auth/callback/fake",
		base64.RawURLEncoding.EncodeToString(sum[:]) != r.challenge:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"secret detail"}`))
		return
	}
	answer := map[string]any{"access_token": "access-token-1", "token_type": "Bearer", "expires_in": 3600}
	if !r.omitID {
		answer["id_token"] = r.mint(r.lastNonce)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(answer)
}

// attemptOf is a started sign-in as the browser holds it.
type attemptOf struct {
	cookie   *http.Cookie
	state    string
	nonce    string
	location *url.URL
}

func (r *rig) start(provider string, cookies ...*http.Cookie) (*httptest.ResponseRecorder, attemptOf) {
	r.t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/login/"+provider, nil)
	for _, c := range cookies {
		req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
	}
	r.handler.ServeHTTP(rec, req)
	var got attemptOf
	if rec.Code != http.StatusSeeOther {
		return rec, got
	}
	got.cookie = cookieNamed(rec.Result().Cookies(), attemptCookieName)
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		r.t.Fatal(err)
	}
	got.location = loc
	got.state = loc.Query().Get("state")
	got.nonce = loc.Query().Get("nonce")
	r.mu.Lock()
	r.challenge = loc.Query().Get("code_challenge")
	r.lastNonce = got.nonce
	r.mu.Unlock()
	return rec, got
}

func (r *rig) callback(provider string, a attemptOf, query url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	r.t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/auth/callback/"+provider+"?"+query.Encode(), nil)
	if a.cookie != nil {
		req.AddCookie(&http.Cookie{Name: a.cookie.Name, Value: a.cookie.Value})
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	r.handler.ServeHTTP(rec, req)
	return rec
}

func goodQuery(a attemptOf) url.Values {
	return url.Values{"code": {"good-code"}, "state": {a.state}}
}

func cookieNamed(cookies []*http.Cookie, name string) *http.Cookie {
	for _, c := range cookies {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func bodyCode(t *testing.T, rec *httptest.ResponseRecorder) map[string]string {
	t.Helper()
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body %q: %v", rec.Body.String(), err)
	}
	return body
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }
