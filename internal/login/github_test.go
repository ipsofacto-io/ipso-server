package login

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/ipsofacto-io/ipso-server/internal/authn"
	"github.com/ipsofacto-io/ipso-server/internal/identity"
)

// githubRig is a service with one GitHub provider, whose token endpoint and user endpoint are fakes.
type githubRig struct {
	t       *testing.T
	svc     *Service
	handler http.Handler
	store   *fakeStore
	logs    *testLog
	server  *httptest.Server

	mu        sync.Mutex
	challenge string
	userReqs  []*http.Request
	// tokenBody and userBody are the answers. A test changes them.
	tokenStatus int
	tokenBody   string
	userStatus  int
	userBody    string
}

type testLog struct{ buf []byte }

func (l *testLog) Write(p []byte) (int, error) { l.buf = append(l.buf, p...); return len(p), nil }
func (l *testLog) String() string              { return string(l.buf) }

const githubToken = "gho_test-access-token"

func newGitHubRig(t *testing.T) *githubRig {
	t.Helper()
	g := &githubRig{t: t, logs: &testLog{}}
	g.tokenStatus, g.tokenBody = http.StatusOK, "access_token="+githubToken+"&token_type=bearer&scope="
	g.userStatus, g.userBody = http.StatusOK, `{"id": 4242, "login": "ada"}`
	mux := http.NewServeMux()
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		g.mu.Lock()
		defer g.mu.Unlock()
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if r.PostForm.Get("code") != "good-code" || r.PostForm.Get("client_id") != clientID || r.PostForm.Get("client_secret") != clientSecret ||
			r.PostForm.Get("redirect_uri") != publicURL+"/auth/callback/github" || base64.RawURLEncoding.EncodeToString(sum[:]) != g.challenge {
			w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
			_, _ = w.Write([]byte("error=bad_verification_code&error_description=secret+detail"))
			return
		}
		w.Header().Set("Content-Type", "application/x-www-form-urlencoded")
		w.WriteHeader(g.tokenStatus)
		_, _ = w.Write([]byte(g.tokenBody))
	})
	mux.HandleFunc("GET /user", func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		defer g.mu.Unlock()
		g.userReqs = append(g.userReqs, r)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(g.userStatus)
		_, _ = w.Write([]byte(g.userBody))
	})
	g.server = httptest.NewTLSServer(mux)
	t.Cleanup(g.server.Close)

	now := time.Date(2026, 11, 6, 12, 0, 0, 0, time.UTC)
	g.store = newFakeStore(func() time.Time { return now })
	svc, err := New(t.Context(), Options{
		store:     g.store,
		Tenant:    tenant,
		PublicURL: publicURL,
		Providers: []ProviderConfig{{ID: "github", Kind: KindGitHub, ClientID: clientID, ClientSecretEnv: secretEnv}},
		Secret:    func(name string) string { return map[string]string{secretEnv: clientSecret}[name] },
		Client:    g.server.Client(),
		Log:       newLogger(g.logs),
		Now:       func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	p := svc.providers["github"].(*githubProvider)
	p.oauth.Endpoint.TokenURL = g.server.URL + "/token"
	p.userURL = g.server.URL + "/user"
	g.svc, g.handler = svc, svc.Handler()
	return g
}

func (g *githubRig) signIn(mutate func(url.Values)) (*httptest.ResponseRecorder, *url.URL) {
	g.t.Helper()
	rec := httptest.NewRecorder()
	g.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/login/github", nil))
	if rec.Code != http.StatusSeeOther {
		g.t.Fatalf("start = %d", rec.Code)
	}
	loc, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		g.t.Fatal(err)
	}
	g.mu.Lock()
	g.challenge = loc.Query().Get("code_challenge")
	g.mu.Unlock()
	cookie := cookieNamed(rec.Result().Cookies(), attemptCookieName)
	query := url.Values{"code": {"good-code"}, "state": {loc.Query().Get("state")}}
	if mutate != nil {
		mutate(query)
	}
	req := httptest.NewRequest(http.MethodGet, "/auth/callback/github?"+query.Encode(), nil)
	req.AddCookie(&http.Cookie{Name: cookie.Name, Value: cookie.Value})
	out := httptest.NewRecorder()
	g.handler.ServeHTTP(out, req)
	return out, loc
}

func TestAGitHubSignInUsesTheNumericIDAndAsksForNothingElse(t *testing.T) {
	g := newGitHubRig(t)
	g.store.bind(githubIssuer, "4242", identity.KindHuman)
	rec, loc := g.signIn(nil)

	if loc.Host != "github.com" || loc.Path != "/login/oauth/authorize" {
		t.Errorf("sent to %s", loc)
	}
	q := loc.Query()
	if q.Get("client_id") != clientID || q.Get("redirect_uri") != publicURL+"/auth/callback/github" || q.Get("code_challenge_method") != "S256" ||
		q.Get("response_type") != "code" || q.Has("scope") || q.Has("nonce") {
		t.Errorf("authorize parameters %v", q)
	}
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" || cookieNamed(rec.Result().Cookies(), authn.SessionCookieName) == nil {
		t.Fatalf("callback = %d %s", rec.Code, rec.Body)
	}
	if g.store.sessionCount() != 1 {
		t.Errorf("%d sessions", g.store.sessionCount())
	}
	if len(g.userReqs) != 1 {
		t.Fatalf("%d user requests", len(g.userReqs))
	}
	h := g.userReqs[0].Header
	if h.Get("Authorization") != "Bearer "+githubToken || h.Get("Accept") != "application/vnd.github+json" || h.Get("X-GitHub-Api-Version") == "" || h.Get("User-Agent") == "" {
		t.Errorf("user request headers %v", h)
	}
	if contains(g.logs.String(), githubToken) || contains(g.logs.String(), "4242") {
		t.Errorf("the log holds the token or the id:\n%s", g.logs)
	}
}

func TestAGitHubSignInOfAnUnboundIDGetsTheValuesToBind(t *testing.T) {
	g := newGitHubRig(t)
	rec, _ := g.signIn(nil)
	body := bodyCode(t, rec)
	if rec.Code != http.StatusForbidden || body["error"] != "unknown_login" || body["issuer"] != "https://github.com" || body["subject"] != "4242" {
		t.Fatalf("%d %v", rec.Code, body)
	}
}

// GitHub answers 200 with an error in the body for a code it refuses, and the user endpoint answers
// whatever a proxy in between does. Nothing short of a positive numeric id is a person.
func TestAGitHubSignInThatDoesNotYieldAPositiveIDStartsNoSession(t *testing.T) {
	for name, change := range map[string]func(g *githubRig){
		"a token answer with an error": func(g *githubRig) { g.tokenBody = "error=bad_verification_code&error_description=secret+detail" },
		"a token answer with no token": func(g *githubRig) { g.tokenBody = "token_type=bearer" },
		"a token answer of 500":        func(g *githubRig) { g.tokenStatus = 500 },
		"the user endpoint of 401":     func(g *githubRig) { g.userStatus = 401 },
		"the user endpoint of 500":     func(g *githubRig) { g.userStatus = 500 },
		"an id of zero":                func(g *githubRig) { g.userBody = `{"id": 0}` },
		"a negative id":                func(g *githubRig) { g.userBody = `{"id": -5}` },
		"no id":                        func(g *githubRig) { g.userBody = `{"login": "ada"}` },
		"an id that is a float":        func(g *githubRig) { g.userBody = `{"id": 1.5}` },
		"an id in exponent form":       func(g *githubRig) { g.userBody = `{"id": 1e3}` },
		"an id that is a string":       func(g *githubRig) { g.userBody = `{"id": "4242"}` },
		"an id beyond int64":           func(g *githubRig) { g.userBody = `{"id": 99999999999999999999}` },
		"an answer that is not JSON":   func(g *githubRig) { g.userBody = `<html>login</html>` },
		"an empty answer":              func(g *githubRig) { g.userBody = `` },
	} {
		t.Run(name, func(t *testing.T) {
			g := newGitHubRig(t)
			g.store.bind(githubIssuer, "4242", identity.KindHuman)
			g.store.bind(githubIssuer, "1", identity.KindHuman)
			g.store.bind(githubIssuer, "0", identity.KindHuman)
			change(g)
			rec, _ := g.signIn(nil)
			if rec.Code != http.StatusBadRequest || bodyCode(t, rec)["error"] != "invalid_login" || g.store.sessionCount() != 0 || g.store.starts != 0 {
				t.Fatalf("%d %s, %d sessions", rec.Code, rec.Body, g.store.sessionCount())
			}
			for _, leak := range []string{"secret detail", githubToken} {
				if contains(rec.Body.String(), leak) || contains(g.logs.String(), leak) {
					t.Errorf("%q leaked:\n%s", leak, g.logs)
				}
			}
		})
	}
}

func TestAGitHubCallbackWithAnotherIssIsRefused(t *testing.T) {
	g := newGitHubRig(t)
	g.store.bind(githubIssuer, "4242", identity.KindHuman)
	if rec, _ := g.signIn(func(q url.Values) { q.Set("iss", "https://evil.example.test") }); rec.Code != http.StatusBadRequest {
		t.Errorf("another iss: %d", rec.Code)
	}
	// GitHub sends none; one that names GitHub is not a reason to refuse.
	if rec, _ := g.signIn(func(q url.Values) { q.Set("iss", githubIssuer) }); rec.Code != http.StatusSeeOther {
		t.Errorf("iss of GitHub: %d %s", rec.Code, rec.Body)
	}
}

func TestAGitHubSignInWithAWrongStateNeverReachesGitHub(t *testing.T) {
	g := newGitHubRig(t)
	g.store.bind(githubIssuer, "4242", identity.KindHuman)
	rec, _ := g.signIn(func(q url.Values) { q.Set("state", "forged") })
	if rec.Code != http.StatusBadRequest || len(g.userReqs) != 0 {
		t.Fatalf("%d, %d user requests", rec.Code, len(g.userReqs))
	}
}
