package api

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ipsofacto-io/ipso-server/internal/authn"
)

const publicOrigin = "https://ipso.example.test"

// sessionLookup is a Lookup that counts its calls and answers a fixed status.
type sessionLookup struct {
	calls  int
	tokens [][]byte
	status SessionStatus
	caller Caller
}

func (l *sessionLookup) lookup(_ context.Context, token []byte) (Caller, SessionStatus) {
	l.calls++
	l.tokens = append(l.tokens, token)
	return l.caller, l.status
}

func newSessionAPI(t *testing.T, sessions *Sessions) http.Handler {
	t.Helper()
	db, err := sql.Open("pgx", unreachable)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	handler, err := New(Config{DB: db, Verifier: fakeVerifier{}, Callers: callerOf(tenantA), Policy: testPolicy(t), Sessions: sessions})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func newLookup(status SessionStatus) (*sessionLookup, *Sessions) {
	l := &sessionLookup{status: status, caller: Caller{Tenant: tenantA, Principal: someone}}
	return l, &Sessions{Origin: publicOrigin, Lookup: l.lookup}
}

func sessionCookie(t *testing.T) *http.Cookie {
	t.Helper()
	token, err := authn.NewSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	return &http.Cookie{Name: authn.SessionCookieName, Value: authn.NewSessionCookie(token, time.Now().Add(time.Hour), time.Now()).Value}
}

func withCookies(method, target string, headers map[string]string, cookies ...*http.Cookie) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	for _, c := range cookies {
		r.AddCookie(c)
	}
	return r
}

func serve(handler http.Handler, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}

func clearsTheCookie(w *httptest.ResponseRecorder) bool {
	for _, c := range w.Result().Cookies() {
		if c.Name == authn.SessionCookieName && c.MaxAge < 0 && c.Secure && c.Path == "/" {
			return true
		}
	}
	return false
}

func TestNewRefusesSessionsItCannotUse(t *testing.T) {
	db, err := sql.Open("pgx", unreachable)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	_, good := newLookup(SessionFound)
	for name, sessions := range map[string]*Sessions{
		"no lookup":             {Origin: publicOrigin},
		"no origin":             {Lookup: good.Lookup},
		"an origin with a path": {Origin: publicOrigin + "/app", Lookup: good.Lookup},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := New(Config{DB: db, Verifier: fakeVerifier{}, Callers: callerOf(tenantA), Policy: testPolicy(t), Sessions: sessions}); err == nil {
				t.Fatal("New accepted it")
			}
		})
	}
}

// With sign-in off a cookie is not read at all, so a session that was made before an operator removed
// the providers stops working at once.
func TestTheCookieIsIgnoredWhenSignInIsOff(t *testing.T) {
	handler := newSessionAPI(t, nil)
	w := serve(handler, withCookies(http.MethodGet, "/v1/decisions", nil, sessionCookie(t)))
	if w.Code != http.StatusUnauthorized || errorOf(t, w) != errUnauthorized {
		t.Fatalf("status %d", w.Code)
	}
	if clearsTheCookie(w) {
		t.Error("a cookie the guard does not read was cleared")
	}
}

func TestACallWithNoCredentialIsAskedForOne(t *testing.T) {
	l, sessions := newLookup(SessionFound)
	w := serve(newSessionAPI(t, sessions), httptest.NewRequest(http.MethodGet, "/v1/decisions", nil))
	if w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") != `Bearer realm="ipso"` || l.calls != 0 || clearsTheCookie(w) {
		t.Fatalf("status %d, %d lookups, %v", w.Code, l.calls, w.Header())
	}
}

func TestAGoodSessionPassesTheGuard(t *testing.T) {
	l, sessions := newLookup(SessionFound)
	cookie := sessionCookie(t)
	w := serve(newSessionAPI(t, sessions), withCookies(http.MethodGet, "/v1/decisions", nil, cookie))
	// The store is unreachable, so a call that gets past the guard fails there, with 500 and no lookup error.
	if w.Code != http.StatusInternalServerError || l.calls != 1 {
		t.Fatalf("status %d, %d lookups", w.Code, l.calls)
	}
	got, err := authn.SessionToken(withCookies(http.MethodGet, "/", nil, cookie))
	if err != nil || string(l.tokens[0]) != string(got) {
		t.Errorf("the lookup got %x, want the 32 bytes of the cookie", l.tokens[0])
	}
}

// A request that carries an Authorization header is a bearer call, whatever cookie it also carries, so a
// script cannot be made to act as a signed-in person by a cookie it did not choose.
func TestABearerHeaderWinsOverACookie(t *testing.T) {
	l, sessions := newLookup(SessionFound)
	handler := newSessionAPI(t, sessions)

	w := serve(handler, withCookies(http.MethodGet, "/v1/decisions", map[string]string{"Authorization": "Bearer bad"}, sessionCookie(t)))
	if w.Code != http.StatusUnauthorized || w.Header().Get("WWW-Authenticate") != `Bearer realm="ipso", error="invalid_token"` {
		t.Fatalf("a bad token and a good cookie: status %d", w.Code)
	}
	w = serve(handler, withCookies(http.MethodGet, "/v1/decisions", map[string]string{"Authorization": "Bearer good"}, &http.Cookie{Name: authn.SessionCookieName, Value: "garbage"}))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("a good token and a bad cookie: status %d", w.Code)
	}
	if l.calls != 0 {
		t.Errorf("the cookie was looked up %d times", l.calls)
	}
}

func TestACookieThatIsNotWellFormedIsRefusedBeforeTheLookup(t *testing.T) {
	l, sessions := newLookup(SessionFound)
	handler := newSessionAPI(t, sessions)
	good := sessionCookie(t)
	for name, cookies := range map[string][]*http.Cookie{
		"too short":  {{Name: authn.SessionCookieName, Value: "abc"}},
		"too long":   {{Name: authn.SessionCookieName, Value: good.Value + "A"}},
		"not base64": {{Name: authn.SessionCookieName, Value: strings.Repeat("!", 43)}},
		"empty":      {{Name: authn.SessionCookieName, Value: ""}},
		"sent twice": {good, good},
	} {
		t.Run(name, func(t *testing.T) {
			w := serve(handler, withCookies(http.MethodGet, "/v1/decisions", nil, cookies...))
			if w.Code != http.StatusUnauthorized || !clearsTheCookie(w) || errorOf(t, w) != errUnauthorized {
				t.Fatalf("status %d, cleared %v", w.Code, clearsTheCookie(w))
			}
		})
	}
	if l.calls != 0 {
		t.Errorf("%d lookups for cookies that are not tokens", l.calls)
	}
}

func TestEachOutcomeOfALookupHasItsOwnAnswer(t *testing.T) {
	for name, tc := range map[string]struct {
		status  SessionStatus
		caller  *Caller
		want    int
		cleared bool
		retry   string
	}{
		"unknown":      {SessionUnknown, nil, http.StatusUnauthorized, true, ""},
		"busy":         {SessionBusy, nil, http.StatusTooManyRequests, false, "1"},
		"failed":       {SessionFailed, nil, http.StatusInternalServerError, false, ""},
		"no tenant":    {SessionFound, &Caller{Principal: someone}, http.StatusForbidden, false, ""},
		"no principal": {SessionFound, &Caller{Tenant: tenantA}, http.StatusForbidden, false, ""},
	} {
		t.Run(name, func(t *testing.T) {
			l, sessions := newLookup(tc.status)
			if tc.caller != nil {
				l.caller = *tc.caller
			}
			w := serve(newSessionAPI(t, sessions), withCookies(http.MethodGet, "/v1/decisions", nil, sessionCookie(t)))
			if w.Code != tc.want || clearsTheCookie(w) != tc.cleared || w.Header().Get("Retry-After") != tc.retry {
				t.Fatalf("status %d, cleared %v, Retry-After %q", w.Code, clearsTheCookie(w), w.Header().Get("Retry-After"))
			}
			if w.Code == http.StatusInternalServerError && errorOf(t, w) != errInternal {
				t.Error("the error says more than internal")
			}
		})
	}
}

// A browser sends the cookie on a request another site makes, so a request that could change state is
// refused when it comes from another origin, before the cookie is looked up.
func TestACrossOriginRequestThatCouldChangeStateIsRefusedBeforeTheLookup(t *testing.T) {
	l, sessions := newLookup(SessionFound)
	handler := newSessionAPI(t, sessions)
	cookie := sessionCookie(t)

	for name, headers := range map[string]map[string]string{
		"from another site":              {"Sec-Fetch-Site": "cross-site"},
		"from a sibling subdomain":       {"Sec-Fetch-Site": "same-site"},
		"with an Origin of another site": {"Origin": "https://evil.example.test"},
		"with an Origin on http":         {"Origin": "http://ipso.example.test"},
	} {
		w := serve(handler, withCookies(http.MethodPost, "/v1/resolve", headers, cookie))
		if w.Code != http.StatusForbidden || errorOf(t, w) != errForbidden {
			t.Errorf("%s: status %d", name, w.Code)
		}
	}
	if l.calls != 0 {
		t.Fatalf("%d lookups for refused requests", l.calls)
	}

	// A read passes from anywhere, as the browser never sends a cookie for a read that a page can see.
	// The ones that change nothing and the same origin are served.
	for name, request := range map[string]*http.Request{
		"a GET from another site":           withCookies(http.MethodGet, "/v1/decisions", map[string]string{"Sec-Fetch-Site": "cross-site"}, cookie),
		"a POST from the same origin":       withCookies(http.MethodPost, "/v1/resolve?x=1", map[string]string{"Sec-Fetch-Site": "same-origin"}, cookie),
		"a POST with the public Origin":     withCookies(http.MethodPost, "/v1/resolve?x=1", map[string]string{"Origin": publicOrigin}, cookie),
		"a POST that is not from a browser": withCookies(http.MethodPost, "/v1/resolve?x=1", nil, cookie),
	} {
		before := l.calls
		serve(handler, request)
		if l.calls != before+1 {
			t.Errorf("%s was not looked up", name)
		}
	}
}

func TestAQueryAfterASessionIsStillChecked(t *testing.T) {
	_, sessions := newLookup(SessionFound)
	w := serve(newSessionAPI(t, sessions), withCookies(http.MethodGet, "/v1/decisions?tenant="+tenantB.String(), nil, sessionCookie(t)))
	if w.Code != http.StatusBadRequest || errorOf(t, w) != errInvalidQuery {
		t.Fatalf("status %d", w.Code)
	}
}
