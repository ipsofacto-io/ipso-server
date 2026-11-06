package login

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ipsofacto-io/ipso-server/internal/authn"
	"github.com/ipsofacto-io/ipso-server/internal/authn/authntest"
	"github.com/ipsofacto-io/ipso-server/internal/identity"
)

// Google sends scope, authuser, and prompt on a callback, and Microsoft sends keys of its own, so a
// callback is read for the keys it needs and the rest is ignored.
func TestASignInEndsInASessionForABoundPerson(t *testing.T) {
	for name, keys := range map[string][]authntest.Option{
		"an EC key with alg":                             nil,
		"an RSA key with no alg, as Microsoft publishes": {authntest.WithRSAKeyWithoutAlg()},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, withKeys(keys...))
			r.store.bind(r.auth.Server.URL, subjectOne, identity.KindHuman)

			rec, a := r.start("fake")
			if rec.Code != http.StatusSeeOther || a.cookie == nil {
				t.Fatalf("start = %d %v", rec.Code, rec.Header())
			}
			q := a.location.Query()
			for key, want := range map[string]string{
				"response_type":         "code",
				"client_id":             clientID,
				"redirect_uri":          publicURL + "/auth/callback/fake",
				"scope":                 "openid",
				"code_challenge_method": "S256",
			} {
				if q.Get(key) != want {
					t.Errorf("%s = %q, want %q", key, q.Get(key), want)
				}
			}
			if a.location.Host != strings.TrimPrefix(r.auth.Server.URL, "https://") || a.location.Path != "/authorize" {
				t.Errorf("sent to %s", a.location)
			}
			if len(a.state) < 40 || len(a.nonce) < 40 || a.state == a.nonce || len(q.Get("code_challenge")) != 43 {
				t.Errorf("state %q, nonce %q, challenge %q", a.state, a.nonce, q.Get("code_challenge"))
			}
			for label, ok := range map[string]bool{
				"Secure":    a.cookie.Secure,
				"HttpOnly":  a.cookie.HttpOnly,
				"Lax":       a.cookie.SameSite == http.SameSiteLaxMode,
				"Path=/":    a.cookie.Path == "/",
				"10 min":    a.cookie.MaxAge == 600,
				"no Domain": a.cookie.Domain == "",
			} {
				if !ok {
					t.Errorf("the attempt cookie is not %s: %v", label, a.cookie)
				}
			}

			query := goodQuery(a)
			query.Set("scope", "openid")
			query.Set("authuser", "0")
			query.Set("prompt", "consent")
			rec = r.callback("fake", a, query)
			if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
				t.Fatalf("callback = %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body)
			}
			cookies := rec.Result().Cookies()
			session := cookieNamed(cookies, authn.SessionCookieName)
			if session == nil || !session.Secure || !session.HttpOnly || session.SameSite != http.SameSiteStrictMode || session.Path != "/" || session.MaxAge != 8*3600 {
				t.Fatalf("session cookie %v", session)
			}
			cleared := cookieNamed(cookies, attemptCookieName)
			if cleared == nil || cleared.MaxAge >= 0 || !cleared.Secure || cleared.Path != "/" {
				t.Errorf("the attempt cookie was not cleared with its own attributes: %v", cleared)
			}
			if r.store.sessionCount() != 1 {
				t.Errorf("%d sessions, want 1", r.store.sessionCount())
			}
			form := r.tokenForms[0]
			if form.Get("client_secret") != clientSecret || form.Get("code_verifier") == "" {
				t.Errorf("token request %v", form)
			}
			for _, secret := range []string{clientSecret, session.Value, "good-code", a.state, a.nonce} {
				if contains(r.logs.String(), secret) {
					t.Errorf("the log holds %q", secret)
				}
			}

			// The cookie it set is the session the guard looks up.
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.AddCookie(&http.Cookie{Name: session.Name, Value: session.Value})
			token, err := authn.SessionToken(req)
			if err != nil {
				t.Fatal(err)
			}
			if principal, status := r.svc.Lookup(t.Context(), token); status != Found || principal != personID {
				t.Errorf("Lookup = %v, %v", principal, status)
			}
		})
	}
}

func TestEverySignInStartsFromNewRandomValues(t *testing.T) {
	r := newRig(t)
	_, first := r.start("fake")
	_, second := r.start("fake")
	if first.state == second.state || first.nonce == second.nonce || first.cookie.Value == second.cookie.Value ||
		first.location.Query().Get("code_challenge") == second.location.Query().Get("code_challenge") {
		t.Fatal("two sign-ins share a value")
	}
}

func TestAPersonTheTenantNeverBoundGetsNoSessionAndTheValuesToBind(t *testing.T) {
	r := newRig(t)
	_, a := r.start("fake")
	rec := r.callback("fake", a, goodQuery(a))

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status %d", rec.Code)
	}
	body := bodyCode(t, rec)
	if body["error"] != "unknown_login" || body["issuer"] != r.auth.Server.URL || body["subject"] != subjectOne {
		t.Fatalf("%v", body)
	}
	if cookieNamed(rec.Result().Cookies(), authn.SessionCookieName) != nil || r.store.sessionCount() != 0 {
		t.Error("a session was started")
	}
	if contains(r.logs.String(), subjectOne) {
		t.Errorf("the log holds the subject:\n%s", r.logs)
	}
}

func TestAnAgentLoginGetsNoBrowserSession(t *testing.T) {
	r := newRig(t)
	r.store.bind(r.auth.Server.URL, subjectOne, identity.KindAgent)
	_, a := r.start("fake")
	rec := r.callback("fake", a, goodQuery(a))
	if rec.Code != http.StatusForbidden || bodyCode(t, rec)["error"] != "forbidden" || r.store.sessionCount() != 0 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestAStoreFailureIsA500WithNoDetail(t *testing.T) {
	r := newRig(t)
	r.store.bind(r.auth.Server.URL, subjectOne, identity.KindHuman)
	r.store.err = errBoom
	_, a := r.start("fake")
	rec := r.callback("fake", a, goodQuery(a))
	if rec.Code != http.StatusInternalServerError || bodyCode(t, rec)["error"] != "internal" || contains(rec.Body.String(), "boom") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

type boom struct{}

func (boom) Error() string { return "boom: the password is hunter2" }

var errBoom = boom{}

// Every refusal below clears the attempt cookie, starts no session, and says nothing the provider sent.
func TestACallbackThatFailsAnyCheckStartsNoSession(t *testing.T) {
	type tweak func(r *rig, a *attemptOf, q url.Values)
	for name, tc := range map[string]struct {
		change tweak
		status int
		code   string
	}{
		"a wrong state":                 {func(_ *rig, _ *attemptOf, q url.Values) { q.Set("state", "another") }, 400, "invalid_login"},
		"no state":                      {func(_ *rig, _ *attemptOf, q url.Values) { q.Del("state") }, 400, "invalid_login"},
		"a state that is only a prefix": {func(_ *rig, a *attemptOf, q url.Values) { q.Set("state", a.state[:10]) }, 400, "invalid_login"},
		"a very long state":             {func(_ *rig, _ *attemptOf, q url.Values) { q.Set("state", strings.Repeat("a", 300)) }, 400, "invalid_login"},
		"no code":                       {func(_ *rig, _ *attemptOf, q url.Values) { q.Del("code") }, 400, "invalid_login"},
		"a very long code":              {func(_ *rig, _ *attemptOf, q url.Values) { q.Set("code", strings.Repeat("a", 5000)) }, 400, "invalid_login"},
		"a repeated state":              {func(_ *rig, a *attemptOf, q url.Values) { q.Add("state", a.state) }, 400, "invalid_login"},
		"a repeated code":               {func(_ *rig, _ *attemptOf, q url.Values) { q.Add("code", "good-code") }, 400, "invalid_login"},
		"an error from the provider": {func(_ *rig, _ *attemptOf, q url.Values) {
			q.Set("error", "access_denied")
			q.Set("error_description", "the user said no")
		}, 400, "login_refused"},
		"another issuer in iss":                {func(_ *rig, _ *attemptOf, q url.Values) { q.Set("iss", "https://evil.example.test") }, 400, "invalid_login"},
		"no attempt cookie":                    {func(_ *rig, a *attemptOf, _ url.Values) { a.cookie = nil }, 400, "invalid_login"},
		"an attempt cookie that is not base64": {func(_ *rig, a *attemptOf, _ url.Values) { a.cookie.Value = "!!not base64!!" }, 400, "invalid_login"},
		"an attempt cookie that is not JSON":   {func(_ *rig, a *attemptOf, _ url.Values) { a.cookie.Value = "bm90IGpzb24" }, 400, "invalid_login"},
		"a rejected code":                      {func(_ *rig, _ *attemptOf, q url.Values) { q.Set("code", "bad-code") }, 400, "invalid_login"},
		"a token endpoint that refuses":        {func(r *rig, _ *attemptOf, _ url.Values) { r.reject = true }, 400, "invalid_login"},
		"an answer with no ID token":           {func(r *rig, _ *attemptOf, _ url.Values) { r.omitID = true }, 400, "invalid_login"},
		"an ID token with another nonce": {func(r *rig, _ *attemptOf, _ url.Values) {
			r.mint = func(string) string {
				return r.auth.Token(clientID, nil, authntest.Subject(subjectOne), authntest.Claim("nonce", "another"))
			}
		}, 400, "invalid_login"},
		"an ID token with no nonce": {func(r *rig, _ *attemptOf, _ url.Values) {
			r.mint = func(string) string { return r.auth.Token(clientID, nil, authntest.Subject(subjectOne)) }
		}, 400, "invalid_login"},
		"an ID token for another client": {func(r *rig, _ *attemptOf, _ url.Values) {
			r.mint = func(nonce string) string {
				return r.auth.Token("another-client", nil, authntest.Subject(subjectOne), authntest.Claim("nonce", nonce))
			}
		}, 400, "invalid_login"},
		"an ID token from another issuer": {func(r *rig, _ *attemptOf, _ url.Values) {
			r.mint = func(nonce string) string {
				return r.auth.Token(clientID, nil, authntest.Subject(subjectOne), authntest.Claim("nonce", nonce), authntest.Issuer("https://evil.example.test"))
			}
		}, 400, "invalid_login"},
		"an ID token that is garbage": {func(r *rig, _ *attemptOf, _ url.Values) { r.mint = func(string) string { return "not.a.jwt" } }, 400, "invalid_login"},
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.store.bind(r.auth.Server.URL, subjectOne, identity.KindHuman)
			_, a := r.start("fake")
			query := goodQuery(a)
			tc.change(r, &a, query)
			rec := r.callback("fake", a, query)

			if rec.Code != tc.status || bodyCode(t, rec)["error"] != tc.code {
				t.Fatalf("%d %s", rec.Code, rec.Body)
			}
			if r.store.sessionCount() != 0 || r.store.starts != 0 {
				t.Error("a session was started or asked for")
			}
			if cleared := cookieNamed(rec.Result().Cookies(), attemptCookieName); cleared == nil || cleared.MaxAge >= 0 {
				t.Errorf("the attempt cookie was not cleared: %v", rec.Header()["Set-Cookie"])
			}
			if cookieNamed(rec.Result().Cookies(), authn.SessionCookieName) != nil {
				t.Error("a session cookie was set")
			}
			for _, leak := range []string{"secret detail", "access-token-1", "the user said no"} {
				if contains(rec.Body.String(), leak) || contains(r.logs.String(), leak) {
					t.Errorf("%q reached the answer or the log:\n%s", leak, r.logs)
				}
			}
			// The short error code of RFC 6749 may be logged for an operator. The answer never carries it.
			if contains(rec.Body.String(), "invalid_grant") {
				t.Errorf("the provider's error code reached the answer: %s", rec.Body)
			}
		})
	}
}

func TestAnAttemptCookieOfAnotherProviderIsRefused(t *testing.T) {
	r := newRig(t)
	r.store.bind(r.auth.Server.URL, subjectOne, identity.KindHuman)
	_, a := r.start("fake")
	other := attempt{Provider: "github", State: a.state, Nonce: a.nonce, Verifier: "v"}.cookie()
	a.cookie = other
	if rec := r.callback("fake", a, goodQuery(a)); rec.Code != http.StatusBadRequest {
		t.Fatalf("status %d", rec.Code)
	}
}

func TestTwoAttemptCookiesAreRefused(t *testing.T) {
	r := newRig(t)
	r.store.bind(r.auth.Server.URL, subjectOne, identity.KindHuman)
	_, a := r.start("fake")
	rec := r.callback("fake", a, goodQuery(a), &http.Cookie{Name: attemptCookieName, Value: a.cookie.Value})
	if rec.Code != http.StatusBadRequest || r.store.sessionCount() != 0 {
		t.Fatalf("status %d", rec.Code)
	}
}

// A provider that promises the iss parameter (RFC 9207) must send it, so a response from another
// authorization server cannot be mixed in.
func TestAProviderThatPromisesIssMustSendIt(t *testing.T) {
	r := newRig(t, withMeta("authorization_response_iss_parameter_supported", true))
	r.store.bind(r.auth.Server.URL, subjectOne, identity.KindHuman)

	_, a := r.start("fake")
	if rec := r.callback("fake", a, goodQuery(a)); rec.Code != http.StatusBadRequest {
		t.Fatalf("a callback with no iss: %d", rec.Code)
	}
	_, a = r.start("fake")
	query := goodQuery(a)
	query.Set("iss", r.auth.Server.URL)
	if rec := r.callback("fake", a, query); rec.Code != http.StatusSeeOther {
		t.Fatalf("a callback with iss: %d %s", rec.Code, rec.Body)
	}
}

func TestOnlyGETStartsOrFinishesASignIn(t *testing.T) {
	r := newRig(t)
	for _, tc := range []struct{ method, path string }{
		{http.MethodHead, "/auth/login/fake"},
		{http.MethodPost, "/auth/login/fake"},
		{http.MethodHead, "/auth/callback/fake?code=good-code&state=x"},
		{http.MethodPost, "/auth/callback/fake?code=good-code&state=x"},
		{http.MethodGet, "/auth/logout"},
		{http.MethodHead, "/auth/logout"},
	} {
		rec := httptest.NewRecorder()
		r.handler.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.path, nil))
		if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") == "" {
			t.Errorf("%s %s = %d", tc.method, tc.path, rec.Code)
		}
	}
	if len(r.tokenForms) != 0 {
		t.Error("the token endpoint was called")
	}
}

func TestAnUnknownProviderOrPathIs404(t *testing.T) {
	r := newRig(t)
	for _, path := range []string{"/auth/login/nobody", "/auth/callback/nobody?code=a&state=b", "/auth/nothing", "/auth/login/", "/auth/login/fake/extra"} {
		rec := httptest.NewRecorder()
		r.handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s = %d", path, rec.Code)
		}
	}
}

func TestEveryAnswerIsNotCachedAndSendsNoReferrer(t *testing.T) {
	r := newRig(t)
	_, a := r.start("fake")
	requests := []*http.Request{
		httptest.NewRequest(http.MethodGet, "/auth/login/fake", nil),
		httptest.NewRequest(http.MethodGet, "/auth/callback/fake?code=x&state=y", nil),
		httptest.NewRequest(http.MethodGet, "/auth/callback/nobody", nil),
		httptest.NewRequest(http.MethodPost, "/auth/logout", nil),
		httptest.NewRequest(http.MethodGet, "/auth/nothing", nil),
		httptest.NewRequest(http.MethodGet, "/auth/logout", nil),
	}
	good := httptest.NewRequest(http.MethodGet, "/auth/callback/fake?"+goodQuery(a).Encode(), nil)
	good.AddCookie(&http.Cookie{Name: a.cookie.Name, Value: a.cookie.Value})
	requests = append(requests, good)
	for _, req := range requests {
		rec := httptest.NewRecorder()
		r.handler.ServeHTTP(rec, req)
		if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Referrer-Policy") != "no-referrer" || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s %s: %v", req.Method, req.URL, rec.Header())
		}
	}
}

// The token endpoint is called, and the database written, only inside the bucket.
func TestCallbacksPastTheBucketAreRefusedBeforeTheProviderIsCalled(t *testing.T) {
	r := newRig(t, withLimits(1, 2))
	r.store.bind(r.auth.Server.URL, subjectOne, identity.KindHuman)
	var statuses []int
	for range 4 {
		_, a := r.start("fake")
		rec := r.callback("fake", a, goodQuery(a))
		statuses = append(statuses, rec.Code)
		if rec.Code == http.StatusTooManyRequests && rec.Header().Get("Retry-After") == "" {
			t.Error("no Retry-After")
		}
	}
	if statuses[0] != http.StatusSeeOther || statuses[1] != http.StatusSeeOther || statuses[2] != http.StatusTooManyRequests || statuses[3] != http.StatusTooManyRequests {
		t.Fatalf("statuses %v", statuses)
	}
	if len(r.tokenForms) != 2 {
		t.Errorf("the provider was called %d times, want 2", len(r.tokenForms))
	}
	r.now = r.now.Add(10 * time.Second)
	_, a := r.start("fake")
	if rec := r.callback("fake", a, goodQuery(a)); rec.Code != http.StatusSeeOther {
		t.Errorf("after the bucket refilled: %d", rec.Code)
	}
}

func TestASignInEndsTheSessionTheBrowserSent(t *testing.T) {
	r := newRig(t)
	r.store.bind(r.auth.Server.URL, subjectOne, identity.KindHuman)
	_, a := r.start("fake")
	rec := r.callback("fake", a, goodQuery(a))
	first := cookieNamed(rec.Result().Cookies(), authn.SessionCookieName)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: first.Name, Value: first.Value})
	token, _ := authn.SessionToken(req)
	if _, status := r.svc.Lookup(t.Context(), token); status != Found {
		t.Fatalf("first session: %v", status)
	}

	_, a = r.start("fake")
	rec = r.callback("fake", a, goodQuery(a), &http.Cookie{Name: first.Name, Value: first.Value})
	second := cookieNamed(rec.Result().Cookies(), authn.SessionCookieName)
	if second == nil || second.Value == first.Value {
		t.Fatalf("second cookie %v", second)
	}
	if string(r.store.previous) != string(authn.SessionHash(token)) {
		t.Error("the sign-in did not pass the old session on")
	}
	if r.store.sessionCount() != 1 {
		t.Errorf("%d sessions, want 1", r.store.sessionCount())
	}
	if _, status := r.svc.Lookup(t.Context(), token); status != Unknown {
		t.Errorf("the old session is %v, want Unknown (and not served from the cache)", status)
	}
}

// The callback is a request from the provider's site, so a SameSite=Strict cookie is not sent with it.
// The sign-in remembers the session the browser held when it began, which is a request from this site,
// and ends that one.
func TestASignInEndsTheSessionTheBrowserHeldWhenItBegan(t *testing.T) {
	r := newRig(t)
	r.store.bind(r.auth.Server.URL, subjectOne, identity.KindHuman)
	_, a := r.start("fake")
	first := cookieNamed(r.callback("fake", a, goodQuery(a)).Result().Cookies(), authn.SessionCookieName)
	held := &http.Cookie{Name: first.Name, Value: first.Value}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(held)
	token, _ := authn.SessionToken(req)
	if _, status := r.svc.Lookup(t.Context(), token); status != Found {
		t.Fatalf("first session: %v", status)
	}

	// The sign-in begins on this site with the cookie, and comes back without it.
	_, a = r.start("fake", held)
	rec := r.callback("fake", a, goodQuery(a))
	second := cookieNamed(rec.Result().Cookies(), authn.SessionCookieName)
	if rec.Code != http.StatusSeeOther || second == nil || second.Value == first.Value {
		t.Fatalf("callback = %d, %v", rec.Code, second)
	}
	if string(r.store.previous) != string(authn.SessionHash(token)) {
		t.Errorf("the sign-in passed on %x, want the hash of the session held at the start", r.store.previous)
	}
	if r.store.sessionCount() != 1 {
		t.Errorf("%d sessions, want 1", r.store.sessionCount())
	}
	if _, status := r.svc.Lookup(t.Context(), token); status != Unknown {
		t.Errorf("the replaced session is %v, want Unknown", status)
	}
}

func TestASignInThatBeganWithoutASessionEndsNone(t *testing.T) {
	r := newRig(t)
	r.store.bind(r.auth.Server.URL, subjectOne, identity.KindHuman)
	_, a := r.start("fake")
	raw, err := base64.RawURLEncoding.DecodeString(a.cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	if contains(string(raw), `"o"`) {
		t.Errorf("the attempt names a previous session: %s", raw)
	}
	if rec := r.callback("fake", a, goodQuery(a)); rec.Code != http.StatusSeeOther {
		t.Fatalf("status %d", rec.Code)
	}
	if r.store.previous != nil {
		t.Errorf("the sign-in passed on %x", r.store.previous)
	}
}

// What the attempt names as previous is a hash the server wrote, and a value that is not one ends nothing.
func TestAMalformedPreviousSessionInTheAttemptIsIgnored(t *testing.T) {
	for name, previous := range map[string]string{
		"not base64": "!!!",
		"too short":  base64.RawURLEncoding.EncodeToString([]byte("short")),
		"too long":   base64.RawURLEncoding.EncodeToString(make([]byte, 33)),
		"padded":     base64.URLEncoding.EncodeToString(make([]byte, 31)),
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t)
			r.store.bind(r.auth.Server.URL, subjectOne, identity.KindHuman)
			_, a := r.start("fake")
			var decoded attempt
			raw, _ := base64.RawURLEncoding.DecodeString(a.cookie.Value)
			if err := json.Unmarshal(raw, &decoded); err != nil {
				t.Fatal(err)
			}
			decoded.Previous = previous
			a.cookie = decoded.cookie()
			if rec := r.callback("fake", a, goodQuery(a)); rec.Code != http.StatusSeeOther {
				t.Fatalf("status %d: %s", rec.Code, rec.Body)
			}
			if r.store.previous != nil {
				t.Errorf("the sign-in passed on %x", r.store.previous)
			}
		})
	}
}

func TestLogoutEndsTheSessionAndClearsTheCookie(t *testing.T) {
	r := newRig(t)
	r.store.bind(r.auth.Server.URL, subjectOne, identity.KindHuman)
	_, a := r.start("fake")
	session := cookieNamed(r.callback("fake", a, goodQuery(a)).Result().Cookies(), authn.SessionCookieName)
	cookie := &http.Cookie{Name: session.Name, Value: session.Value}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	token, _ := authn.SessionToken(req)
	if _, status := r.svc.Lookup(t.Context(), token); status != Found {
		t.Fatal("not found")
	}

	logout := func(headers map[string]string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		for _, c := range cookies {
			req.AddCookie(c)
		}
		rec := httptest.NewRecorder()
		r.handler.ServeHTTP(rec, req)
		return rec
	}

	for name, headers := range map[string]map[string]string{
		"a request from another site":          {"Sec-Fetch-Site": "cross-site"},
		"a request from a sibling subdomain":   {"Sec-Fetch-Site": "same-site"},
		"an Origin of another site":            {"Origin": "https://evil.example.test"},
		"an Origin of the same host on http":   {"Origin": "http://ipso.example.test"},
		"an Origin of the same host on a port": {"Origin": "https://ipso.example.test:8443"},
	} {
		rec := logout(headers, cookie)
		if rec.Code != http.StatusForbidden || r.store.sessionCount() != 1 {
			t.Errorf("%s: %d, %d sessions", name, rec.Code, r.store.sessionCount())
		}
	}

	rec := logout(map[string]string{"Sec-Fetch-Site": "same-origin"}, cookie)
	if rec.Code != http.StatusNoContent || r.store.sessionCount() != 0 {
		t.Fatalf("%d, %d sessions", rec.Code, r.store.sessionCount())
	}
	if c := cookieNamed(rec.Result().Cookies(), authn.SessionCookieName); c == nil || c.MaxAge >= 0 || !c.Secure || c.Path != "/" {
		t.Errorf("the cookie was not cleared: %v", rec.Header()["Set-Cookie"])
	}
	if _, status := r.svc.Lookup(t.Context(), token); status != Unknown {
		t.Errorf("a logged-out session is %v, want Unknown", status)
	}
	// An Origin the proxy dropped the port from is still the public origin.
	if rec := logout(map[string]string{"Origin": publicURL}, cookie); rec.Code != http.StatusNoContent {
		t.Errorf("the public origin: %d", rec.Code)
	}
	// Signing out twice, with nothing, or with garbage, is the same as signing out once.
	for name, cookies := range map[string][]*http.Cookie{
		"no cookie":    nil,
		"a bad cookie": {{Name: authn.SessionCookieName, Value: "short"}},
		"two cookies":  {cookie, cookie},
	} {
		rec := logout(map[string]string{"Sec-Fetch-Site": "same-origin"}, cookies...)
		if rec.Code != http.StatusNoContent || cookieNamed(rec.Result().Cookies(), authn.SessionCookieName) == nil {
			t.Errorf("%s: %d %v", name, rec.Code, rec.Header()["Set-Cookie"])
		}
	}
}

// A made-up cookie is a delete that anyone can ask for, so it costs a token of the bucket.
func TestLogoutOfACookieNotKeptIsLimited(t *testing.T) {
	r := newRig(t, withLimits(1, 2))
	token, _ := authn.NewSessionToken()
	var statuses []int
	for range 3 {
		req := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		req.AddCookie(authn.NewSessionCookie(token, r.now.Add(time.Hour), r.now))
		rec := httptest.NewRecorder()
		r.handler.ServeHTTP(rec, req)
		statuses = append(statuses, rec.Code)
	}
	if statuses[0] != http.StatusNoContent || statuses[1] != http.StatusNoContent || statuses[2] != http.StatusTooManyRequests {
		t.Fatalf("statuses %v", statuses)
	}
}

func TestLookupKeepsASessionForAMinuteAndNeverPastItsEnd(t *testing.T) {
	r := newRig(t)
	r.store.bind(r.auth.Server.URL, subjectOne, identity.KindHuman)
	token, _ := authn.NewSessionToken()
	hash := authn.SessionHash(token)
	r.store.sessions[string(hash)] = r.now.Add(90 * time.Second)

	for range 3 {
		if principal, status := r.svc.Lookup(t.Context(), token); status != Found || principal != personID {
			t.Fatalf("%v %v", principal, status)
		}
	}
	if r.store.lookups != 1 {
		t.Errorf("%d database lookups for 3 calls, want 1", r.store.lookups)
	}
	r.now = r.now.Add(61 * time.Second)
	if _, status := r.svc.Lookup(t.Context(), token); status != Found || r.store.lookups != 2 {
		t.Errorf("after a minute: %v, %d lookups", status, r.store.lookups)
	}
	// The session ends 29 seconds from now, so it is kept for 29 seconds and not for a minute.
	r.now = r.now.Add(30 * time.Second)
	if _, status := r.svc.Lookup(t.Context(), token); status != Unknown {
		t.Errorf("after the session ended: %v, want Unknown", status)
	}
}

func TestLookupNeverKeepsAMissAndLimitsTheDatabase(t *testing.T) {
	r := newRig(t, withLimits(1, 3))
	var statuses []Status
	for range 5 {
		token, _ := authn.NewSessionToken()
		_, status := r.svc.Lookup(t.Context(), token)
		statuses = append(statuses, status)
	}
	want := []Status{Unknown, Unknown, Unknown, Busy, Busy}
	for i := range want {
		if statuses[i] != want[i] {
			t.Fatalf("statuses %v, want %v", statuses, want)
		}
	}
	if r.store.lookups != 3 {
		t.Errorf("%d lookups reached the store, want 3", r.store.lookups)
	}
	// A session the process already keeps is served while the bucket is empty.
	token, _ := authn.NewSessionToken()
	r.now = r.now.Add(time.Minute)
	r.store.sessions[string(authn.SessionHash(token))] = r.now.Add(time.Hour)
	if _, status := r.svc.Lookup(t.Context(), token); status != Found {
		t.Fatalf("a valid session: %v", status)
	}
	for range 5 {
		other, _ := authn.NewSessionToken()
		r.svc.Lookup(t.Context(), other)
	}
	if _, status := r.svc.Lookup(t.Context(), token); status != Found {
		t.Errorf("a kept session with an empty bucket: %v", status)
	}
}

func TestLookupSaysFailedWhenTheDatabaseDoes(t *testing.T) {
	r := newRig(t)
	r.store.err = errBoom
	token, _ := authn.NewSessionToken()
	if _, status := r.svc.Lookup(t.Context(), token); status != Failed {
		t.Fatalf("status %v", status)
	}
	if contains(r.logs.String(), "hunter2") {
		t.Errorf("the log holds the database error:\n%s", r.logs)
	}
}
