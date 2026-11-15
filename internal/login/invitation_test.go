package login

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ipsofacto-io/ipso-server/internal/authn"
	"github.com/ipsofacto-io/ipso-server/internal/identity"
)

// newToken is an invitation token and the fake store holding an open invitation for it.
func newToken(t *testing.T, r *rig) string {
	t.Helper()
	token, _, err := identity.NewInvitationToken()
	if err != nil {
		t.Fatal(err)
	}
	r.store.open(token)
	return token
}

// attemptCookieOf reads what the attempt cookie of a sign-in holds.
func attemptCookieOf(t *testing.T, a attemptOf) attempt {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(a.cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	var got attempt
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	return got
}

func TestAnInvitedPersonSignsInAndIsBoundOnce(t *testing.T) {
	r := newRig(t)
	token := newToken(t, r)

	a := r.invited(token)
	if got := attemptCookieOf(t, a); got.Invitation != token {
		t.Fatalf("the attempt cookie holds %q, want the token the page sent", got.Invitation)
	}
	if !r.store.isOpen(token) {
		t.Fatal("starting the sign-in used the invitation: it is used at the callback")
	}
	rec := r.callback("fake", a, goodQuery(a))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
		t.Fatalf("callback: %d %s", rec.Code, rec.Body)
	}
	cookie := cookieNamed(rec.Result().Cookies(), authn.SessionCookieName)
	if cookie == nil || r.store.sessionCount() != 1 {
		t.Fatal("the person got no session")
	}
	if r.store.isOpen(token) {
		t.Error("the invitation is still open after it was used")
	}
	if cleared := cookieNamed(rec.Result().Cookies(), attemptCookieName); cleared == nil || cleared.MaxAge >= 0 {
		t.Error("the attempt cookie, which holds the token, was not cleared")
	}

	// A second use of the same link fails before the provider is asked, and sets no cookie.
	again := r.invite("fake", `{"token":"`+token+`"}`, nil)
	if again.Code != http.StatusForbidden || bodyCode(t, again)["error"] != "unknown_invitation" {
		t.Fatalf("second use: %d %s", again.Code, again.Body)
	}
	if cookieNamed(again.Result().Cookies(), attemptCookieName) != nil {
		t.Error("a refused invitation set an attempt cookie")
	}
	if contains(r.logs.String(), token) {
		t.Errorf("the log holds the token:\n%s", r.logs)
	}
}

func TestAnInvitationUsedBetweenTheStartAndTheCallbackIsRefusedWithNoSession(t *testing.T) {
	r := newRig(t)
	token := newToken(t, r)
	a := r.invited(token)

	// Another sign-in used it first.
	hash, _ := identity.InvitationHash(token)
	delete(r.store.invitations, string(hash))

	rec := r.callback("fake", a, goodQuery(a))
	if rec.Code != http.StatusForbidden || bodyCode(t, rec)["error"] != "unknown_invitation" {
		t.Fatalf("callback: %d %s", rec.Code, rec.Body)
	}
	if cookieNamed(rec.Result().Cookies(), authn.SessionCookieName) != nil || r.store.sessionCount() != 0 {
		t.Error("a session was started")
	}
	if strings.Contains(rec.Body.String(), token) || contains(r.logs.String(), token) || contains(r.logs.String(), subjectOne) {
		t.Errorf("the answer or the log holds the token or the subject:\n%s\n%s", rec.Body, r.logs)
	}
}

func TestAPersonAlreadyBoundSignsInAndLeavesTheInvitationOpen(t *testing.T) {
	r := newRig(t)
	r.store.bind(r.auth.Server.URL, subjectOne, identity.KindHuman)
	token := newToken(t, r)

	a := r.invited(token)
	rec := r.callback("fake", a, goodQuery(a))
	if rec.Code != http.StatusSeeOther || r.store.sessionCount() != 1 {
		t.Fatalf("callback: %d %s", rec.Code, rec.Body)
	}
	if !r.store.isOpen(token) {
		t.Error("a person who was already bound used up the invitation of someone else")
	}
}

func TestAnInvitationIsNotNeededToSignInAndAnUnboundSignInStillGetsTheValuesToBind(t *testing.T) {
	r := newRig(t)
	_, a := r.start("fake")
	if got := attemptCookieOf(t, a); got.Invitation != "" {
		t.Fatalf("a plain sign-in carries %q", got.Invitation)
	}
	rec := r.callback("fake", a, goodQuery(a))
	if rec.Code != http.StatusForbidden || bodyCode(t, rec)["error"] != "unknown_login" {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestAnInvitationLinkIsRefusedBeforeAnythingIsReadWhenTheRequestIsNotOurs(t *testing.T) {
	r := newRig(t)
	token := newToken(t, r)
	body := `{"token":"` + token + `"}`

	for name, tc := range map[string]struct {
		method  string
		body    string
		headers map[string]string
		code    int
	}{
		"a request from another site": {http.MethodPost, body, map[string]string{"Sec-Fetch-Site": "cross-site"}, http.StatusForbidden},
		"an Origin of another site":   {http.MethodPost, body, map[string]string{"Sec-Fetch-Site": "", "Origin": "https://evil.example.test"}, http.StatusForbidden},
		"a body that is not json":     {http.MethodPost, body, map[string]string{"Content-Type": "text/plain"}, http.StatusUnsupportedMediaType},
		"a field the type lacks":      {http.MethodPost, `{"token":"` + token + `","tenant":"x"}`, nil, http.StatusBadRequest},
		"data after the body":         {http.MethodPost, body + `{}`, nil, http.StatusBadRequest},
		"a body over the cap":         {http.MethodPost, `{"token":"` + strings.Repeat("a", 2048) + `"}`, nil, http.StatusBadRequest},
	} {
		t.Run(name, func(t *testing.T) {
			rec := r.invite("fake", tc.body, tc.headers)
			if rec.Code != tc.code {
				t.Fatalf("status %d (%s), want %d", rec.Code, rec.Body, tc.code)
			}
			// A request that is not one is invalid_request, which is not a failed login at a provider.
			if tc.code != http.StatusForbidden && bodyCode(t, rec)["error"] != "invalid_request" {
				t.Errorf("the code is %q", bodyCode(t, rec)["error"])
			}
			if cookieNamed(rec.Result().Cookies(), attemptCookieName) != nil {
				t.Error("a refused request set the attempt cookie")
			}
		})
	}
	if r.store.checks != 0 {
		t.Errorf("a refused request reached the store %d times", r.store.checks)
	}
	if rec := r.invite("nobody", body, nil); rec.Code != http.StatusNotFound {
		t.Errorf("an unknown provider is %d", rec.Code)
	}
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		req, _ := http.NewRequest(method, "/auth/invitation/fake", nil)
		rec := newRecorder(r, req)
		if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != http.MethodPost {
			t.Errorf("%s: %d %q", method, rec.Code, rec.Header().Get("Allow"))
		}
	}
}

func TestATokenThatIsNotOpenIsOneAnswerWhateverIsWrongWithIt(t *testing.T) {
	r := newRig(t)
	other, _, _ := identity.NewInvitationToken()
	for name, token := range map[string]string{
		"a token nobody made":     other,
		"an empty token":          "",
		"too short":               "abc",
		"not base64url":           strings.Repeat("!", 43),
		"padded":                  strings.Repeat("A", 42) + "=",
		"the right length, wrong": strings.Repeat("A", 43),
	} {
		t.Run(name, func(t *testing.T) {
			rec := r.invite("fake", `{"token":"`+token+`"}`, nil)
			if rec.Code != http.StatusForbidden || bodyCode(t, rec)["error"] != "unknown_invitation" {
				t.Fatalf("%d %s", rec.Code, rec.Body)
			}
			if cookieNamed(rec.Result().Cookies(), attemptCookieName) != nil {
				t.Error("an attempt cookie was set")
			}
		})
	}
}

func TestInvitationLinksAreRateLimitedInABucketOfTheirOwn(t *testing.T) {
	r := newRig(t, withLimits(1, 2))
	other, _, _ := identity.NewInvitationToken()
	var last *http.Response
	for range 3 {
		last = r.invite("fake", `{"token":"`+other+`"}`, nil).Result()
	}
	if last.StatusCode != http.StatusTooManyRequests || last.Header.Get("Retry-After") == "" {
		t.Fatalf("the third guess is %d", last.StatusCode)
	}
	// A guess spent nothing of the bucket of the callbacks, so a person can still sign in.
	r.store.bind(r.auth.Server.URL, subjectOne, identity.KindHuman)
	_, a := r.start("fake")
	if rec := r.callback("fake", a, goodQuery(a)); rec.Code != http.StatusSeeOther {
		t.Errorf("the callback is %d while invitation links are limited", rec.Code)
	}
}

func TestAnAttemptCookieWithATokenThatDoesNotReadEndsTheSignInAtOnce(t *testing.T) {
	r := newRig(t)
	token := newToken(t, r)
	a := r.invited(token)
	got := attemptCookieOf(t, a)
	got.Invitation = "not a token"
	a.cookie = got.cookie()

	rec := r.callback("fake", a, goodQuery(a))
	if rec.Code != http.StatusBadRequest || bodyCode(t, rec)["error"] != "invalid_login" || r.store.starts != 0 {
		t.Fatalf("%d %s, %d starts", rec.Code, rec.Body, r.store.starts)
	}
}

func TestAStoreThatFailsOnAnInvitationIsA500WithNothingStarted(t *testing.T) {
	r := newRig(t)
	token := newToken(t, r)
	r.store.err = http.ErrAbortHandler
	rec := r.invite("fake", `{"token":"`+token+`"}`, nil)
	if rec.Code != http.StatusInternalServerError || contains(r.logs.String(), token) {
		t.Fatalf("%d %s\n%s", rec.Code, rec.Body, r.logs)
	}
}
