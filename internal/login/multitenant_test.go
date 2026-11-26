package login

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/authn"
	"github.com/ipsofacto-io/ipso-server/internal/identity"
	"github.com/ipsofacto-io/ipso-server/internal/telemetry"
	"github.com/ipsofacto-io/ipso-server/internal/telemetry/telemetrytest"
)

var (
	tenantA = uuid.MustParse("00000000-0000-4000-8000-00000000000a")
	tenantB = uuid.MustParse("00000000-0000-4000-8000-00000000000b")
	personA = uuid.MustParse("00000000-0000-4000-8000-0000000000a1")
	personB = uuid.MustParse("00000000-0000-4000-8000-0000000000b1")
)

func TestMultiTenantAmbiguousSubjectFailsClosed(t *testing.T) {
	r := newRig(t, withMultiTenant())
	r.store.bindIn(tenantA, personA, r.auth.Server.URL, subjectOne, identity.KindHuman)
	r.store.bindIn(tenantB, personB, r.auth.Server.URL, subjectOne, identity.KindHuman)

	// JSON callback fails closed with 403 forbidden and creates no session.
	_, a := r.start("fake")
	rec := r.callback("fake", a, goodQuery(a))
	if rec.Code != http.StatusForbidden || bodyCode(t, rec)["error"] != "forbidden" {
		t.Fatalf("json callback = %d %s, want 403 forbidden", rec.Code, rec.Body)
	}
	if cookieNamed(rec.Result().Cookies(), authn.SessionCookieName) != nil || r.store.sessionCount() != 0 {
		t.Fatal("ambiguous subject started a session")
	}

	// Browser HTML callback redirects to /signin#code=forbidden.
	_, a = r.start("fake")
	htmlRec := r.callbackWith("fake", a, goodQuery(a), map[string]string{"Accept": "text/html"})
	got := refusalFragment(t, htmlRec)
	if got.Get("code") != "forbidden" || len(got) != 1 {
		t.Fatalf("html callback fragment = %v, want code=forbidden", got)
	}

	// CLI loopback callback also fails closed with 403 forbidden and writes no CLI session.
	_, challenge := pkcePair()
	q := url.Values{
		"redirect_uri":          {"http://127.0.0.1:54321/callback"},
		"state":                 {"cli-state-ambiguous"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	startReq := httptest.NewRequest(http.MethodGet, publicURL+"/auth/cli/start?"+q.Encode(), nil)
	startRec := httptest.NewRecorder()
	r.handler.ServeHTTP(startRec, startReq)
	attemptCookie := cookieNamed(startRec.Result().Cookies(), attemptCookieName)
	loc, _ := url.Parse(startRec.Header().Get("Location"))
	r.mu.Lock()
	r.challenge = loc.Query().Get("code_challenge")
	r.lastNonce = loc.Query().Get("nonce")
	r.mu.Unlock()

	cbReq := httptest.NewRequest(http.MethodGet, publicURL+"/auth/callback/fake?state="+url.QueryEscape(loc.Query().Get("state"))+"&code=good-code", nil)
	cbReq.AddCookie(&http.Cookie{Name: attemptCookie.Name, Value: attemptCookie.Value})
	cbRec := httptest.NewRecorder()
	r.handler.ServeHTTP(cbRec, cbReq)
	cbLoc, err := url.Parse(cbRec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if cbRec.Code != http.StatusSeeOther || cbLoc.Query().Get("error") != "forbidden" || cbLoc.Query().Get("code") != "" {
		t.Fatalf("cli callback = %d %s, want 303 error=forbidden with no code", cbRec.Code, cbRec.Header().Get("Location"))
	}
}

func TestMultiTenantInvitationResolvesTargetTenantWhenSubjectAlreadyBoundElsewhere(t *testing.T) {
	r := newRig(t, withMultiTenant())
	r.store.bindIn(tenantA, personA, r.auth.Server.URL, subjectOne, identity.KindHuman)

	token, _, err := identity.NewInvitationToken()
	if err != nil {
		t.Fatal(err)
	}
	r.store.openIn(tenantB, token)

	a := r.invited(token)
	rec := r.callback("fake", a, goodQuery(a))
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/" {
		t.Fatalf("invited callback = %d %s", rec.Code, rec.Body)
	}
	session := cookieNamed(rec.Result().Cookies(), authn.SessionCookieName)
	if session == nil {
		t.Fatal("missing session cookie")
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: session.Name, Value: session.Value})
	rawTok, err := authn.SessionToken(req)
	if err != nil {
		t.Fatal(err)
	}
	gotTenant, _, status := r.svc.Lookup(t.Context(), rawTok)
	if status != Found || gotTenant != tenantB {
		t.Fatalf("Lookup = (%v, %v), want (%v, Found)", gotTenant, status, tenantB)
	}
}

func TestSessionCachePerTenantEvictionCapIsolatesTenants(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	cache := newSessionCache(time.Minute, 10, 4)

	// Tenant B inserts 2 hot entries.
	hashOf := func(s string) []byte { return authn.SessionHash([]byte(s)) }
	cache.put(uuid.Nil, hashOf("b1"), tenantB, personB, now.Add(time.Minute), now)
	cache.put(uuid.Nil, hashOf("b2"), tenantB, personB, now.Add(time.Minute), now)

	// Tenant A floods 20 entries. Per-tenant cap (4) must evict only Tenant A's own entries,
	// leaving Tenant B's 2 entries intact.
	for i := range 20 {
		cache.put(uuid.Nil, hashOf(fmt.Sprintf("a-%d", i)), tenantA, personA, now.Add(time.Duration(i+1)*time.Second), now)
	}
	if gotTenant, gotPrincipal, ok := cache.get(uuid.Nil, hashOf("b1"), now); !ok || gotTenant != tenantB || gotPrincipal != personB {
		t.Fatalf("tenant A flood evicted tenant B entry b1: %v %v %v", gotTenant, gotPrincipal, ok)
	}
	if gotTenant, gotPrincipal, ok := cache.get(uuid.Nil, hashOf("b2"), now); !ok || gotTenant != tenantB || gotPrincipal != personB {
		t.Fatalf("tenant A flood evicted tenant B entry b2: %v %v %v", gotTenant, gotPrincipal, ok)
	}
	if got := len(cache.byTenant[tenantA]); got > 4 {
		t.Fatalf("tenant A holds %d entries, want at most 4", got)
	}
}

func TestMultiTenantLoginSetsTelemetryTenant(t *testing.T) {
	r := newRig(t, withMultiTenant())
	r.store.bindIn(tenantB, personB, r.auth.Server.URL, subjectOne, identity.KindHuman)

	tel, rec := telemetrytest.New(t)
	handler := tel.Handler(uuid.Nil, telemetry.Routed(r.handler))

	// Browser sign-in callback tags tenantB.
	startReq := httptest.NewRequest(http.MethodGet, "/auth/login/fake", nil)
	startRec := httptest.NewRecorder()
	handler.ServeHTTP(startRec, startReq)
	attemptCookie := cookieNamed(startRec.Result().Cookies(), attemptCookieName)
	loc, _ := url.Parse(startRec.Header().Get("Location"))
	r.mu.Lock()
	r.challenge = loc.Query().Get("code_challenge")
	r.lastNonce = loc.Query().Get("nonce")
	r.mu.Unlock()

	cbReq := httptest.NewRequest(http.MethodGet, "/auth/callback/fake?state="+url.QueryEscape(loc.Query().Get("state"))+"&code=good-code", nil)
	cbReq.AddCookie(&http.Cookie{Name: attemptCookie.Name, Value: attemptCookie.Value})
	cbRec := httptest.NewRecorder()
	handler.ServeHTTP(cbRec, cbReq)
	if cbRec.Code != http.StatusSeeOther {
		t.Fatalf("callback = %d %s", cbRec.Code, cbRec.Body)
	}
	sessionCookie := cookieNamed(cbRec.Result().Cookies(), authn.SessionCookieName)

	// Logout tags tenantB.
	logoutReq := httptest.NewRequest(http.MethodPost, "/auth/logout", nil)
	logoutReq.Header.Set("Sec-Fetch-Site", "same-origin")
	logoutReq.AddCookie(&http.Cookie{Name: sessionCookie.Name, Value: sessionCookie.Value})
	logoutRec := httptest.NewRecorder()
	handler.ServeHTTP(logoutRec, logoutReq)
	if logoutRec.Code != http.StatusNoContent {
		t.Fatalf("logout = %d", logoutRec.Code)
	}

	// Invitation check tags tenantA.
	invTok, _, _ := identity.NewInvitationToken()
	r.store.openIn(tenantA, invTok)
	invReq := httptest.NewRequest(http.MethodPost, "/auth/invitation/fake", strings.NewReader(`{"token":"`+invTok+`"}`))
	invReq.Header.Set("Content-Type", "application/json")
	invReq.Header.Set("Sec-Fetch-Site", "same-origin")
	invRec := httptest.NewRecorder()
	handler.ServeHTTP(invRec, invReq)
	if invRec.Code != http.StatusOK {
		t.Fatalf("invite = %d %s", invRec.Code, invRec.Body)
	}

	var callbackTenant, logoutTenant, inviteTenant string
	for _, s := range rec.Spans() {
		attrs := telemetrytest.Attrs(s.Attributes)
		switch s.Name {
		case "GET /auth/callback/{provider}":
			callbackTenant = attrs["ipso.tenant.id"]
		case "POST /auth/logout":
			logoutTenant = attrs["ipso.tenant.id"]
		case "POST /auth/invitation/{provider}":
			inviteTenant = attrs["ipso.tenant.id"]
		}
	}
	if callbackTenant != tenantB.String() {
		t.Errorf("callback span tenant = %q, want %s", callbackTenant, tenantB)
	}
	if logoutTenant != tenantB.String() {
		t.Errorf("logout span tenant = %q, want %s", logoutTenant, tenantB)
	}
	if inviteTenant != tenantA.String() {
		t.Errorf("invite span tenant = %q, want %s", inviteTenant, tenantA)
	}
}
