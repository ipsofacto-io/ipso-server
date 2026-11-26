package login

import (
	"context"
	"encoding/json"
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
	tenantC = uuid.MustParse("00000000-0000-4000-8000-00000000000c")
	personA = uuid.MustParse("00000000-0000-4000-8000-0000000000a1")
	personB = uuid.MustParse("00000000-0000-4000-8000-0000000000b1")
	agentC  = uuid.MustParse("00000000-0000-4000-8000-0000000000c2")
)

func TestMultiTenantBrowserChoiceFlowHTMLAndJSON(t *testing.T) {
	r := newRig(t, withMultiTenant())
	r.store.setTenantName(tenantA, "Acme Europe")
	r.store.setTenantName(tenantB, "Beta Platform")
	r.store.setTenantName(tenantC, "Gamma Agent Org")
	r.store.bindIn(tenantA, personA, r.auth.Server.URL, subjectOne, identity.KindHuman)
	r.store.bindIn(tenantB, personB, r.auth.Server.URL, subjectOne, identity.KindHuman)
	// Agent login in Tenant C must not appear in human tenant options.
	r.store.bindIn(tenantC, agentC, r.auth.Server.URL, subjectOne, identity.KindAgent)

	// 1. HTML callback redirects 303 to /signin/tenant with __Host-ipso-choice and no session cookie.
	_, a := r.start("fake")
	htmlRec := r.callbackWith("fake", a, goodQuery(a), map[string]string{"Accept": "text/html"})
	if htmlRec.Code != http.StatusSeeOther || htmlRec.Header().Get("Location") != "/signin/tenant" {
		t.Fatalf("html callback = %d %q, want 303 /signin/tenant", htmlRec.Code, htmlRec.Header().Get("Location"))
	}
	if cookieNamed(htmlRec.Result().Cookies(), authn.SessionCookieName) != nil || r.store.sessionCount() != 0 {
		t.Fatal("pending choice callback created a session")
	}
	choiceCk := cookieNamed(htmlRec.Result().Cookies(), choiceCookieName)
	if choiceCk == nil || !choiceCk.HttpOnly || !choiceCk.Secure || choiceCk.SameSite != http.SameSiteLaxMode || choiceCk.Path != "/" || choiceCk.MaxAge != 300 {
		t.Fatalf("choice cookie = %+v, want HttpOnly Secure SameSite=Lax Path=/ MaxAge=300", choiceCk)
	}

	// 2. GET /auth/tenants returns only the verified subject's open human tenants.
	listReq := httptest.NewRequest(http.MethodGet, "/auth/tenants", nil)
	listReq.AddCookie(&http.Cookie{Name: choiceCk.Name, Value: choiceCk.Value})
	listRec := newRecorder(r, listReq)
	if listRec.Code != http.StatusOK {
		t.Fatalf("GET /auth/tenants = %d %s", listRec.Code, listRec.Body)
	}
	var listed tenantChoiceResponse
	if err := json.Unmarshal(listRec.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if listed.Flow != flowBrowser || len(listed.Tenants) != 2 ||
		listed.Tenants[0].ID != tenantA.String() || listed.Tenants[0].Name != "Acme Europe" ||
		listed.Tenants[1].ID != tenantB.String() || listed.Tenants[1].Name != "Beta Platform" {
		t.Fatalf("listed = %+v, want [Acme Europe, Beta Platform] browser flow", listed)
	}

	// 3. POST /auth/tenants opens a session strictly for Tenant B and clears __Host-ipso-choice.
	chooseReq := httptest.NewRequest(http.MethodPost, "/auth/tenants", strings.NewReader(`{"tenant_id":"`+tenantB.String()+`"}`))
	chooseReq.Header.Set("Content-Type", "application/json")
	chooseReq.Header.Set("Sec-Fetch-Site", "same-origin")
	chooseReq.AddCookie(&http.Cookie{Name: choiceCk.Name, Value: choiceCk.Value})
	chooseRec := newRecorder(r, chooseReq)
	if chooseRec.Code != http.StatusOK || bodyCode(t, chooseRec)["location"] != "/" {
		t.Fatalf("POST /auth/tenants = %d %s, want 200 location=/", chooseRec.Code, chooseRec.Body)
	}
	clearedChoice := cookieNamed(chooseRec.Result().Cookies(), choiceCookieName)
	if clearedChoice == nil || clearedChoice.MaxAge != -1 {
		t.Fatalf("expected cleared choice cookie, got %+v", clearedChoice)
	}
	sessionCk := cookieNamed(chooseRec.Result().Cookies(), authn.SessionCookieName)
	if sessionCk == nil {
		t.Fatal("missing session cookie after POST /auth/tenants")
	}
	probeReq := httptest.NewRequest(http.MethodGet, "/", nil)
	probeReq.AddCookie(&http.Cookie{Name: sessionCk.Name, Value: sessionCk.Value})
	rawTok, err := authn.SessionToken(probeReq)
	if err != nil {
		t.Fatal(err)
	}
	gotTenant, gotPrincipal, status := r.svc.Lookup(t.Context(), rawTok)
	if status != Found || gotTenant != tenantB || gotPrincipal != personB {
		t.Fatalf("Lookup = (%v, %v, %v), want (%v, %v, Found)", gotTenant, gotPrincipal, status, tenantB, personB)
	}

	// 4. Replaying the consumed choice cookie fails with 401 and creates no second session.
	replayReq := httptest.NewRequest(http.MethodPost, "/auth/tenants", strings.NewReader(`{"tenant_id":"`+tenantA.String()+`"}`))
	replayReq.Header.Set("Content-Type", "application/json")
	replayReq.Header.Set("Sec-Fetch-Site", "same-origin")
	replayReq.AddCookie(&http.Cookie{Name: choiceCk.Name, Value: choiceCk.Value})
	replayRec := newRecorder(r, replayReq)
	if replayRec.Code != http.StatusUnauthorized || bodyCode(t, replayRec)["error"] != codeInvalidLogin {
		t.Fatalf("replay = %d %s, want 401 invalid_login", replayRec.Code, replayRec.Body)
	}
	if r.store.sessionCount() != 1 {
		t.Fatalf("sessionCount = %d, want 1", r.store.sessionCount())
	}

	// 5. Non-HTML callback answers 200 JSON with the tenant list, flow, and __Host-ipso-choice cookie.
	_, a2 := r.start("fake", &http.Cookie{Name: sessionCk.Name, Value: sessionCk.Value})
	jsonRec := r.callback("fake", a2, goodQuery(a2))
	if jsonRec.Code != http.StatusOK {
		t.Fatalf("json callback = %d %s, want 200", jsonRec.Code, jsonRec.Body)
	}
	var cbBody tenantChoiceResponse
	if err := json.Unmarshal(jsonRec.Body.Bytes(), &cbBody); err != nil {
		t.Fatal(err)
	}
	if cbBody.Flow != flowBrowser || len(cbBody.Tenants) != 2 {
		t.Fatalf("json callback body = %+v", cbBody)
	}
	choiceCk2 := cookieNamed(jsonRec.Result().Cookies(), choiceCookieName)
	if choiceCk2 == nil {
		t.Fatal("json callback missing choice cookie")
	}

	// Picking Tenant A replaces the previous Tenant B session.
	chooseA := httptest.NewRequest(http.MethodPost, "/auth/tenants", strings.NewReader(`{"tenant_id":"`+tenantA.String()+`"}`))
	chooseA.Header.Set("Content-Type", "application/json")
	chooseA.Header.Set("Sec-Fetch-Site", "same-origin")
	chooseA.AddCookie(&http.Cookie{Name: choiceCk2.Name, Value: choiceCk2.Value})
	chooseARec := newRecorder(r, chooseA)
	if chooseARec.Code != http.StatusOK {
		t.Fatalf("choose Tenant A = %d %s", chooseARec.Code, chooseARec.Body)
	}
	if _, _, oldStatus := r.svc.Lookup(t.Context(), rawTok); oldStatus != Unknown {
		t.Fatalf("previous Tenant B session status = %v, want Unknown after replacement", oldStatus)
	}
}

func TestMultiTenantChoiceRefusesUnauthorizedExpiredCanceledAndSingleTenant(t *testing.T) {
	r := newRig(t, withMultiTenant())
	r.store.bindIn(tenantA, personA, r.auth.Server.URL, subjectOne, identity.KindHuman)
	r.store.bindIn(tenantB, personB, r.auth.Server.URL, subjectOne, identity.KindHuman)
	r.store.bindIn(tenantC, agentC, r.auth.Server.URL, subjectOne, identity.KindAgent)

	// Helper to get a fresh pending choice cookie.
	freshChoice := func() *http.Cookie {
		t.Helper()
		_, a := r.start("fake")
		rec := r.callbackWith("fake", a, goodQuery(a), map[string]string{"Accept": "text/html"})
		if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/signin/tenant" {
			t.Fatalf("freshChoice callback = %d %s", rec.Code, rec.Header().Get("Location"))
		}
		return cookieNamed(rec.Result().Cookies(), choiceCookieName)
	}

	// 1. Unauthorized tenant (agent-only Tenant C) consumes the choice and creates no session.
	ck := freshChoice()
	req := httptest.NewRequest(http.MethodPost, "/auth/tenants", strings.NewReader(`{"tenant_id":"`+tenantC.String()+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.AddCookie(&http.Cookie{Name: ck.Name, Value: ck.Value})
	rec := newRecorder(r, req)
	if rec.Code != http.StatusForbidden || bodyCode(t, rec)["error"] != codeForbidden {
		t.Fatalf("unauthorized tenant = %d %s, want 403 forbidden", rec.Code, rec.Body)
	}
	if cookieNamed(rec.Result().Cookies(), authn.SessionCookieName) != nil || r.store.sessionCount() != 0 {
		t.Fatal("unauthorized choice created a session")
	}
	// Choice was consumed on the failed attempt, so retrying Tenant A now fails with 401.
	retry := httptest.NewRequest(http.MethodPost, "/auth/tenants", strings.NewReader(`{"tenant_id":"`+tenantA.String()+`"}`))
	retry.Header.Set("Content-Type", "application/json")
	retry.Header.Set("Sec-Fetch-Site", "same-origin")
	retry.AddCookie(&http.Cookie{Name: ck.Name, Value: ck.Value})
	if retryRec := newRecorder(r, retry); retryRec.Code != http.StatusUnauthorized {
		t.Fatalf("retry after failed choice = %d %s, want 401", retryRec.Code, retryRec.Body)
	}

	// 2. Unbound random tenant also fails closed, consumes choice, and creates no session.
	ck = freshChoice()
	other := uuid.MustParse("00000000-0000-4000-8000-0000000000ff")
	req = httptest.NewRequest(http.MethodPost, "/auth/tenants", strings.NewReader(`{"tenant_id":"`+other.String()+`"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.AddCookie(&http.Cookie{Name: ck.Name, Value: ck.Value})
	if rec := newRecorder(r, req); rec.Code != http.StatusForbidden || r.store.sessionCount() != 0 {
		t.Fatalf("unbound tenant = %d %s, sessions=%d", rec.Code, rec.Body, r.store.sessionCount())
	}

	// 3. Cross-origin POST and DELETE are refused 403 before touching the pending choice.
	ck = freshChoice()
	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		cross := httptest.NewRequest(method, "/auth/tenants", strings.NewReader(`{"tenant_id":"`+tenantA.String()+`"}`))
		cross.Header.Set("Content-Type", "application/json")
		cross.Header.Set("Sec-Fetch-Site", "cross-site")
		cross.AddCookie(&http.Cookie{Name: ck.Name, Value: ck.Value})
		if crossRec := newRecorder(r, cross); crossRec.Code != http.StatusForbidden {
			t.Fatalf("cross-site %s = %d, want 403", method, crossRec.Code)
		}
	}

	// 4. Malformed payloads are refused 400/415 before touching the choice.
	badCT := httptest.NewRequest(http.MethodPost, "/auth/tenants", strings.NewReader(`{"tenant_id":"`+tenantA.String()+`"}`))
	badCT.Header.Set("Content-Type", "text/plain")
	badCT.Header.Set("Sec-Fetch-Site", "same-origin")
	if rec := newRecorder(r, badCT); rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("bad content-type = %d, want 415", rec.Code)
	}
	for _, body := range []string{`{}`, `{"tenant_id":"not-a-uuid"}`, `{"tenant_id":"00000000-0000-0000-0000-000000000000"}`, `{"tenant_id":"` + tenantA.String() + `","extra":1}`, `{"tenant_id":"` + tenantA.String() + `"} trailing`} {
		bad := httptest.NewRequest(http.MethodPost, "/auth/tenants", strings.NewReader(body))
		bad.Header.Set("Content-Type", "application/json")
		bad.Header.Set("Sec-Fetch-Site", "same-origin")
		if rec := newRecorder(r, bad); rec.Code != http.StatusBadRequest {
			t.Fatalf("body %q = %d, want 400", body, rec.Code)
		}
	}

	// 5. DELETE /auth/tenants cancels the choice, clears the cookie, and leaves no session.
	delReq := httptest.NewRequest(http.MethodDelete, "/auth/tenants", nil)
	delReq.Header.Set("Sec-Fetch-Site", "same-origin")
	delReq.AddCookie(&http.Cookie{Name: ck.Name, Value: ck.Value})
	delRec := newRecorder(r, delReq)
	if delRec.Code != http.StatusNoContent {
		t.Fatalf("DELETE /auth/tenants = %d %s, want 204", delRec.Code, delRec.Body)
	}
	if cleared := cookieNamed(delRec.Result().Cookies(), choiceCookieName); cleared == nil || cleared.MaxAge != -1 {
		t.Fatalf("DELETE did not clear choice cookie: %+v", cleared)
	}
	getAfterDel := httptest.NewRequest(http.MethodGet, "/auth/tenants", nil)
	getAfterDel.AddCookie(&http.Cookie{Name: ck.Name, Value: ck.Value})
	if rec := newRecorder(r, getAfterDel); rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET after DELETE = %d, want 401", rec.Code)
	}

	// 6. Abandoned choice expires after 5 minutes and creates no session.
	ck = freshChoice()
	r.now = r.now.Add(identity.LoginChoiceTTL + time.Second)
	expReq := httptest.NewRequest(http.MethodGet, "/auth/tenants", nil)
	expReq.AddCookie(&http.Cookie{Name: ck.Name, Value: ck.Value})
	if rec := newRecorder(r, expReq); rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET expired choice = %d, want 401", rec.Code)
	}
	if r.store.sessionCount() != 0 {
		t.Fatalf("abandoned choice created %d sessions", r.store.sessionCount())
	}

	// 7. Single-tenant mode returns 404 for /auth/tenants.
	single := newRig(t)
	if rec := newRecorder(single, httptest.NewRequest(http.MethodGet, "/auth/tenants", nil)); rec.Code != http.StatusNotFound {
		t.Fatalf("single-tenant GET /auth/tenants = %d, want 404", rec.Code)
	}

	// 8. Rate limit on /auth/tenants answers 429 with Retry-After.
	limited := newRig(t, withMultiTenant(), withLimits(0.001, 1))
	_ = newRecorder(limited, httptest.NewRequest(http.MethodGet, "/auth/tenants", nil))
	rlRec := newRecorder(limited, httptest.NewRequest(http.MethodGet, "/auth/tenants", nil))
	if rlRec.Code != http.StatusTooManyRequests || rlRec.Header().Get("Retry-After") == "" {
		t.Fatalf("rate-limited GET /auth/tenants = %d Retry-After=%q, want 429", rlRec.Code, rlRec.Header().Get("Retry-After"))
	}
}

func TestMultiTenantCLIChoiceFlow(t *testing.T) {
	r := newRig(t, withMultiTenant())
	r.store.setTenantName(tenantA, "Acme Europe")
	r.store.setTenantName(tenantB, "Beta Platform")
	r.store.bindIn(tenantA, personA, r.auth.Server.URL, subjectOne, identity.KindHuman)
	r.store.bindIn(tenantB, personB, r.auth.Server.URL, subjectOne, identity.KindHuman)

	startCLI := func(accept string) (*httptest.ResponseRecorder, string, string) {
		t.Helper()
		verifier, challenge := pkcePair()
		redirectURI := "http://127.0.0.1:54321/callback"
		q := url.Values{
			"redirect_uri":          {redirectURI},
			"state":                 {"cli-state-choice"},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
		}
		startRec := newRecorder(r, httptest.NewRequest(http.MethodGet, publicURL+"/auth/cli/start?"+q.Encode(), nil))
		attemptCk := cookieNamed(startRec.Result().Cookies(), attemptCookieName)
		loc, _ := url.Parse(startRec.Header().Get("Location"))
		r.mu.Lock()
		r.challenge = loc.Query().Get("code_challenge")
		r.lastNonce = loc.Query().Get("nonce")
		r.mu.Unlock()

		cbReq := httptest.NewRequest(http.MethodGet, publicURL+"/auth/callback/fake?state="+url.QueryEscape(loc.Query().Get("state"))+"&code=good-code", nil)
		if accept != "" {
			cbReq.Header.Set("Accept", accept)
		}
		cbReq.AddCookie(&http.Cookie{Name: attemptCk.Name, Value: attemptCk.Value})
		return newRecorder(r, cbReq), verifier, redirectURI
	}

	// HTML CLI callback redirects 303 to /signin/tenant with __Host-ipso-choice and mints no CLI code yet.
	cbRec, verifier, redirectURI := startCLI("text/html")
	if cbRec.Code != http.StatusSeeOther || cbRec.Header().Get("Location") != "/signin/tenant" {
		t.Fatalf("cli html callback = %d %q, want 303 /signin/tenant", cbRec.Code, cbRec.Header().Get("Location"))
	}
	choiceCk := cookieNamed(cbRec.Result().Cookies(), choiceCookieName)
	if choiceCk == nil {
		t.Fatal("cli callback missing choice cookie")
	}

	// GET /auth/tenants reports flow="cli".
	getReq := httptest.NewRequest(http.MethodGet, "/auth/tenants", nil)
	getReq.AddCookie(&http.Cookie{Name: choiceCk.Name, Value: choiceCk.Value})
	getRec := newRecorder(r, getReq)
	var listed tenantChoiceResponse
	if err := json.Unmarshal(getRec.Body.Bytes(), &listed); err != nil {
		t.Fatal(err)
	}
	if listed.Flow != flowCLI || len(listed.Tenants) != 2 {
		t.Fatalf("GET /auth/tenants = %+v, want cli flow with 2 tenants", listed)
	}

	// POST /auth/tenants for Tenant A returns the loopback callback URL with a one-time code.
	chooseReq := httptest.NewRequest(http.MethodPost, "/auth/tenants", strings.NewReader(`{"tenant_id":"`+tenantA.String()+`"}`))
	chooseReq.Header.Set("Content-Type", "application/json")
	chooseReq.Header.Set("Sec-Fetch-Site", "same-origin")
	chooseReq.AddCookie(&http.Cookie{Name: choiceCk.Name, Value: choiceCk.Value})
	chooseRec := newRecorder(r, chooseReq)
	if chooseRec.Code != http.StatusOK {
		t.Fatalf("POST /auth/tenants cli = %d %s", chooseRec.Code, chooseRec.Body)
	}
	loc, err := url.Parse(bodyCode(t, chooseRec)["location"])
	if err != nil || loc.Scheme != "http" || loc.Host != "127.0.0.1:54321" || loc.Path != "/callback" || loc.Query().Get("state") != "cli-state-choice" || loc.Query().Get("code") == "" {
		t.Fatalf("cli location = %q (%v)", bodyCode(t, chooseRec)["location"], err)
	}
	if cookieNamed(chooseRec.Result().Cookies(), authn.SessionCookieName) != nil {
		t.Fatal("CLI tenant choice must not set a browser session cookie")
	}

	// Exchange the loopback code for an ipsocli_ token scoped strictly to Tenant A.
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {loc.Query().Get("code")},
		"code_verifier": {verifier},
		"redirect_uri":  {redirectURI},
	}
	tokReq := httptest.NewRequest(http.MethodPost, "/auth/cli/token", strings.NewReader(form.Encode()))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokRec := newRecorder(r, tokReq)
	if tokRec.Code != http.StatusOK {
		t.Fatalf("POST /auth/cli/token = %d %s", tokRec.Code, tokRec.Body)
	}
	var tokBody struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(tokRec.Body.Bytes(), &tokBody); err != nil {
		t.Fatal(err)
	}
	gotTenant, gotPrincipal, status := r.svc.LookupCLI(t.Context(), tokBody.AccessToken)
	if status != Found || gotTenant != tenantA || gotPrincipal != personA {
		t.Fatalf("LookupCLI = (%v, %v, %v), want (%v, %v, Found)", gotTenant, gotPrincipal, status, tenantA, personA)
	}

	// JSON CLI callback returns 200 with flow="cli" and choice cookie; unauthorized tenant fails 403 and writes no CLI session.
	jsonCB, _, _ := startCLI("")
	if jsonCB.Code != http.StatusOK {
		t.Fatalf("cli json callback = %d %s, want 200", jsonCB.Code, jsonCB.Body)
	}
	jsonChoiceCk := cookieNamed(jsonCB.Result().Cookies(), choiceCookieName)
	badCLI := httptest.NewRequest(http.MethodPost, "/auth/tenants", strings.NewReader(`{"tenant_id":"`+tenantC.String()+`"}`))
	badCLI.Header.Set("Content-Type", "application/json")
	badCLI.Header.Set("Sec-Fetch-Site", "same-origin")
	badCLI.AddCookie(&http.Cookie{Name: jsonChoiceCk.Name, Value: jsonChoiceCk.Value})
	if badRec := newRecorder(r, badCLI); badRec.Code != http.StatusForbidden {
		t.Fatalf("unauthorized CLI tenant = %d %s, want 403", badRec.Code, badRec.Body)
	}
	if r.store.cliSessionCount() != 1 {
		t.Fatalf("cliSessionCount = %d, want 1", r.store.cliSessionCount())
	}
}

func TestMultiTenantSAMLChoiceFlow(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	store := newFakeStore(func() time.Time { return now })
	const samlIssuer = "https://idp.example.test/saml"
	store.bindIn(tenantA, personA, samlIssuer, "saml-person-1", identity.KindHuman)
	store.bindIn(tenantB, personB, samlIssuer, "saml-person-1", identity.KindHuman)

	svc, err := New(t.Context(), Options{
		store:       store,
		MultiTenant: true,
		PublicURL:   publicURL,
		Providers:   []ProviderConfig{{ID: "gh", Kind: KindGitHub, ClientID: "cid", ClientSecretEnv: "IPSO_LOGIN_GH"}},
		Secret:      func(string) string { return "secret" },
		Now:         func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	svc.providers["saml"] = &fakePostedProvider{
		issuer:  samlIssuer,
		subject: "saml-person-1",
	}
	handler := svc.Handler()

	// Start SAML sign-in.
	startRec := httptest.NewRecorder()
	handler.ServeHTTP(startRec, httptest.NewRequest(http.MethodGet, "/auth/login/saml", nil))
	if startRec.Code != http.StatusSeeOther {
		t.Fatalf("saml start = %d", startRec.Code)
	}
	attemptCk := cookieNamed(startRec.Result().Cookies(), attemptCookieName)
	if attemptCk == nil || attemptCk.SameSite != http.SameSiteNoneMode {
		t.Fatalf("saml attempt cookie = %+v, want SameSite=None", attemptCk)
	}

	// Posted SAML callback with HTML Accept redirects 303 to /signin/tenant and sets SameSite=Lax __Host-ipso-choice.
	cbReq := httptest.NewRequest(http.MethodPost, "/auth/callback/saml", strings.NewReader("SAMLResponse=ok"))
	cbReq.Header.Set("Accept", "text/html")
	cbReq.AddCookie(&http.Cookie{Name: attemptCk.Name, Value: attemptCk.Value})
	cbRec := httptest.NewRecorder()
	handler.ServeHTTP(cbRec, cbReq)
	if cbRec.Code != http.StatusSeeOther || cbRec.Header().Get("Location") != "/signin/tenant" {
		t.Fatalf("saml callback = %d %q, want 303 /signin/tenant", cbRec.Code, cbRec.Header().Get("Location"))
	}
	choiceCk := cookieNamed(cbRec.Result().Cookies(), choiceCookieName)
	if choiceCk == nil || choiceCk.SameSite != http.SameSiteLaxMode {
		t.Fatalf("saml choice cookie = %+v, want SameSite=Lax", choiceCk)
	}
	if cookieNamed(cbRec.Result().Cookies(), authn.SessionCookieName) != nil {
		t.Fatal("saml choice callback must not set session cookie")
	}

	// Pick Tenant B.
	chooseReq := httptest.NewRequest(http.MethodPost, "/auth/tenants", strings.NewReader(`{"tenant_id":"`+tenantB.String()+`"}`))
	chooseReq.Header.Set("Content-Type", "application/json")
	chooseReq.Header.Set("Sec-Fetch-Site", "same-origin")
	chooseReq.AddCookie(&http.Cookie{Name: choiceCk.Name, Value: choiceCk.Value})
	chooseRec := httptest.NewRecorder()
	handler.ServeHTTP(chooseRec, chooseReq)
	if chooseRec.Code != http.StatusOK || cookieNamed(chooseRec.Result().Cookies(), authn.SessionCookieName) == nil {
		t.Fatalf("saml choose tenant = %d %s", chooseRec.Code, chooseRec.Body)
	}
}

type fakePostedProvider struct {
	issuer  string
	subject string
}

func (f *fakePostedProvider) authorizeURL(_, _, _, _ string) string                { return "" }
func (f *fakePostedProvider) issuerParameter() (string, bool)                      { return "", false }
func (f *fakePostedProvider) complete(context.Context, string, string, string, string) (subject, error) {
	return subject{}, nil
}
func (f *fakePostedProvider) redirect(id string) string { return "https://idp.example.test/sso?id=" + id }
func (f *fakePostedProvider) completePOST(context.Context, []byte, string) (subject, error) {
	return subject{issuer: f.issuer, subject: f.subject}, nil
}
func (f *fakePostedProvider) metadata() []byte { return []byte("<EntityDescriptor/>") }
func (f *fakePostedProvider) idpIssuer() string { return f.issuer }

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

	// Multi-tenant choice POST /auth/tenants tags the chosen tenantA.
	r.store.bindIn(tenantA, personA, r.auth.Server.URL, subjectOne, identity.KindHuman)
	startReq2 := httptest.NewRequest(http.MethodGet, "/auth/login/fake", nil)
	startRec2 := httptest.NewRecorder()
	handler.ServeHTTP(startRec2, startReq2)
	attempt2 := cookieNamed(startRec2.Result().Cookies(), attemptCookieName)
	loc2, _ := url.Parse(startRec2.Header().Get("Location"))
	r.mu.Lock()
	r.challenge = loc2.Query().Get("code_challenge")
	r.lastNonce = loc2.Query().Get("nonce")
	r.mu.Unlock()
	cbReq2 := httptest.NewRequest(http.MethodGet, "/auth/callback/fake?state="+url.QueryEscape(loc2.Query().Get("state"))+"&code=good-code", nil)
	cbReq2.AddCookie(&http.Cookie{Name: attempt2.Name, Value: attempt2.Value})
	cbRec2 := httptest.NewRecorder()
	handler.ServeHTTP(cbRec2, cbReq2)
	choiceCk := cookieNamed(cbRec2.Result().Cookies(), choiceCookieName)
	chooseReq := httptest.NewRequest(http.MethodPost, "/auth/tenants", strings.NewReader(`{"tenant_id":"`+tenantA.String()+`"}`))
	chooseReq.Header.Set("Content-Type", "application/json")
	chooseReq.Header.Set("Sec-Fetch-Site", "same-origin")
	chooseReq.AddCookie(&http.Cookie{Name: choiceCk.Name, Value: choiceCk.Value})
	chooseRec := httptest.NewRecorder()
	handler.ServeHTTP(chooseRec, chooseReq)
	if chooseRec.Code != http.StatusOK {
		t.Fatalf("choose tenant = %d %s", chooseRec.Code, chooseRec.Body)
	}

	var callbackTenant, logoutTenant, inviteTenant, choiceTenant string
	for _, s := range rec.Spans() {
		attrs := telemetrytest.Attrs(s.Attributes)
		switch s.Name {
		case "GET /auth/callback/{provider}":
			if attrs["ipso.tenant.id"] != "" {
				callbackTenant = attrs["ipso.tenant.id"]
			}
		case "POST /auth/logout":
			logoutTenant = attrs["ipso.tenant.id"]
		case "POST /auth/invitation/{provider}":
			inviteTenant = attrs["ipso.tenant.id"]
		case "POST /auth/tenants":
			choiceTenant = attrs["ipso.tenant.id"]
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
	if choiceTenant != tenantA.String() {
		t.Errorf("choice span tenant = %q, want %s", choiceTenant, tenantA)
	}
}
