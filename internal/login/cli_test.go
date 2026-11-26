package login

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ipsofacto-io/ipso-server/internal/identity"
)

func pkcePair() (verifier, challenge string) {
	verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk_extra_entropy"
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge
}

func TestCLILoopbackPKCEFlowAndLogout(t *testing.T) {
	r := newRig(t)
	r.store.bind(r.auth.Server.URL, subjectOne, identity.KindHuman)

	verifier, challenge := pkcePair()
	redirectURI := "http://127.0.0.1:54321/callback"
	cliState := "cli-random-state-12345"

	startQuery := url.Values{
		"redirect_uri":          {redirectURI},
		"state":                 {cliState},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	startReq := httptest.NewRequest(http.MethodGet, publicURL+"/auth/cli/start?"+startQuery.Encode(), nil)
	startRec := httptest.NewRecorder()
	r.handler.ServeHTTP(startRec, startReq)
	if startRec.Code != http.StatusSeeOther {
		t.Fatalf("cli start status = %d, want 303", startRec.Code)
	}
	attemptCookie := cookieNamed(startRec.Result().Cookies(), attemptCookieName)
	if attemptCookie == nil {
		t.Fatal("missing attempt cookie")
	}

	loc, err := url.Parse(startRec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	idpState := loc.Query().Get("state")
	r.mu.Lock()
	r.challenge = loc.Query().Get("code_challenge")
	r.lastNonce = loc.Query().Get("nonce")
	r.mu.Unlock()

	cbReq := httptest.NewRequest(http.MethodGet, publicURL+"/auth/callback/fake?state="+url.QueryEscape(idpState)+"&code=good-code", nil)
	cbReq.AddCookie(&http.Cookie{Name: attemptCookie.Name, Value: attemptCookie.Value})
	cbRec := httptest.NewRecorder()
	r.handler.ServeHTTP(cbRec, cbReq)
	if cbRec.Code != http.StatusSeeOther {
		t.Fatalf("callback status = %d, want 303", cbRec.Code)
	}
	cbLoc, err := url.Parse(cbRec.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if got := cbLoc.Scheme + "://" + cbLoc.Host + cbLoc.Path; got != redirectURI {
		t.Fatalf("redirect target = %q, want %q", got, redirectURI)
	}
	if cbLoc.Query().Get("state") != cliState {
		t.Fatalf("state = %q, want %q", cbLoc.Query().Get("state"), cliState)
	}
	cliCode := cbLoc.Query().Get("code")
	if cliCode == "" {
		t.Fatal("expected CLI authorization code")
	}

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {cliCode},
		"code_verifier": {verifier},
		"redirect_uri":  {redirectURI},
	}
	tokReq := httptest.NewRequest(http.MethodPost, publicURL+"/auth/cli/token", strings.NewReader(form.Encode()))
	tokReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokRec := httptest.NewRecorder()
	r.handler.ServeHTTP(tokRec, tokReq)
	if tokRec.Code != http.StatusOK {
		t.Fatalf("cli token status = %d: %s", tokRec.Code, tokRec.Body.String())
	}
	var tokResp struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresAt   string `json:"expires_at"`
	}
	if err := json.Unmarshal(tokRec.Body.Bytes(), &tokResp); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tokResp.AccessToken, identity.CLITokenPrefix) {
		t.Fatalf("unexpected token prefix: %q", tokResp.AccessToken)
	}

	replayReq := httptest.NewRequest(http.MethodPost, publicURL+"/auth/cli/token", strings.NewReader(form.Encode()))
	replayReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	replayRec := httptest.NewRecorder()
	r.handler.ServeHTTP(replayRec, replayReq)
	if replayRec.Code != http.StatusBadRequest {
		t.Fatalf("code replay status = %d, want 400", replayRec.Code)
	}

	gotTenant, principal, status := r.svc.LookupCLI(t.Context(), tokResp.AccessToken)
	if status != Found || gotTenant != tenant || principal != personID {
		t.Fatalf("LookupCLI = (%v, %v, %v), want (%v, %v, Found)", gotTenant, principal, status, tenant, personID)
	}

	logoutReq := httptest.NewRequest(http.MethodPost, publicURL+"/auth/cli/logout", nil)
	logoutReq.Header.Set("Authorization", "Bearer "+tokResp.AccessToken)
	logoutRec := httptest.NewRecorder()
	r.handler.ServeHTTP(logoutRec, logoutReq)
	if logoutRec.Code != http.StatusNoContent {
		t.Fatalf("cli logout status = %d, want 204", logoutRec.Code)
	}

	_, _, status = r.svc.LookupCLI(t.Context(), tokResp.AccessToken)
	if status != Unknown {
		t.Fatalf("LookupCLI after logout = %v, want Unknown", status)
	}
}

func TestCLIStartRejectsNonLoopbackRedirect(t *testing.T) {
	r := newRig(t)
	_, challenge := pkcePair()
	for _, bad := range []string{
		"https://evil.example.com/callback",
		"http://localhost:8080/callback",
		"http://127.0.0.1:8080/other",
		"http://127.0.0.1/callback",
	} {
		q := url.Values{
			"redirect_uri":          {bad},
			"state":                 {"state123"},
			"code_challenge":        {challenge},
			"code_challenge_method": {"S256"},
		}
		req := httptest.NewRequest(http.MethodGet, publicURL+"/auth/cli/start?"+q.Encode(), nil)
		rec := httptest.NewRecorder()
		r.handler.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("redirect_uri %q: status = %d, want 400", bad, rec.Code)
		}
	}
}
