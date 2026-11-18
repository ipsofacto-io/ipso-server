package login

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ipsofacto-io/ipso-server/eehooks"
	"github.com/ipsofacto-io/ipso-server/internal/identity"
)

type fakeBrowser struct {
	issuer, subject string
	requestID       string
}

func (f *fakeBrowser) RedirectURL(requestID string) string {
	f.requestID = requestID
	return "https://idp.example.test/sso?id=" + requestID
}

func (f *fakeBrowser) Subject(context.Context, []byte, string) (string, string, error) {
	return f.issuer, f.subject, nil
}

func (f *fakeBrowser) Metadata() []byte { return []byte("<EntityDescriptor/>") }

func (f *fakeBrowser) Issuer() string { return f.issuer }

type postingBrowser struct{ *fakeBrowser }

func (p postingBrowser) Subject(_ context.Context, body []byte, requestID string) (string, string, error) {
	if p.fakeBrowser == nil || requestID == "" || !strings.Contains(string(body), requestID) {
		return "", "", errors.New("saml")
	}
	return p.issuer, p.subject, nil
}

type quietBrowser struct{}

func (quietBrowser) RedirectURL(string) string { return "" }
func (quietBrowser) Subject(context.Context, []byte, string) (string, string, error) {
	return "", "", errors.New("saml")
}
func (quietBrowser) Metadata() []byte { return []byte("<EntityDescriptor/>") }
func (quietBrowser) Issuer() string   { return "https://idp.example.test/meta" }

func TestPostedCallbackOpensASession(t *testing.T) {
	browser := &fakeBrowser{issuer: "https://idp.example.test/meta", subject: subjectOne}
	eehooks.ResetForTest()
	t.Cleanup(eehooks.ResetForTest)
	eehooks.SetGate(allowSAML{})
	eehooks.RegisterKind("saml", func(context.Context, eehooks.KindConfig) (eehooks.BrowserLogin, error) {
		return postingBrowser{browser}, nil
	})

	store := newFakeStore(func() time.Time { return time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC) })
	store.bind(browser.issuer, browser.subject, identity.KindHuman)
	svc, err := New(t.Context(), Options{
		store:     store,
		Tenant:    tenant,
		PublicURL: publicURL,
		Providers: []ProviderConfig{{
			ID: "okta", Kind: "saml", MetadataURL: "https://idp.example.test/metadata", ClientID: publicURL + "/auth/saml/okta",
		}},
		Log: newLogger(io.Discard),
		Now: func() time.Time { return time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatal(err)
	}
	handler := svc.Handler()

	start := httptest.NewRequest(http.MethodGet, "/auth/login/okta", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, start)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("start: %d %s", rec.Code, rec.Body.String())
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %d", len(cookies))
	}
	cookie := cookies[0]
	if cookie.Name != attemptCookieName || cookie.SameSite != http.SameSiteNoneMode || !cookie.Secure || !cookie.HttpOnly {
		t.Fatalf("attempt cookie = %+v", cookie)
	}
	if browser.requestID == "" || !strings.HasPrefix(browser.requestID, "_") {
		t.Fatalf("request id %q", browser.requestID)
	}

	post := httptest.NewRequest(http.MethodPost, "/auth/callback/okta", strings.NewReader("SAMLResponse=abc&RelayState="+browser.requestID))
	post.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	post.AddCookie(cookie)
	done := httptest.NewRecorder()
	handler.ServeHTTP(done, post)
	if done.Code != http.StatusSeeOther || done.Header().Get("Location") != "/" {
		t.Fatalf("callback: %d %s", done.Code, done.Body.String())
	}
	if store.starts != 1 {
		t.Fatalf("sessions started = %d", store.starts)
	}

	refused := httptest.NewRequest(http.MethodPost, "/auth/callback/okta", strings.NewReader("SAMLResponse=nope"))
	refused.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	refused.Header.Set("Accept", "text/html")
	refused.AddCookie(cookie)
	page := httptest.NewRecorder()
	handler.ServeHTTP(page, refused)
	if page.Code != http.StatusSeeOther || !strings.HasPrefix(page.Header().Get("Location"), "/signin#") {
		t.Fatalf("posted refusal: %d %s", page.Code, page.Header().Get("Location"))
	}

	meta := httptest.NewRecorder()
	handler.ServeHTTP(meta, httptest.NewRequest(http.MethodGet, "/auth/saml/okta/metadata", nil))
	if meta.Code != http.StatusOK || meta.Body.String() != "<EntityDescriptor/>" {
		t.Fatalf("metadata: %d %s", meta.Code, meta.Body.String())
	}
}

func TestAFailedSAMLRedirectIsAnError(t *testing.T) {
	eehooks.ResetForTest()
	t.Cleanup(eehooks.ResetForTest)
	eehooks.SetGate(allowSAML{})
	eehooks.RegisterKind("saml", func(context.Context, eehooks.KindConfig) (eehooks.BrowserLogin, error) {
		return quietBrowser{}, nil
	})
	svc, err := New(t.Context(), Options{
		store:     newFakeStore(time.Now),
		Tenant:    tenant,
		PublicURL: publicURL,
		Providers: []ProviderConfig{{
			ID: "okta", Kind: "saml", MetadataURL: "https://idp.example.test/metadata", ClientID: publicURL + "/auth/saml/okta",
		}},
		Log: newLogger(io.Discard),
		Now: time.Now,
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	svc.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/login/okta", nil))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("start: %d %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Location") != "" {
		t.Fatalf("location %q", rec.Header().Get("Location"))
	}
}

func TestADeniedKeyLeavesSAMLUnmounted(t *testing.T) {
	eehooks.ResetForTest()
	t.Cleanup(eehooks.ResetForTest)
	eehooks.RegisterKind("saml", func(context.Context, eehooks.KindConfig) (eehooks.BrowserLogin, error) {
		return postingBrowser{}, nil
	})
	svc, err := New(t.Context(), Options{
		store:     newFakeStore(time.Now),
		Tenant:    tenant,
		PublicURL: publicURL,
		Providers: []ProviderConfig{{
			ID: "okta", Kind: "saml", MetadataURL: "https://idp.example.test/metadata", ClientID: publicURL + "/auth/saml/okta",
		}},
		Log: newLogger(io.Discard),
	})
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	svc.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth/login/okta", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("a denied key mounted the provider: %d", rec.Code)
	}
	if _, ok := svc.EnterpriseIssuer(); ok {
		t.Fatal("a denied key reported an issuer")
	}
}

type allowSAML struct{}

func (allowSAML) Allow(feature string) bool { return feature == eehooks.FeatureSAML }
