//go:build compose

package compose

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"
)

// noFollow keeps a redirect for the test to read, as a browser reads one before it follows it.
func noFollow(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

// plain reaches the front over http and follows nothing: the sign-in redirects to Dex, a name the host
// does not resolve, and the callback redirects to a page the test does not want.
var plain = &http.Client{Timeout: 15 * time.Second, CheckRedirect: noFollow}

// dexBrowser reaches Dex the way a browser on the host does once `dex` is in its hosts file: the name
// dex is dialed at the published loopback port, and the certificate is checked for the name dex against
// the throwaway CA of the stack.
func dexBrowser(t *testing.T) *http.Client {
	t.Helper()
	pem, err := os.ReadFile(setting(t, "IPSO_SMOKE_CA", ""))
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("IPSO_SMOKE_CA holds no certificate")
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	return &http.Client{
		Timeout:       15 * time.Second,
		CheckRedirect: noFollow,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if addr == "dex:5556" {
					addr = "127.0.0.1:5556"
				}
				return dialer.DialContext(ctx, network, addr)
			},
		},
	}
}

type answer struct {
	status int
	header http.Header
	body   string
}

// send makes one request and reads the whole answer. headers and form are optional.
func send(t *testing.T, c *http.Client, method, target string, headers map[string]string, form url.Values) answer {
	t.Helper()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(t.Context(), method, target, body)
	if err != nil {
		t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, target, err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return answer{status: resp.StatusCode, header: resp.Header, body: string(raw)}
}

func (a answer) cookie(name string) *http.Cookie {
	resp := http.Response{Header: a.header}
	for _, c := range resp.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// signedIn drives a whole sign-in through Dex: the control plane's redirect, Dex's login form with the
// test user, and the callback. It returns the cookies the control plane set on the callback.
func signedIn(t *testing.T, api string, dex *http.Client, state func(string) string) answer {
	t.Helper()
	start := send(t, plain, http.MethodGet, api+"/auth/login/dex", nil, nil)
	attempt := start.cookie("__Host-ipso-login")
	if start.status != http.StatusSeeOther || attempt == nil {
		t.Fatalf("start: status %d: %s", start.status, start.body)
	}
	next := start.header.Get("Location")

	// Dex sends the browser from the authorization endpoint to the login form of its password connector.
	login := ""
	for range 6 {
		hop := send(t, dex, http.MethodGet, next, nil, nil)
		if hop.status >= 300 && hop.status < 400 {
			base, err := url.Parse(next)
			if err != nil {
				t.Fatal(err)
			}
			target, err := base.Parse(hop.header.Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			next = target.String()
			continue
		}
		if hop.status != http.StatusOK {
			t.Fatalf("Dex answered %d at %s: %s", hop.status, next, hop.body)
		}
		login = next
		break
	}
	if login == "" {
		t.Fatal("Dex did not show its login form")
	}
	form := url.Values{"login": {setting(t, "IPSO_DEX_USER", "")}, "password": {setting(t, "IPSO_DEX_PASSWORD", "")}}
	posted := send(t, dex, http.MethodPost, login, nil, form)
	// With the approval screen skipped, Dex answers with the redirect back to the control plane, maybe
	// after one hop through its own approval address.
	callback := ""
	for range 4 {
		if posted.status < 300 || posted.status >= 400 {
			t.Fatalf("Dex answered %d to the login: %s", posted.status, posted.body)
		}
		base, err := url.Parse(login)
		if err != nil {
			t.Fatal(err)
		}
		target, err := base.Parse(posted.header.Get("Location"))
		if err != nil {
			t.Fatal(err)
		}
		if target.Host != "dex:5556" {
			callback = target.RequestURI()
			break
		}
		login = target.String()
		posted = send(t, dex, http.MethodGet, login, nil, nil)
	}
	if callback == "" || !strings.HasPrefix(callback, "/auth/callback/dex?") {
		t.Fatalf("Dex sent the browser to %q, want /auth/callback/dex", callback)
	}
	if state != nil {
		callback = state(callback)
	}
	return send(t, plain, http.MethodGet, api+callback, map[string]string{"Cookie": attempt.Name + "=" + attempt.Value}, nil)
}

// The generic OpenID Connect path that Google, Microsoft, and a self-hosted provider share, run for real:
// the control plane's redirect, a person typing a password at Dex, the callback, the cookie on the API,
// a request from another site, and logout.
func TestAPersonSignsInThroughDexAndSignsOut(t *testing.T) {
	waitForHealth(t)
	api := setting(t, "IPSO_SMOKE_API", defaultAPI)
	dex := dexBrowser(t)

	callback := signedIn(t, api, dex, nil)
	if callback.status != http.StatusSeeOther || callback.header.Get("Location") != "/" {
		t.Fatalf("callback: status %d: %s", callback.status, callback.body)
	}
	session := callback.cookie("__Host-ipso-session")
	if session == nil {
		t.Fatalf("no session cookie: %v", callback.header["Set-Cookie"])
	}
	if !session.Secure || !session.HttpOnly || session.SameSite != http.SameSiteStrictMode || session.Path != "/" || session.Domain != "" || session.MaxAge <= 0 {
		t.Errorf("session cookie attributes: %v", session)
	}
	if cleared := callback.cookie("__Host-ipso-login"); cleared == nil || cleared.MaxAge >= 0 {
		t.Errorf("the attempt cookie was not cleared: %v", callback.header["Set-Cookie"])
	}
	cookie := map[string]string{"Cookie": session.Name + "=" + session.Value}

	t.Run("the cookie reads the registry", func(t *testing.T) {
		if got := send(t, plain, http.MethodGet, api+"/v1/scopes", cookie, nil); got.status != http.StatusOK {
			t.Errorf("status %d: %s", got.status, got.body)
		}
	})
	t.Run("a made-up cookie is refused and cleared", func(t *testing.T) {
		fake := map[string]string{"Cookie": session.Name + "=" + strings.Repeat("A", 43)}
		got := send(t, plain, http.MethodGet, api+"/v1/scopes", fake, nil)
		if got.status != http.StatusUnauthorized || got.cookie("__Host-ipso-session") == nil {
			t.Errorf("status %d: %v", got.status, got.header["Set-Cookie"])
		}
	})
	t.Run("a request from another site is refused", func(t *testing.T) {
		headers := map[string]string{"Cookie": cookie["Cookie"], "Sec-Fetch-Site": "cross-site"}
		if got := send(t, plain, http.MethodPost, api+"/auth/logout", headers, nil); got.status != http.StatusForbidden {
			t.Errorf("logout from another site: status %d", got.status)
		}
		if got := send(t, plain, http.MethodGet, api+"/v1/scopes", cookie, nil); got.status != http.StatusOK {
			t.Errorf("the session did not survive a refused logout: status %d", got.status)
		}
	})
	t.Run("a state that is not the one sent creates no session", func(t *testing.T) {
		forged := signedIn(t, api, dex, func(callback string) string {
			target, err := url.Parse(callback)
			if err != nil {
				t.Fatal(err)
			}
			query := target.Query()
			query.Set("state", "forged")
			target.RawQuery = query.Encode()
			return target.RequestURI()
		})
		if forged.status != http.StatusBadRequest || forged.cookie("__Host-ipso-session") != nil {
			t.Errorf("status %d: %v", forged.status, forged.header["Set-Cookie"])
		}
	})
	t.Run("logout ends the session", func(t *testing.T) {
		headers := map[string]string{"Cookie": cookie["Cookie"], "Sec-Fetch-Site": "same-origin"}
		got := send(t, plain, http.MethodPost, api+"/auth/logout", headers, nil)
		if got.status != http.StatusNoContent {
			t.Fatalf("logout: status %d: %s", got.status, got.body)
		}
		if cleared := got.cookie("__Host-ipso-session"); cleared == nil || cleared.MaxAge >= 0 {
			t.Errorf("the cookie was not cleared: %v", got.header["Set-Cookie"])
		}
		if got := send(t, plain, http.MethodGet, api+"/v1/scopes", cookie, nil); got.status != http.StatusUnauthorized {
			t.Errorf("after logout: status %d, want 401", got.status)
		}
	})
}
