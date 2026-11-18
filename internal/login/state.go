package login

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"time"
)

const (
	// attemptCookieName holds the state of one sign-in between the redirect to the provider and its
	// callback. The __Host- prefix stops a sibling subdomain or a plain http page from planting one, so
	// the cookie needs no signature and ipso needs no key to sign it with.
	attemptCookieName = "__Host-ipso-login"
	attemptLife       = 10 * time.Minute
	// maxAttemptCookie bounds what is parsed. A real one is about 280 bytes.
	maxAttemptCookie = 1024
)

// attempt is what a sign-in needs to remember: which provider it went to, the state and nonce it
// sent, and the PKCE verifier it holds back until the code exchange. Previous is the hash of the
// session the browser held when the sign-in began, as unpadded base64url, or empty. The callback is a
// request from the provider's site, so a SameSite=Strict session cookie is not sent with it, and this
// is how the sign-in still ends the session it replaces. Invitation is the token of the invitation the
// person came with, or empty (ADR-0127). It is the token and not its hash, because the cookie is not
// signed: a hash in it would let anyone who read the table use an invitation. Only the server sets the
// cookie, and the callback hashes the token itself.
type attempt struct {
	Provider   string `json:"p"`
	State      string `json:"s"`
	Nonce      string `json:"n"`
	Verifier   string `json:"v"`
	Previous   string `json:"o,omitempty"`
	Invitation string `json:"i,omitempty"`
	// Request is set for a posted callback. The cookie is then SameSite=None, because a cross-site
	// POST does not send a Lax cookie (ADR-0131). OIDC and GitHub leave it empty and stay Lax.
	Request string `json:"r,omitempty"`
}

func (a attempt) cookie() *http.Cookie {
	raw, _ := json.Marshal(a)
	cookie := baseAttemptCookie()
	if a.Request != "" {
		cookie.SameSite = http.SameSiteNoneMode
	}
	cookie.Value = base64.RawURLEncoding.EncodeToString(raw)
	cookie.MaxAge = int(attemptLife / time.Second)
	return cookie
}

// clearedAttemptCookie deletes the cookie with the attributes it was set with, because a browser
// ignores the deletion of a __Host- cookie that differs.
func clearedAttemptCookie() *http.Cookie {
	return clearAttempt(http.SameSiteLaxMode)
}

// clearedPostedAttemptCookie deletes a SameSite=None attempt cookie. A Lax deletion leaves it.
func clearedPostedAttemptCookie() *http.Cookie {
	return clearAttempt(http.SameSiteNoneMode)
}

func clearAttempt(site http.SameSite) *http.Cookie {
	cookie := baseAttemptCookie()
	cookie.SameSite = site
	cookie.MaxAge = -1
	return cookie
}

func baseAttemptCookie() *http.Cookie {
	return &http.Cookie{
		Name:     attemptCookieName,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		// Lax, because the provider sends the browser back with a top-level GET, which Strict would not
		// carry the cookie on.
		SameSite: http.SameSiteLaxMode,
	}
}

// readAttempt returns the attempt of the request's cookie. A request that sends the cookie twice, or
// one that does not decode, has none.
func readAttempt(r *http.Request) (attempt, bool) {
	cookies := r.CookiesNamed(attemptCookieName)
	if len(cookies) != 1 || len(cookies[0].Value) > maxAttemptCookie {
		return attempt{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(cookies[0].Value)
	if err != nil {
		return attempt{}, false
	}
	var a attempt
	if err := json.Unmarshal(raw, &a); err != nil || a.Provider == "" || a.State == "" || a.Nonce == "" || a.Verifier == "" {
		return attempt{}, false
	}
	return a, true
}

// randomText returns n random bytes as unpadded base64url.
func randomText(n int) (string, error) {
	raw := make([]byte, n)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
