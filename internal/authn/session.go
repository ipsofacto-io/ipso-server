package authn

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"time"
)

const (
	// SessionCookieName is the cookie of a browser session (ADR-0099). The __Host- prefix makes a
	// browser refuse it unless it is Secure, has Path=/, and names no Domain, so another subdomain or a
	// plain http page cannot plant one.
	SessionCookieName = "__Host-ipso-session"
	// SessionTokenSize is the number of random bytes in a session token.
	SessionTokenSize = 32
	// sessionTokenText is the length of a token as unpadded base64url.
	sessionTokenText = 43
)

var (
	// ErrNoSession is returned when a request carries no session cookie.
	ErrNoSession = errors.New("no session cookie")
	// ErrBadSession is returned for a session cookie that is repeated or is not 32 bytes of unpadded
	// base64url. Nothing has to ask the database about one.
	ErrBadSession = errors.New("the session cookie is malformed")
)

// NewSessionToken returns 32 random bytes from the system's source.
func NewSessionToken() ([]byte, error) {
	token := make([]byte, SessionTokenSize)
	if _, err := rand.Read(token); err != nil {
		return nil, err
	}
	return token, nil
}

// SessionToken returns the token of the request's session cookie. A request that sends the cookie more
// than once is malformed, because the first value would not be the one a proxy or a script meant.
func SessionToken(r *http.Request) ([]byte, error) {
	cookies := r.CookiesNamed(SessionCookieName)
	switch len(cookies) {
	case 0:
		return nil, ErrNoSession
	case 1:
	default:
		return nil, ErrBadSession
	}
	value := cookies[0].Value
	if len(value) != sessionTokenText {
		return nil, ErrBadSession
	}
	token, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(token) != SessionTokenSize {
		return nil, ErrBadSession
	}
	return token, nil
}

// SessionHash is what the database keeps of a token: its SHA-256. A read of the table is not a session.
func SessionHash(token []byte) []byte {
	sum := sha256.Sum256(token)
	return sum[:]
}

// NewSessionCookie is the cookie that carries token until expires. Secure is always set, whatever the
// request looked like: TLS usually ends at a proxy, and the browsers that matter treat a loopback
// origin as secure.
func NewSessionCookie(token []byte, expires, now time.Time) *http.Cookie {
	seconds := int(expires.Sub(now) / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	cookie := baseSessionCookie()
	cookie.Value = base64.RawURLEncoding.EncodeToString(token)
	cookie.MaxAge = seconds
	return cookie
}

// ClearedSessionCookie deletes the session cookie. It repeats the attributes of the cookie it deletes,
// because a browser ignores a deletion of a __Host- cookie that differs.
func ClearedSessionCookie() *http.Cookie {
	cookie := baseSessionCookie()
	cookie.MaxAge = -1
	return cookie
}

func baseSessionCookie() *http.Cookie {
	return &http.Cookie{
		Name:     SessionCookieName,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		// Strict, because the SPA that uses the cookie is same-origin and a page on another site has no
		// reason to send it.
		SameSite: http.SameSiteStrictMode,
	}
}

// NewOriginCheck returns the check that refuses a cross-origin request that could change state: an
// unsafe method whose Sec-Fetch-Site or Origin says it came from another site. Safe methods pass. The
// public origin is trusted, because a proxy that drops the port changes what a browser's Origin is
// compared with. A session cookie is only honoured for a request that passes it (ADR-0099).
func NewOriginCheck(origin string) (*http.CrossOriginProtection, error) {
	protection := http.NewCrossOriginProtection()
	if err := protection.AddTrustedOrigin(origin); err != nil {
		return nil, err
	}
	return protection, nil
}
