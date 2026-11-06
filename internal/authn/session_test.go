package authn

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestASessionCookieRoundTripsAndKeepsTheHost(t *testing.T) {
	token, err := NewSessionToken()
	if err != nil || len(token) != SessionTokenSize {
		t.Fatalf("token %d bytes, %v", len(token), err)
	}
	other, _ := NewSessionToken()
	if bytes.Equal(token, other) {
		t.Fatal("two tokens are equal")
	}
	now := time.Now()
	cookie := NewSessionCookie(token, now.Add(8*time.Hour), now)
	for name, ok := range map[string]bool{
		"Secure":    cookie.Secure,
		"HttpOnly":  cookie.HttpOnly,
		"Path=/":    cookie.Path == "/",
		"Strict":    cookie.SameSite == http.SameSiteStrictMode,
		"no Domain": cookie.Domain == "",
		"Max-Age":   cookie.MaxAge == 8*3600,
		"prefix":    strings.HasPrefix(cookie.Name, "__Host-"),
	} {
		if !ok {
			t.Errorf("the cookie is not %s: %v", name, cookie)
		}
	}
	if len(cookie.Value) != sessionTokenText {
		t.Errorf("value is %d characters, want %d", len(cookie.Value), sessionTokenText)
	}

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: cookie.Name, Value: cookie.Value})
	got, err := SessionToken(r)
	if err != nil || !bytes.Equal(got, token) {
		t.Fatalf("SessionToken = %x, %v", got, err)
	}
	if hash := SessionHash(got); len(hash) != 32 || bytes.Equal(hash, got) {
		t.Fatalf("hash %x", hash)
	}
}

func TestAnExpiredLifetimeStillGivesAUsableCookie(t *testing.T) {
	now := time.Now()
	if cookie := NewSessionCookie(make([]byte, 32), now.Add(-time.Hour), now); cookie.MaxAge != 1 {
		t.Errorf("Max-Age = %d, want 1 and never 0 or negative, which would delete it", cookie.MaxAge)
	}
}

func TestAClearedCookieRepeatsTheAttributesItDeletes(t *testing.T) {
	cookie := ClearedSessionCookie()
	if cookie.Name != SessionCookieName || cookie.MaxAge >= 0 || cookie.Value != "" || !cookie.Secure || cookie.Path != "/" || cookie.Domain != "" || !cookie.HttpOnly {
		t.Fatalf("%v", cookie)
	}
	header := cookie.String()
	for _, want := range []string{"Max-Age=0", "Secure", "Path=/", "HttpOnly", "SameSite=Strict"} {
		if !strings.Contains(header, want) {
			t.Errorf("%q lacks %s", header, want)
		}
	}
}

func TestOnlyOneWellFormedSessionCookieIsRead(t *testing.T) {
	good := strings.Repeat("A", sessionTokenText)
	for name, tc := range map[string]struct {
		values []string
		want   error
	}{
		"none":            {nil, ErrNoSession},
		"one":             {[]string{good}, nil},
		"two":             {[]string{good, good}, ErrBadSession},
		"short":           {[]string{good[:42]}, ErrBadSession},
		"long":            {[]string{good + "A"}, ErrBadSession},
		"padded":          {[]string{good[:42] + "="}, ErrBadSession},
		"standard base64": {[]string{strings.Repeat("A", 42) + "+"}, ErrBadSession},
		"stray bits":      {[]string{strings.Repeat("A", 42) + "B"}, ErrBadSession},
		"not base64":      {[]string{strings.Repeat("!", sessionTokenText)}, ErrBadSession},
		"empty":           {[]string{""}, ErrBadSession},
	} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			for _, v := range tc.values {
				r.AddCookie(&http.Cookie{Name: SessionCookieName, Value: v})
			}
			_, err := SessionToken(r)
			if tc.want == nil && err != nil || tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}
