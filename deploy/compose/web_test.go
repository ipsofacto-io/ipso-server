//go:build compose

package compose

import (
	"net/http"
	"regexp"
	"strings"
	"testing"
)

var (
	scriptTag = regexp.MustCompile(`(?i)<script[^>]*>`)
	scriptRef = regexp.MustCompile(`<script[^>]+src="(/assets/[^"]+\.js)"`)
	styleRef  = regexp.MustCompile(`<link[^>]+href="(/assets/[^"]+\.css)"`)
	fontRef   = regexp.MustCompile(`url\((/assets/[^)]+\.woff2)\)`)
)

// The web app (ADR-0106) is served by the api role through the nginx front, at every path that is not the
// API's or the sign-in's: the page and its files with the policy that keeps the page to its own files, a view
// by its address, and a 404 for a file that is not there. The API and the sign-in answer as before.
func TestTheStackServesTheWebApp(t *testing.T) {
	waitForHealth(t)
	base := setting(t, "IPSO_SMOKE_API", defaultAPI)

	page := send(t, plain, http.MethodGet, base+"/", nil, nil)
	if page.status != http.StatusOK || !strings.HasPrefix(page.header.Get("Content-Type"), "text/html") || !strings.Contains(page.body, `<div id="root">`) {
		t.Fatalf("/: status %d, type %q: %.200s", page.status, page.header.Get("Content-Type"), page.body)
	}
	for name, want := range map[string]string{
		"Content-Security-Policy":    "script-src 'self'",
		"X-Content-Type-Options":     "nosniff",
		"Referrer-Policy":            "no-referrer",
		"Cross-Origin-Opener-Policy": "same-origin",
		"X-Frame-Options":            "DENY",
	} {
		if got := page.header.Get(name); !strings.Contains(got, want) {
			t.Errorf("%s = %q, want it to hold %q", name, got, want)
		}
	}
	for _, directive := range []string{"default-src 'none'", "style-src 'self'", "font-src 'self'", "connect-src 'self'", "frame-ancestors 'none'", "base-uri 'none'"} {
		if !strings.Contains(page.header.Get("Content-Security-Policy"), directive) {
			t.Errorf("the policy lacks %s: %s", directive, page.header.Get("Content-Security-Policy"))
		}
	}
	if strings.Contains(page.header.Get("Content-Security-Policy"), "unsafe") {
		t.Errorf("the policy allows something unsafe: %s", page.header.Get("Content-Security-Policy"))
	}
	for _, tag := range scriptTag.FindAllString(page.body, -1) {
		if !strings.Contains(tag, " src=") {
			t.Errorf("the page holds an inline script, which its policy would refuse: %s", tag)
		}
	}

	t.Run("a view is the page", func(t *testing.T) {
		for _, path := range []string{"/decisions", "/decisions/use-tls", "/audit/merges"} {
			if got := send(t, plain, http.MethodGet, base+path, nil, nil); got.status != http.StatusOK || got.body != page.body {
				t.Errorf("%s: status %d, and the page differs", path, got.status)
			}
		}
	})

	t.Run("the files of the build are served by type, and the hashed ones are kept for a year", func(t *testing.T) {
		script, style := scriptRef.FindStringSubmatch(page.body), styleRef.FindStringSubmatch(page.body)
		if script == nil || style == nil {
			t.Fatalf("the page names no script or no style: %s", page.body)
		}
		js := send(t, plain, http.MethodGet, base+script[1], nil, nil)
		if js.status != http.StatusOK || !strings.HasPrefix(js.header.Get("Content-Type"), "text/javascript") || !strings.Contains(js.header.Get("Cache-Control"), "immutable") {
			t.Errorf("%s: status %d, type %q, cache %q", script[1], js.status, js.header.Get("Content-Type"), js.header.Get("Cache-Control"))
		}
		css := send(t, plain, http.MethodGet, base+style[1], nil, nil)
		if css.status != http.StatusOK || !strings.HasPrefix(css.header.Get("Content-Type"), "text/css") {
			t.Fatalf("%s: status %d, type %q", style[1], css.status, css.header.Get("Content-Type"))
		}
		font := fontRef.FindStringSubmatch(css.body)
		if font == nil {
			t.Fatal("the style names no font from the app's own origin")
		}
		if got := send(t, plain, http.MethodGet, base+font[1], nil, nil); got.status != http.StatusOK || got.header.Get("Content-Type") != "font/woff2" {
			t.Errorf("%s: status %d, type %q", font[1], got.status, got.header.Get("Content-Type"))
		}
		if strings.Contains(css.body, "fonts.googleapis.com") || strings.Contains(css.body, "fonts.gstatic.com") {
			t.Error("the style loads a font from another origin, which the policy refuses")
		}
	})

	t.Run("a file that is not there is a 404, never the page", func(t *testing.T) {
		got := send(t, plain, http.MethodGet, base+"/assets/gone-0a0a0a.js", nil, nil)
		if got.status != http.StatusNotFound || strings.Contains(got.body, `<div id="root">`) {
			t.Errorf("status %d: %.100s", got.status, got.body)
		}
	})

	t.Run("the page takes no POST", func(t *testing.T) {
		if got := send(t, plain, http.MethodPost, base+"/", nil, nil); got.status != http.StatusMethodNotAllowed {
			t.Errorf("status %d", got.status)
		}
	})

	t.Run("the API and the sign-in answer as before", func(t *testing.T) {
		if got := send(t, plain, http.MethodGet, base+"/v1/scopes", nil, nil); got.status != http.StatusUnauthorized || strings.Contains(got.body, "<") {
			t.Errorf("/v1/scopes: status %d: %.100s", got.status, got.body)
		}
		if got := send(t, plain, http.MethodGet, base+"/v1/nothing", nil, nil); got.status != http.StatusUnauthorized {
			t.Errorf("/v1/nothing: status %d", got.status)
		}
		providers := send(t, plain, http.MethodGet, base+"/auth/providers", nil, nil)
		if providers.status != http.StatusOK || !strings.Contains(providers.body, `{"id":"dex","kind":"oidc"}`) || providers.header.Get("Cache-Control") != "no-store" {
			t.Errorf("/auth/providers: status %d, cache %q: %s", providers.status, providers.header.Get("Cache-Control"), providers.body)
		}
	})
}
