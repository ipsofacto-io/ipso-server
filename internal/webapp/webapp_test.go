package webapp

import (
	"bytes"
	"compress/gzip"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

const page = "<!doctype html><title>ipso</title><script type=\"module\" src=\"/assets/app-1a2b3c.js\"></script>"

func app() fstest.MapFS {
	return fstest.MapFS{
		"index.html":               {Data: []byte(page)},
		"assets/app-1a2b3c.js":     {Data: []byte(strings.Repeat("console.log(1);\n", 80))},
		"assets/app-9f8e7d.css":    {Data: []byte("body{margin:0}")},
		"assets/font-4d5e6f.woff2": {Data: []byte("wOF2")},
		"favicon.svg":              {Data: []byte("<svg xmlns=\"http://www.w3.org/2000/svg\"/>")},
		"site.webmanifest":         {Data: []byte("{}")},
	}
}

func serve(t *testing.T, h http.Handler, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, target, nil))
	return rec
}

func newHandler(t *testing.T) http.Handler {
	t.Helper()
	h, err := New(app())
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// Every answer of the handler carries the headers that make the strict policy hold, the 404 and the 405
// included.
func assertHeaders(t *testing.T, rec *httptest.ResponseRecorder, what string) {
	t.Helper()
	want := map[string]string{
		"Content-Security-Policy":    contentSecurityPolicy,
		"X-Content-Type-Options":     "nosniff",
		"Referrer-Policy":            "no-referrer",
		"Cross-Origin-Opener-Policy": "same-origin",
		"X-Frame-Options":            "DENY",
	}
	for name, value := range want {
		if got := rec.Header().Get(name); got != value {
			t.Errorf("%s: %s = %q, want %q", what, name, got, value)
		}
	}
}

func TestThePolicyLetsNothingInlineOrForeignRun(t *testing.T) {
	for _, forbidden := range []string{"unsafe-inline", "unsafe-eval", "http:", "https:", "*"} {
		if strings.Contains(contentSecurityPolicy, forbidden) {
			t.Errorf("the policy holds %q", forbidden)
		}
	}
	for _, directive := range []string{"default-src 'none'", "script-src 'self'", "frame-ancestors 'none'", "base-uri 'none'", "connect-src 'self'"} {
		if !strings.Contains(contentSecurityPolicy, directive) {
			t.Errorf("the policy lacks %q", directive)
		}
	}
}

func TestEveryViewIsThePageAndIsNotCached(t *testing.T) {
	h := newHandler(t)
	for _, target := range []string{"/", "/index.html", "/decisions", "/decisions/use-postgresql", "/decisions/v1.2", "/audit/merges", "/inbox/", "/signin"} {
		rec := serve(t, h, http.MethodGet, target)
		if rec.Code != http.StatusOK || rec.Body.String() != page {
			t.Errorf("%s = %d %q", target, rec.Code, rec.Body.String())
		}
		if got := rec.Header().Get("Content-Type"); got != "text/html; charset=utf-8" {
			t.Errorf("%s content type %q", target, got)
		}
		if got := rec.Header().Get("Cache-Control"); got != "no-cache" {
			t.Errorf("%s cache %q", target, got)
		}
		assertHeaders(t, rec, target)
	}
}

func TestAHashedAssetIsServedForAYearWithItsType(t *testing.T) {
	h := newHandler(t)
	for target, contentType := range map[string]string{
		"/assets/app-1a2b3c.js":     "text/javascript; charset=utf-8",
		"/assets/app-9f8e7d.css":    "text/css; charset=utf-8",
		"/assets/font-4d5e6f.woff2": "font/woff2",
	} {
		rec := serve(t, h, http.MethodGet, target)
		if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != contentType {
			t.Errorf("%s = %d %q", target, rec.Code, rec.Header().Get("Content-Type"))
		}
		if got := rec.Header().Get("Cache-Control"); got != "public, max-age=31536000, immutable" {
			t.Errorf("%s cache %q", target, got)
		}
		assertHeaders(t, rec, target)
	}
	for target, contentType := range map[string]string{"/favicon.svg": "image/svg+xml", "/site.webmanifest": "application/manifest+json"} {
		rec := serve(t, h, http.MethodGet, target)
		if rec.Code != http.StatusOK || rec.Header().Get("Content-Type") != contentType || rec.Header().Get("Cache-Control") != "no-cache" {
			t.Errorf("%s = %d %v", target, rec.Code, rec.Header())
		}
	}
}

func TestAFileThatIsNotThereIsA404NeverThePage(t *testing.T) {
	h := newHandler(t)
	for _, target := range []string{"/assets/gone-0a0a0a.js", "/assets/", "/assets/nothing", "/app.js", "/robots.txt", "/missing.css", "/icon.png", "/x.woff2"} {
		rec := serve(t, h, http.MethodGet, target)
		if rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "<title>") {
			t.Errorf("%s = %d %q", target, rec.Code, rec.Body.String())
		}
		assertHeaders(t, rec, target)
	}
}

func TestARepeatedRequestIsAnsweredFromTheEntityTag(t *testing.T) {
	h := newHandler(t)
	first := serve(t, h, http.MethodGet, "/")
	etag := first.Header().Get("ETag")
	if etag == "" || etag != serve(t, h, http.MethodGet, "/index.html").Header().Get("ETag") {
		t.Fatalf("etag %q", etag)
	}
	req := httptest.NewRequest(http.MethodGet, "/decisions", nil)
	req.Header.Set("If-None-Match", etag)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotModified || rec.Body.Len() != 0 {
		t.Errorf("revalidation = %d %q", rec.Code, rec.Body.String())
	}
	assertHeaders(t, rec, "304")
}

func TestHEADSendsNoBodyAndOtherMethodsAre405(t *testing.T) {
	h := newHandler(t)
	if rec := serve(t, h, http.MethodHead, "/"); rec.Code != http.StatusOK || rec.Body.Len() != 0 || rec.Header().Get("Content-Length") == "" {
		t.Errorf("HEAD = %d %q %v", rec.Code, rec.Body.String(), rec.Header())
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch, http.MethodOptions} {
		rec := serve(t, h, method, "/decisions")
		if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != "GET, HEAD" {
			t.Errorf("%s = %d %v", method, rec.Code, rec.Header())
		}
		assertHeaders(t, rec, method)
	}
}

// Whatever the path says, the answer is a file of the build or the page. Nothing outside the build is
// reachable, because the handler holds only what it read at start.
func TestAPathThatClimbsOutOfTheBuildReadsNothingElse(t *testing.T) {
	h := newHandler(t)
	for _, target := range []string{"/../go.mod", "/%2e%2e/%2e%2e/etc/passwd", "/assets/../../secret", "//etc/passwd", "/assets/%2e%2e/index.html"} {
		rec := serve(t, h, http.MethodGet, target)
		if strings.Contains(rec.Body.String(), "root:") || (rec.Code == http.StatusOK && rec.Body.String() != page) {
			t.Errorf("%s = %d %q", target, rec.Code, rec.Body.String())
		}
	}
}

func TestABuildWithoutThePageOrWithAnUnknownTypeIsRefusedAtStart(t *testing.T) {
	if _, err := New(fstest.MapFS{"assets/app.js": {Data: []byte("x")}}); err == nil || !strings.Contains(err.Error(), "index.html") {
		t.Errorf("no index.html: %v", err)
	}
	if _, err := New(fstest.MapFS{"index.html": {Data: []byte(page)}, "assets/app.exe": {Data: []byte("x")}}); err == nil || !strings.Contains(err.Error(), "app.exe") {
		t.Errorf("unknown type: %v", err)
	}
	if _, err := New(fstest.MapFS{}); err == nil {
		t.Error("an empty build was accepted")
	}
}

func TestAMissingAppSaysSoAndServesNoPage(t *testing.T) {
	for _, target := range []string{"/", "/decisions"} {
		rec := serve(t, Missing(), http.MethodGet, target)
		if rec.Code != http.StatusNotFound || !strings.Contains(rec.Body.String(), "not built into this binary") {
			t.Errorf("%s = %d %q", target, rec.Code, rec.Body.String())
		}
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s cache %q", target, rec.Header().Get("Cache-Control"))
		}
		assertHeaders(t, rec, target)
	}
}

// The binary compiles without a build of web/, and then Files is nil. When the build is there, it has a
// page, and the handler accepts it.
func TestFilesIsNilWithoutABuildAndAcceptedWithOne(t *testing.T) {
	files := Files()
	if files == nil {
		return
	}
	if _, err := fs.Stat(files, "index.html"); err != nil {
		t.Fatal(err)
	}
	if _, err := New(files); err != nil {
		t.Fatal(err)
	}
}

func gzipped(t *testing.T, h http.Handler, target, accept string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if accept != "" {
		req.Header.Set("Accept-Encoding", accept)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAClientThatAcceptsGzipGetsTheSmallerFormWithItsOwnEntityTag(t *testing.T) {
	h := newHandler(t)
	const target = "/assets/app-1a2b3c.js"
	plain := gzipped(t, h, target, "")
	packed := gzipped(t, h, target, "br, gzip;q=0.8")
	if packed.Header().Get("Content-Encoding") != "gzip" || packed.Header().Get("Vary") != "Accept-Encoding" || packed.Body.Len() >= plain.Body.Len() {
		t.Fatalf("gzip: %v, %d bytes against %d", packed.Header(), packed.Body.Len(), plain.Body.Len())
	}
	zr, err := gzip.NewReader(bytes.NewReader(packed.Body.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	inflated, err := io.ReadAll(zr)
	if err != nil || !bytes.Equal(inflated, plain.Body.Bytes()) {
		t.Errorf("the gzip form is not the same file: %v", err)
	}
	if plain.Header().Get("Content-Encoding") != "" || plain.Header().Get("Vary") != "Accept-Encoding" {
		t.Errorf("the plain form: %v", plain.Header())
	}
	if plain.Header().Get("ETag") == packed.Header().Get("ETag") || packed.Header().Get("Content-Type") != "text/javascript; charset=utf-8" {
		t.Errorf("etags %q and %q, type %q", plain.Header().Get("ETag"), packed.Header().Get("ETag"), packed.Header().Get("Content-Type"))
	}
	assertHeaders(t, packed, "gzip")

	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("If-None-Match", packed.Header().Get("ETag"))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotModified || rec.Header().Get("Content-Encoding") != "" {
		t.Errorf("revalidation: %d %v", rec.Code, rec.Header())
	}
}

func TestGzipIsOfferedOnlyWhereItHelpsAndIsAsked(t *testing.T) {
	h := newHandler(t)
	for _, accept := range []string{"", "identity", "gzip;q=0", "gzip; q=0.0", "deflate", "gzip;q=junk"} {
		if rec := gzipped(t, h, "/assets/app-1a2b3c.js", accept); rec.Header().Get("Content-Encoding") != "" {
			t.Errorf("Accept-Encoding %q got %q", accept, rec.Header().Get("Content-Encoding"))
		}
	}
	// A font is compressed already, and a page too small to shrink is sent as it is.
	for _, target := range []string{"/assets/font-4d5e6f.woff2", "/"} {
		if rec := gzipped(t, h, target, "gzip"); rec.Header().Get("Content-Encoding") != "" || rec.Header().Get("Vary") != "" {
			t.Errorf("%s: %v", target, rec.Header())
		}
	}
}
