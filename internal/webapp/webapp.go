// Package webapp serves the single-page web app of IPSO-62 from the files built into the binary
// (ADR-0106). The api role mounts it at every path that is not the API's or the sign-in's. The app is
// static: it holds no secret, reads no cookie, and calls the API from the browser with the session
// cookie of ADR-0099.
//
// The Vite build of web/ writes internal/webapp/dist/app. A build without that directory (go build,
// go test) still compiles, and Files then returns nil.
package webapp

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"
)

//go:embed all:dist
var built embed.FS

// Files returns the web app built into the binary, rooted at its index.html, or nil when the binary was
// built without it.
func Files() fs.FS {
	files, err := fs.Sub(built, "dist/app")
	if err != nil {
		return nil
	}
	if info, err := fs.Stat(files, "index.html"); err != nil || !info.Mode().IsRegular() {
		return nil
	}
	return files
}

// contentSecurityPolicy lets a page load only its own scripts, styles, fonts, images, and requests. The
// app has no inline script or style, so none is allowed. It cannot be framed, and it sets no base.
const contentSecurityPolicy = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; " +
	"font-src 'self'; connect-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

// types holds the content type of each file the build writes. The table is fixed, so an answer does
// not depend on the mime database of the host, and nosniff has a type to trust.
var types = map[string]string{
	".html":        "text/html; charset=utf-8",
	".js":          "text/javascript; charset=utf-8",
	".css":         "text/css; charset=utf-8",
	".json":        "application/json",
	".webmanifest": "application/manifest+json",
	".svg":         "image/svg+xml",
	".png":         "image/png",
	".ico":         "image/x-icon",
	".woff":        "font/woff",
	".woff2":       "font/woff2",
	".txt":         "text/plain; charset=utf-8",
}

// compressible names the types that gzip makes smaller. The others are compressed already.
var compressible = map[string]bool{".html": true, ".js": true, ".css": true, ".json": true, ".webmanifest": true, ".svg": true, ".txt": true}

type asset struct {
	body        []byte
	contentType string
	etag        string
	cache       string
	// gz is the gzip form of body, kept only when it is smaller, and gzEtag is its own entity tag, because a
	// cache must not take one form for the other.
	gz     []byte
	gzEtag string
}

type handler struct {
	assets map[string]asset
	index  asset
}

// New returns the handler of the built app. It reads every file once, so it fails at start when the
// build is missing its index.html or holds a file of a type it does not know, and it serves from memory
// afterwards.
func New(files fs.FS) (http.Handler, error) {
	h := &handler{assets: map[string]asset{}}
	err := fs.WalkDir(files, ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		if !entry.Type().IsRegular() {
			return fmt.Errorf("%s is not a regular file", name)
		}
		contentType, ok := types[path.Ext(name)]
		if !ok {
			return fmt.Errorf("%s has a file type the web app does not serve", name)
		}
		body, err := fs.ReadFile(files, name)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(body)
		cache := "no-cache"
		if strings.HasPrefix(name, "assets/") {
			// The build names these files by their content, so a changed file has a new name.
			cache = "public, max-age=31536000, immutable"
		}
		tag := hex.EncodeToString(sum[:16])
		a := asset{body: body, contentType: contentType, etag: `"` + tag + `"`, cache: cache}
		if compressible[path.Ext(name)] {
			var packed bytes.Buffer
			zw, err := gzip.NewWriterLevel(&packed, gzip.BestCompression)
			if err != nil {
				return err
			}
			if _, err := zw.Write(body); err != nil {
				return err
			}
			if err := zw.Close(); err != nil {
				return err
			}
			if packed.Len() < len(body) {
				a.gz, a.gzEtag = packed.Bytes(), `"`+tag+`-gzip"`
			}
		}
		h.assets[name] = a
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("read the web app: %w", err)
	}
	index, ok := h.assets["index.html"]
	if !ok {
		return nil, errors.New("read the web app: there is no index.html")
	}
	h.index = index
	return h, nil
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setHeaders(w)
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	name := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	a, ok := h.assets[name]
	switch {
	case ok:
	case isFile(name):
		// A missing script or style is a 404, never the page: a browser would try to run the page as one.
		http.NotFound(w, r)
		return
	default:
		// A path of the app's own router. The page reads the path and draws the view.
		a = h.index
	}
	w.Header().Set("Content-Type", a.contentType)
	w.Header().Set("Cache-Control", a.cache)
	body, etag := a.body, a.etag
	if a.gz != nil {
		w.Header().Add("Vary", "Accept-Encoding")
		if acceptsGzip(r) {
			body, etag = a.gz, a.gzEtag
			w.Header().Set("Content-Encoding", "gzip")
		}
	}
	w.Header().Set("ETag", etag)
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(body))
}

// acceptsGzip reports whether the request lists gzip with a quality above zero.
func acceptsGzip(r *http.Request) bool {
	for _, part := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		coding, params, _ := strings.Cut(strings.TrimSpace(part), ";")
		if !strings.EqualFold(strings.TrimSpace(coding), "gzip") {
			continue
		}
		if q, ok := strings.CutPrefix(strings.ReplaceAll(strings.ToLower(params), " ", ""), "q="); ok {
			if weight, err := strconv.ParseFloat(q, 64); err != nil || weight <= 0 {
				return false
			}
		}
		return true
	}
	return false
}

// isFile reports whether a path names a static file rather than a view: it is under assets/, or it ends
// in an extension the build writes. A view id with a dot in it (a slug such as v1.2) is still a view.
func isFile(name string) bool {
	if name == "assets" || strings.HasPrefix(name, "assets/") {
		return true
	}
	_, ok := types[path.Ext(name)]
	return ok
}

func setHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("Content-Security-Policy", contentSecurityPolicy)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("X-Frame-Options", "DENY")
}

// Missing answers for a binary built without the web app, so an operator sees why "/" shows no page
// instead of a bare 401.
func Missing() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		setHeaders(w)
		w.Header().Set("Cache-Control", "no-store")
		http.Error(w, "The web app is not built into this binary. The API is served at /v1.", http.StatusNotFound)
	})
}
