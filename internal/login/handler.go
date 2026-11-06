package login

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"

	"golang.org/x/oauth2"

	"github.com/ipsofacto-io/ipso-server/internal/authn"
	"github.com/ipsofacto-io/ipso-server/internal/identity"
	"github.com/ipsofacto-io/ipso-server/internal/ratelimit"
)

// The error codes of /auth. They are a closed set, like the API's. None carries what a provider sent.
const (
	codeInvalidLogin = "invalid_login"
	codeLoginRefused = "login_refused"
	codeUnknownLogin = "unknown_login"
	codeForbidden    = "forbidden"
	codeRateLimited  = "rate_limited"
	codeNotFound     = "not_found"
	codeMethod       = "method_not_allowed"
	codeInternal     = "internal"

	// maxState and maxCode bound what a callback may carry before anything reads it.
	maxState = 256
	maxCode  = 4096
)

// Handler serves /auth/login/{provider}, /auth/callback/{provider}, and POST /auth/logout. Every answer
// carries no-store and no-referrer: a callback URL holds a one-time code, and none of it should be
// cached or sent on.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/login/{provider}", s.start)
	mux.HandleFunc("/auth/callback/{provider}", s.callback)
	mux.HandleFunc("/auth/logout", s.logout)
	mux.HandleFunc("/auth/", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusNotFound, codeNotFound) })
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		mux.ServeHTTP(w, r)
	})
}

// start sends the browser to the provider with a new state, nonce, and PKCE challenge, and keeps what
// it must remember in the attempt cookie.
func (s *Service) start(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	id := r.PathValue("provider")
	p, ok := s.providers[id]
	if !ok {
		writeJSON(w, http.StatusNotFound, codeNotFound)
		return
	}
	state, err := randomText(32)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, codeInternal)
		return
	}
	nonce, err := randomText(32)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, codeInternal)
		return
	}
	verifier := oauth2.GenerateVerifier()
	begun := attempt{Provider: id, State: state, Nonce: nonce, Verifier: verifier}
	// This request comes from a page of this site, so a session the browser holds is sent with it.
	if held, err := authn.SessionToken(r); err == nil {
		begun.Previous = base64.RawURLEncoding.EncodeToString(authn.SessionHash(held))
	}
	http.SetCookie(w, begun.cookie())
	w.Header().Set("Location", p.authorizeURL(s.redirectURI(id), state, nonce, verifier))
	w.WriteHeader(http.StatusSeeOther)
}

// callback finishes a sign-in. The checks that cost nothing come first, in the order that reveals
// least: the provider, the attempt cookie, the keys it reads, an error from the provider, the state,
// and the issuer. Only then does it spend the bucket and call the provider. The attempt cookie is
// cleared on every outcome, so a state is never used twice.
func (s *Service) callback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	http.SetCookie(w, clearedAttemptCookie())
	id := r.PathValue("provider")
	p, ok := s.providers[id]
	if !ok {
		writeJSON(w, http.StatusNotFound, codeNotFound)
		return
	}
	refuse := func(reason string) {
		s.log.Warn("a sign-in was refused", "provider", id, "reason", reason)
		writeJSON(w, http.StatusBadRequest, codeInvalidLogin)
	}
	a, ok := readAttempt(r)
	if !ok || a.Provider != id {
		refuse("no_attempt")
		return
	}
	// A provider adds keys of its own (Google sends scope, authuser, and prompt), so only the keys read
	// here have to appear once. A repeated state or code would let a second value hide behind the first.
	query := r.URL.Query()
	for _, key := range []string{"state", "code", "iss", "error"} {
		if len(query[key]) > 1 {
			refuse("repeated_key")
			return
		}
	}
	if query.Get("error") != "" {
		s.log.Warn("a sign-in was refused by the provider", "provider", id)
		writeJSON(w, http.StatusBadRequest, codeLoginRefused)
		return
	}
	state, code := query.Get("state"), query.Get("code")
	if state == "" || len(state) > maxState || subtle.ConstantTimeCompare([]byte(state), []byte(a.State)) != 1 {
		refuse("state")
		return
	}
	expected, required := p.issuerParameter()
	if (query.Has("iss") && query.Get("iss") != expected) || (required && !query.Has("iss")) {
		refuse("issuer")
		return
	}
	if code == "" || len(code) > maxCode {
		refuse("code")
		return
	}
	now := s.now()
	if wait, ok := s.callbacks.Allow(s.tenant, now); !ok {
		w.Header().Set("Retry-After", ratelimit.RetryAfter(wait))
		writeJSON(w, http.StatusTooManyRequests, codeRateLimited)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), callbackTimeout)
	defer cancel()
	who, err := p.complete(ctx, s.redirectURI(id), code, a.Verifier, a.Nonce)
	if err != nil {
		var f *failure
		if errors.As(err, &f) {
			s.log.Warn("a sign-in could not be completed", "provider", id, "step", f.Error())
		} else {
			s.log.Warn("a sign-in could not be completed", "provider", id)
		}
		writeJSON(w, http.StatusBadRequest, codeInvalidLogin)
		return
	}

	previous := previousSession(r, a)
	token, err := authn.NewSessionToken()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, codeInternal)
		return
	}
	expires, err := s.store.start(ctx, who.issuer, who.subject, authn.SessionHash(token), previous)
	switch {
	case errors.Is(err, identity.ErrUnknownLogin):
		// The person gets the two values an operator binds, and nothing is written. The subject is
		// theirs to see and is not logged.
		s.log.Info("a sign-in named a login the tenant never bound", "provider", id)
		writeUnknownLogin(w, who)
		return
	case errors.Is(err, identity.ErrNotHuman):
		writeJSON(w, http.StatusForbidden, codeForbidden)
		return
	case err != nil:
		s.log.Warn("a session could not be started", "provider", id)
		writeJSON(w, http.StatusInternalServerError, codeInternal)
		return
	}
	if previous != nil {
		s.known.remove(previous)
	}
	http.SetCookie(w, authn.NewSessionCookie(token, expires, now))
	// The constant /, never a parameter, so a sign-in cannot be turned into an open redirect.
	w.Header().Set("Location", "/")
	w.WriteHeader(http.StatusSeeOther)
}

// previousSession is the hash of the session this browser holds, which the new one replaces: the one on
// the callback itself when a browser sends it, and otherwise the one it held when the sign-in began.
// The attempt cookie is the server's own, so the hash in it is no one else's choice.
func previousSession(r *http.Request, a attempt) []byte {
	if old, err := authn.SessionToken(r); err == nil {
		return authn.SessionHash(old)
	}
	if hash, err := base64.RawURLEncoding.DecodeString(a.Previous); err == nil && len(hash) == identity.TokenHashSize {
		return hash
	}
	return nil
}

// logout ends the session of the cookie and clears it. It is a POST, and a request from another site
// is refused before anything is read. A cookie this process has not kept is charged to the same
// bucket as a lookup, because a delete is a write that anyone can ask for with a made-up cookie.
func (s *Service) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	if err := s.check.Check(r); err != nil {
		writeJSON(w, http.StatusForbidden, codeForbidden)
		return
	}
	token, err := authn.SessionToken(r)
	if err != nil {
		// Nothing to end. A repeated or malformed cookie is cleared so the browser stops sending it.
		http.SetCookie(w, authn.ClearedSessionCookie())
		w.WriteHeader(http.StatusNoContent)
		return
	}
	hash := authn.SessionHash(token)
	now := s.now()
	if _, kept := s.known.get(hash, now); !kept {
		if wait, ok := s.misses.Allow(s.tenant, now); !ok {
			w.Header().Set("Retry-After", ratelimit.RetryAfter(wait))
			writeJSON(w, http.StatusTooManyRequests, codeRateLimited)
			return
		}
	}
	if err := s.store.end(r.Context(), hash); err != nil {
		s.log.Warn("a session could not be ended", "tenant", s.tenant)
		writeJSON(w, http.StatusInternalServerError, codeInternal)
		return
	}
	s.known.remove(hash)
	http.SetCookie(w, authn.ClearedSessionCookie())
	w.WriteHeader(http.StatusNoContent)
}

func methodNotAllowed(w http.ResponseWriter, allow string) {
	w.Header().Set("Allow", allow)
	writeJSON(w, http.StatusMethodNotAllowed, codeMethod)
}

func writeJSON(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}

func writeUnknownLogin(w http.ResponseWriter, who subject) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": codeUnknownLogin, "issuer": who.issuer, "subject": who.subject})
}
