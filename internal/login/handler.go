package login

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/ipsofacto-io/ipso-server/internal/authn"
	"github.com/ipsofacto-io/ipso-server/internal/identity"
	"github.com/ipsofacto-io/ipso-server/internal/ratelimit"
)

// The error codes of /auth. They are a closed set, like the API's. None carries what a provider sent.
const (
	codeInvalidLogin = "invalid_login"
	codeLoginRefused = "login_refused"
	// codeInvalidRequest is the answer to a request to start an invitation that is not one: another content type, a body
	// that is not the one JSON object, a field it does not name, or one over the cap.
	codeInvalidRequest = "invalid_request"
	codeUnknownLogin   = "unknown_login"
	// codeUnknownInvitation is the answer to a token the tenant holds no open invitation for: one it never made,
	// one that was used or revoked, one that expired, and a string that is not a token (ADR-0127).
	codeUnknownInvitation = "unknown_invitation"
	codeForbidden         = "forbidden"
	codeRateLimited       = "rate_limited"
	codeNotFound          = "not_found"
	codeMethod            = "method_not_allowed"
	codeInternal          = "internal"

	// maxState and maxCode bound what a callback may carry before anything reads it.
	maxState = 256
	maxCode  = 4096
	// maxSAMLBody bounds a posted assertion before it is verified.
	maxSAMLBody = 256 << 10
	// maxInvitationBody bounds the body of POST /auth/invitation/{provider}, which holds one 43 character token.
	maxInvitationBody = 1024
)

// Handler serves GET /auth/providers, /auth/login/{provider}, /auth/callback/{provider}, and POST
// /auth/invitation/{provider} and /auth/logout. Every answer
// carries no-store and no-referrer: a callback URL holds a one-time code, and none of it should be
// cached or sent on.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/providers", s.providerList)
	mux.HandleFunc("/auth/login/{provider}", s.start)
	mux.HandleFunc("/auth/invitation/{provider}", s.invite)
	mux.HandleFunc("/auth/callback/{provider}", s.callback)
	mux.HandleFunc("GET /auth/saml/{provider}/metadata", s.metadata)
	mux.HandleFunc("/auth/logout", s.logout)
	mux.HandleFunc("/auth/", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusNotFound, codeNotFound) })
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		mux.ServeHTTP(w, r)
	})
}

// listedProvider is what a sign-in page may know of a provider: the id to link to and the kind that
// says which button to draw. The issuer, the client id and the secret stay in the configuration.
type listedProvider struct {
	ID   string `json:"id"`
	Kind string `json:"kind"`
}

// providerList names the providers a person can sign in with, so the web app can link to
// /auth/login/{id} without a copy of the configuration. It needs no session, because a person who has not
// signed in has none, so a bucket of its own limits it.
func (s *Service) providerList(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	if wait, ok := s.lists.Allow(s.tenant, s.now()); !ok {
		w.Header().Set("Retry-After", ratelimit.RetryAfter(wait))
		writeJSON(w, http.StatusTooManyRequests, codeRateLimited)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Providers []listedProvider `json:"providers"`
	}{s.listed})
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
	location, ok := s.begin(w, r, id, p, "")
	if !ok {
		return
	}
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusSeeOther)
}

// begin makes the state, nonce and PKCE challenge of one sign-in, keeps what it must remember in the attempt
// cookie, and returns the address of the provider to send the browser to. invitation is the token of an
// invitation the person came with, or empty. It writes the 500 itself when it cannot.
func (s *Service) begin(w http.ResponseWriter, r *http.Request, id string, p provider, invitation string) (string, bool) {
	posted, isPosted := p.(postedLogin)
	var state string
	var err error
	if isPosted {
		state, err = xmlRequestID()
	} else {
		state, err = randomText(32)
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, codeInternal)
		return "", false
	}
	nonce, err := randomText(32)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, codeInternal)
		return "", false
	}
	verifier := oauth2.GenerateVerifier()
	begun := attempt{Provider: id, State: state, Nonce: nonce, Verifier: verifier, Invitation: invitation}
	if isPosted {
		// The posted callback does not use a nonce or a PKCE verifier. They stay non-empty so the
		// cookie still parses, and Request selects SameSite=None.
		begun.Nonce = "saml"
		begun.Verifier = "saml"
		begun.Request = "post"
	}
	// This request comes from a page of this site, so a session the browser holds is sent with it.
	if held, err := authn.SessionToken(r); err == nil {
		begun.Previous = base64.RawURLEncoding.EncodeToString(authn.SessionHash(held))
	}
	http.SetCookie(w, begun.cookie())
	location := p.authorizeURL(s.redirectURI(id), state, nonce, verifier)
	if isPosted {
		location = posted.redirect(state)
	}
	if location == "" {
		if isPosted {
			http.SetCookie(w, clearedPostedAttemptCookie())
		} else {
			http.SetCookie(w, clearedAttemptCookie())
		}
		writeJSON(w, http.StatusInternalServerError, codeInternal)
		return "", false
	}
	return location, true
}

// invitationRequest is the body of POST /auth/invitation/{provider}.
type invitationRequest struct {
	Token string `json:"token"`
}

// invite starts a sign-in that carries an invitation (ADR-0127). The link an admin hands out holds the token in
// its fragment, so no server or proxy sees it, and the page of the web app posts it here. It is a POST so the
// token is never in a URL a log keeps, and a request from another site is refused before anything is read. It
// answers where to send the browser, and not a redirect, because the policy of the app lets a form post only
// to its own origin. A token the tenant holds no open invitation for is 403 and sets no cookie, so a link that
// is used or has expired fails at once and not after a round trip to the provider. The attempt cookie keeps the
// token for the callback, which is where the invitation is used.
func (s *Service) invite(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	if err := s.check.Check(r); err != nil {
		writeJSON(w, http.StatusForbidden, codeForbidden)
		return
	}
	id := r.PathValue("provider")
	p, ok := s.providers[id]
	if !ok {
		writeJSON(w, http.StatusNotFound, codeNotFound)
		return
	}
	if mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mediaType != "application/json" {
		writeJSON(w, http.StatusUnsupportedMediaType, codeInvalidRequest)
		return
	}
	var req invitationRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxInvitationBody))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, codeInvalidRequest)
		return
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, codeInvalidRequest)
		return
	}
	if wait, ok := s.invitations.Allow(s.tenant, s.now()); !ok {
		w.Header().Set("Retry-After", ratelimit.RetryAfter(wait))
		writeJSON(w, http.StatusTooManyRequests, codeRateLimited)
		return
	}
	hash, ok := identity.InvitationHash(req.Token)
	if !ok {
		writeJSON(w, http.StatusForbidden, codeUnknownInvitation)
		return
	}
	switch err := s.store.check(r.Context(), hash); {
	case errors.Is(err, identity.ErrUnknownInvitation):
		s.log.Info("an invitation link named an invitation the tenant holds no open one for", "provider", id)
		writeJSON(w, http.StatusForbidden, codeUnknownInvitation)
		return
	case err != nil:
		s.log.Warn("an invitation could not be read", "provider", id)
		writeJSON(w, http.StatusInternalServerError, codeInternal)
		return
	}
	location, ok := s.begin(w, r, id, p, req.Token)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"location": location})
}

// callback finishes a sign-in. The checks that cost nothing come first, in the order that reveals
// least: the provider, the attempt cookie, the keys it reads, an error from the provider, the state,
// and the issuer. Only then does it spend the bucket and call the provider. The attempt cookie is
// cleared on every outcome, so a state is never used twice.
func (s *Service) callback(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("provider")
	p, ok := s.providers[id]
	if posted, isPosted := p.(postedLogin); ok && isPosted {
		http.SetCookie(w, clearedPostedAttemptCookie())
		if r.Method != http.MethodPost {
			methodNotAllowed(w, http.MethodPost)
			return
		}
		s.postedCallback(w, r, id, posted)
		return
	}
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	http.SetCookie(w, clearedAttemptCookie())
	if !ok {
		s.writeCallbackRefusal(w, r, http.StatusNotFound, codeNotFound, nil)
		return
	}
	refuse := func(reason string) {
		s.log.Warn("a sign-in was refused", "provider", id, "reason", reason)
		s.writeCallbackRefusal(w, r, http.StatusBadRequest, codeInvalidLogin, nil)
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
		s.writeCallbackRefusal(w, r, http.StatusBadRequest, codeLoginRefused, nil)
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
		s.writeCallbackRefusal(w, r, http.StatusTooManyRequests, codeRateLimited, nil)
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
		s.writeCallbackRefusal(w, r, http.StatusBadRequest, codeInvalidLogin, nil)
		return
	}

	s.finishSignIn(w, r, ctx, id, who, a, now)
}

// postedCallback finishes a SAML sign-in. The attempt cookie was cleared by the caller with
// SameSite=None. RelayState and InResponseTo are checked by the registered verifier.
func (s *Service) postedCallback(w http.ResponseWriter, r *http.Request, id string, p postedLogin) {
	refuse := func(reason string) {
		s.log.Warn("a sign-in was refused", "provider", id, "reason", reason)
		s.writeCallbackRefusal(w, r, http.StatusBadRequest, codeInvalidLogin, nil)
	}
	a, ok := readAttempt(r)
	if !ok || a.Provider != id || a.Request == "" {
		refuse("no_attempt")
		return
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxSAMLBody))
	if err != nil || len(body) == 0 {
		refuse("body")
		return
	}
	now := s.now()
	if wait, allowed := s.callbacks.Allow(s.tenant, now); !allowed {
		w.Header().Set("Retry-After", ratelimit.RetryAfter(wait))
		s.writeCallbackRefusal(w, r, http.StatusTooManyRequests, codeRateLimited, nil)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), callbackTimeout)
	defer cancel()
	who, err := p.completePOST(ctx, body, a.State)
	if err != nil {
		var f *failure
		if errors.As(err, &f) {
			s.log.Warn("a sign-in could not be completed", "provider", id, "step", f.Error())
		} else {
			s.log.Warn("a sign-in could not be completed", "provider", id)
		}
		s.writeCallbackRefusal(w, r, http.StatusBadRequest, codeInvalidLogin, nil)
		return
	}
	s.finishSignIn(w, r, ctx, id, who, a, now)
}

// finishSignIn opens the session after the provider has named a subject. It is shared by the GET
// callback and the posted one.
func (s *Service) finishSignIn(w http.ResponseWriter, r *http.Request, ctx context.Context, id string, who subject, a attempt, now time.Time) {
	previous := previousSession(r, a)
	var invitation []byte
	if a.Invitation != "" {
		var ok bool
		if invitation, ok = identity.InvitationHash(a.Invitation); !ok {
			s.log.Warn("a sign-in was refused", "provider", id, "reason", "invitation")
			s.writeCallbackRefusal(w, r, http.StatusBadRequest, codeInvalidLogin, nil)
			return
		}
	}
	token, err := authn.NewSessionToken()
	if err != nil {
		s.writeCallbackRefusal(w, r, http.StatusInternalServerError, codeInternal, nil)
		return
	}
	expires, err := s.store.start(ctx, who.issuer, who.subject, authn.SessionHash(token), previous, invitation)
	switch {
	case errors.Is(err, identity.ErrUnknownInvitation):
		s.log.Info("a sign-in carried an invitation the tenant holds no open one for", "provider", id)
		s.writeCallbackRefusal(w, r, http.StatusForbidden, codeUnknownInvitation, nil)
		return
	case errors.Is(err, identity.ErrUnknownLogin):
		s.log.Info("a sign-in named a login the tenant never bound", "provider", id)
		s.writeCallbackRefusal(w, r, http.StatusForbidden, codeUnknownLogin, &who)
		return
	case errors.Is(err, identity.ErrNotHuman):
		s.writeCallbackRefusal(w, r, http.StatusForbidden, codeForbidden, nil)
		return
	case err != nil:
		s.log.Warn("a session could not be started", "provider", id)
		s.writeCallbackRefusal(w, r, http.StatusInternalServerError, codeInternal, nil)
		return
	}
	if previous != nil {
		s.known.remove(previous)
	}
	http.SetCookie(w, authn.NewSessionCookie(token, expires, now))
	w.Header().Set("Location", "/")
	w.WriteHeader(http.StatusSeeOther)
}

func (s *Service) metadata(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("provider")
	p, ok := s.providers[id]
	posted, isPosted := p.(postedLogin)
	if !ok || !isPosted {
		writeJSON(w, http.StatusNotFound, codeNotFound)
		return
	}
	if wait, allowed := s.lists.Allow(s.tenant, s.now()); !allowed {
		w.Header().Set("Retry-After", ratelimit.RetryAfter(wait))
		writeJSON(w, http.StatusTooManyRequests, codeRateLimited)
		return
	}
	body := posted.metadata()
	if len(body) == 0 {
		writeJSON(w, http.StatusNotFound, codeNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	_, _ = io.Copy(w, strings.NewReader(string(body)))
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

// writeCallbackRefusal answers a callback that did not start a session (ADR-0130, and ADR-0131 for a posted
// callback). A browser navigation
// asks for HTML, and the only page that can explain the refusal is the app's /signin, so the answer is 303
// to that fixed path with the closed code in the fragment. The fragment is not sent on the request that
// loads the page. A client that does not ask for HTML keeps the JSON contract. Issuer and subject are added
// only for unknown_login, and they are the verified login, never a value the provider put on the query.
func (s *Service) writeCallbackRefusal(w http.ResponseWriter, r *http.Request, status int, code string, who *subject) {
	if prefersPage(r) {
		w.Header().Set("Location", signInLocation(code, who))
		w.WriteHeader(http.StatusSeeOther)
		return
	}
	if who != nil && code == codeUnknownLogin {
		writeUnknownLogin(w, *who)
		return
	}
	writeJSON(w, status, code)
}

// signInLocation is the only redirect a refusal may send. The path is fixed, so a callback cannot be turned
// into an open redirect, and the fragment carries the closed code.
func signInLocation(code string, who *subject) string {
	v := url.Values{}
	v.Set("code", code)
	if code == codeUnknownLogin && who != nil {
		v.Set("issuer", who.issuer)
		v.Set("subject", who.subject)
	}
	return "/signin#" + v.Encode()
}

// prefersPage reports whether the client asked for a page rather than the JSON contract. text/html has to be
// listed, and at a higher quality than application/json when that is listed too. An empty Accept, */* alone,
// an equal quality, or JSON ahead of HTML keeps the JSON.
func prefersPage(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	if accept == "" {
		return false
	}
	html, htmlOK := mediaQuality(accept, "text/html")
	jsonQ, jsonOK := mediaQuality(accept, "application/json")
	if !htmlOK {
		return false
	}
	if !jsonOK {
		return true
	}
	return html > jsonQ
}

// mediaQuality is the highest quality at which header lists want, or false when it does not list it at a
// quality above zero. A missing q is 1. A q outside (0, 1] is ignored.
func mediaQuality(header, want string) (float64, bool) {
	var (
		found bool
		best  float64
	)
	for _, part := range strings.Split(header, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		media, params, err := mime.ParseMediaType(part)
		if err != nil || !strings.EqualFold(media, want) {
			continue
		}
		q := 1.0
		if raw, ok := params["q"]; ok {
			parsed, err := strconv.ParseFloat(raw, 64)
			if err != nil || parsed <= 0 || parsed > 1 {
				continue
			}
			q = parsed
		}
		if !found || q > best {
			found = true
			best = q
		}
	}
	return best, found
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
