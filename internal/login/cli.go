package login

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/oauth2"

	"github.com/ipsofacto-io/ipso-server/internal/authn"
	"github.com/ipsofacto-io/ipso-server/internal/identity"
	"github.com/ipsofacto-io/ipso-server/internal/ratelimit"
	"github.com/ipsofacto-io/ipso-server/internal/telemetry"
)

const (
	cliCodeTTL      = 60 * time.Second
	maxCLICodes     = 1024
	maxCLITokenBody = 4096
)

type cliCodeEntry struct {
	tenant      uuid.UUID
	issuer      string
	subject     string
	redirectURI string
	challenge   string
	expiresAt   time.Time
}

type cliCodeStore struct {
	mu      sync.Mutex
	entries map[string]cliCodeEntry
}

func newCLICodeStore() *cliCodeStore {
	return &cliCodeStore{entries: map[string]cliCodeEntry{}}
}

func (c *cliCodeStore) put(code string, entry cliCodeEntry, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, v := range c.entries {
		if !now.Before(v.expiresAt) {
			delete(c.entries, k)
		}
	}
	for len(c.entries) >= maxCLICodes {
		var oldestKey string
		var oldestTime time.Time
		for k, v := range c.entries {
			if oldestKey == "" || v.expiresAt.Before(oldestTime) {
				oldestKey = k
				oldestTime = v.expiresAt
			}
		}
		delete(c.entries, oldestKey)
	}
	c.entries[code] = entry
}

func (c *cliCodeStore) take(code string, now time.Time) (cliCodeEntry, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[code]
	if !ok {
		return cliCodeEntry{}, false
	}
	delete(c.entries, code)
	if !now.Before(entry.expiresAt) {
		return cliCodeEntry{}, false
	}
	return entry, true
}

// LookupCLI returns the tenant and principal an opaque ipsocli_ token speaks for.
func (s *Service) LookupCLI(ctx context.Context, rawToken string) (uuid.UUID, uuid.UUID, Status) {
	hash, ok := identity.CLITokenHash(rawToken)
	if !ok {
		return uuid.Nil, uuid.Nil, Unknown
	}
	now := s.now()
	if tenant, principal, ok := s.cliKnown.get(s.tenant, hash, now); ok {
		return tenant, principal, Found
	}
	if _, ok := s.misses.Allow(s.tenant, now); !ok {
		s.log.Warn("lookups of CLI sessions not kept are over their limit, so one was refused", "tenant", s.tenant)
		return uuid.Nil, uuid.Nil, Busy
	}
	tenant, principal, expires, err := s.store.cliPrincipal(ctx, hash)
	if errors.Is(err, identity.ErrUnknownCLISession) {
		return uuid.Nil, uuid.Nil, Unknown
	}
	if err != nil {
		s.log.Warn("a CLI session could not be read, so the call was refused", "tenant", s.tenant)
		return uuid.Nil, uuid.Nil, Failed
	}
	s.cliKnown.put(s.tenant, hash, tenant, principal, minTime(now.Add(sessionTTL), expires), now)
	return tenant, principal, Found
}

func validLoopbackCallback(raw string) bool {
	if raw == "" || len(raw) > 256 {
		return false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/callback" {
		return false
	}
	host, portStr, err := net.SplitHostPort(u.Host)
	if err != nil {
		return false
	}
	if host != "127.0.0.1" {
		return false
	}
	port, err := strconv.Atoi(portStr)
	return err == nil && port >= 1 && port <= 65535
}

func isBase64URLByte(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_'
}

func validBase64URLToken(s string, minLen, maxLen int) bool {
	if len(s) < minLen || len(s) > maxLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isBase64URLByte(s[i]) {
			return false
		}
	}
	return true
}

// cliStart initiates a loopback PKCE CLI login over the existing sign-in providers (ADR-0160).
func (s *Service) cliStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		methodNotAllowed(w, http.MethodGet)
		return
	}
	query := r.URL.Query()
	for _, key := range []string{"redirect_uri", "state", "code_challenge", "code_challenge_method", "provider"} {
		if len(query[key]) > 1 {
			writeJSON(w, http.StatusBadRequest, codeInvalidRequest)
			return
		}
	}
	redirectURI := query.Get("redirect_uri")
	cliState := query.Get("state")
	challenge := query.Get("code_challenge")
	method := query.Get("code_challenge_method")
	if !validLoopbackCallback(redirectURI) || cliState == "" || len(cliState) > maxState || method != "S256" || !validBase64URLToken(challenge, 43, 128) {
		writeJSON(w, http.StatusBadRequest, codeInvalidRequest)
		return
	}
	if wait, ok := s.lists.Allow(s.tenant, s.now()); !ok {
		w.Header().Set("Retry-After", ratelimit.RetryAfter(wait))
		writeJSON(w, http.StatusTooManyRequests, codeRateLimited)
		return
	}

	providerID := query.Get("provider")
	if providerID == "" {
		if len(s.listed) == 1 {
			providerID = s.listed[0].ID
		} else {
			s.writeCLIProviderPicker(w, redirectURI, cliState, challenge)
			return
		}
	}
	p, ok := s.providers[providerID]
	if !ok {
		writeJSON(w, http.StatusNotFound, codeNotFound)
		return
	}

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
		return
	}
	nonce, err := randomText(32)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, codeInternal)
		return
	}
	verifier := oauth2.GenerateVerifier()
	begun := attempt{
		Provider:     providerID,
		State:        state,
		Nonce:        nonce,
		Verifier:     verifier,
		CLIRedirect:  redirectURI,
		CLIState:     cliState,
		CLIChallenge: challenge,
	}
	if isPosted {
		begun.Nonce = "saml"
		begun.Verifier = "saml"
		begun.Request = "post"
	}
	s.clearStaleChoice(w, r)
	http.SetCookie(w, begun.cookie())
	location := p.authorizeURL(s.redirectURI(providerID), state, nonce, verifier)
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
		return
	}
	w.Header().Set("Location", location)
	w.WriteHeader(http.StatusSeeOther)
}

type cliProviderLink struct {
	Href string
	ID   string
	Kind string
}

var cliProviderPickerTmpl = template.Must(template.New("cli_picker").Parse(
	`<!doctype html><html><head><meta charset="utf-8"><title>Sign in to ipso CLI</title></head><body><h1>Sign in to ipso CLI</h1><ul>{{range .}}<li><a href="{{.Href}}">{{.ID}} ({{.Kind}})</a></li>{{end}}</ul></body></html>`,
))

func (s *Service) writeCLIProviderPicker(w http.ResponseWriter, redirectURI, state, challenge string) {
	items := make([]cliProviderLink, 0, len(s.listed))
	for _, p := range s.listed {
		v := url.Values{}
		v.Set("redirect_uri", redirectURI)
		v.Set("state", state)
		v.Set("code_challenge", challenge)
		v.Set("code_challenge_method", "S256")
		v.Set("provider", p.ID)
		items = append(items, cliProviderLink{
			Href: "/auth/cli/start?" + v.Encode(),
			ID:   p.ID,
			Kind: p.Kind,
		})
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_ = cliProviderPickerTmpl.Execute(w, items)
}

func (s *Service) finishCLISignIn(w http.ResponseWriter, r *http.Request, ctx context.Context, id string, who subject, a attempt, now time.Time) {
	if !validLoopbackCallback(a.CLIRedirect) || a.CLIState == "" || !validBase64URLToken(a.CLIChallenge, 43, 128) {
		s.writeCallbackRefusal(w, r, http.StatusBadRequest, codeInvalidLogin, nil)
		return
	}
	var tenant uuid.UUID
	if s.multiTenant {
		tenants, err := s.store.humanTenants(ctx, who.issuer, who.subject)
		switch {
		case errors.Is(err, identity.ErrUnknownLogin):
			s.log.Info("a CLI sign-in named a login the tenant never bound", "provider", id)
			s.redirectCLIError(w, a.CLIRedirect, a.CLIState, "unknown_login")
			return
		case errors.Is(err, identity.ErrNotHuman):
			s.redirectCLIError(w, a.CLIRedirect, a.CLIState, "forbidden")
			return
		case err != nil:
			s.log.Warn("a CLI login could not list tenants", "provider", id)
			s.redirectCLIError(w, a.CLIRedirect, a.CLIState, "server_error")
			return
		}
		if len(tenants) >= 2 {
			s.beginTenantChoice(w, r, ctx, id, tenants, identity.LoginChoice{
				Issuer:       who.issuer,
				Subject:      who.subject,
				CLIRedirect:  a.CLIRedirect,
				CLIState:     a.CLIState,
				CLIChallenge: a.CLIChallenge,
				IsCLI:        true,
			})
			return
		}
		tenant = tenants[0].ID
		err = s.store.cliCheckForTenant(ctx, tenant, who.issuer, who.subject)
		switch {
		case errors.Is(err, identity.ErrUnknownLogin):
			s.log.Info("a CLI sign-in named a login the tenant never bound", "provider", id)
			s.redirectCLIError(w, a.CLIRedirect, a.CLIState, "unknown_login")
			return
		case errors.Is(err, identity.ErrNotHuman):
			s.redirectCLIError(w, a.CLIRedirect, a.CLIState, "forbidden")
			return
		case err != nil:
			s.log.Warn("a CLI login could not be verified", "provider", id)
			s.redirectCLIError(w, a.CLIRedirect, a.CLIState, "server_error")
			return
		}
	} else {
		var err error
		tenant, err = s.store.cliCheck(ctx, who.issuer, who.subject)
		switch {
		case errors.Is(err, identity.ErrUnknownLogin):
			s.log.Info("a CLI sign-in named a login the tenant never bound", "provider", id)
			s.redirectCLIError(w, a.CLIRedirect, a.CLIState, "unknown_login")
			return
		case errors.Is(err, identity.ErrNotHuman), errors.Is(err, identity.ErrAmbiguousLogin):
			s.redirectCLIError(w, a.CLIRedirect, a.CLIState, "forbidden")
			return
		case err != nil:
			s.log.Warn("a CLI login could not be verified", "provider", id)
			s.redirectCLIError(w, a.CLIRedirect, a.CLIState, "server_error")
			return
		}
	}
	telemetry.SetTenant(r.Context(), tenant)
	code, err := randomText(32)
	if err != nil {
		s.redirectCLIError(w, a.CLIRedirect, a.CLIState, "server_error")
		return
	}
	s.clearStaleChoice(w, r)
	s.cliCodes.put(code, cliCodeEntry{
		tenant:      tenant,
		issuer:      who.issuer,
		subject:     who.subject,
		redirectURI: a.CLIRedirect,
		challenge:   a.CLIChallenge,
		expiresAt:   now.Add(cliCodeTTL),
	}, now)
	v := url.Values{}
	v.Set("code", code)
	v.Set("state", a.CLIState)
	w.Header().Set("Location", a.CLIRedirect+"?"+v.Encode())
	w.WriteHeader(http.StatusSeeOther)
}

func (s *Service) redirectCLIError(w http.ResponseWriter, redirectURI, state, errCode string) {
	v := url.Values{}
	v.Set("error", errCode)
	v.Set("state", state)
	w.Header().Set("Location", redirectURI+"?"+v.Encode())
	w.WriteHeader(http.StatusSeeOther)
}

// cliToken exchanges a one-time loopback authorization code and PKCE S256 verifier for a revocable CLI session token.
func (s *Service) cliToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		writeJSON(w, http.StatusUnsupportedMediaType, codeInvalidRequest)
		return
	}
	now := s.now()
	if wait, ok := s.callbacks.Allow(s.tenant, now); !ok {
		w.Header().Set("Retry-After", ratelimit.RetryAfter(wait))
		writeJSON(w, http.StatusTooManyRequests, codeRateLimited)
		return
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxCLITokenBody))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, codeInvalidRequest)
		return
	}
	form, err := url.ParseQuery(string(raw))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, codeInvalidRequest)
		return
	}
	for _, key := range []string{"grant_type", "code", "code_verifier", "redirect_uri"} {
		if len(form[key]) != 1 {
			writeJSON(w, http.StatusBadRequest, codeInvalidRequest)
			return
		}
	}
	if form.Get("grant_type") != "authorization_code" {
		writeJSON(w, http.StatusBadRequest, codeInvalidRequest)
		return
	}
	code := form.Get("code")
	verifier := form.Get("code_verifier")
	redirectURI := form.Get("redirect_uri")
	if !validBase64URLToken(code, 32, 128) || !validBase64URLToken(verifier, 43, 128) || !validLoopbackCallback(redirectURI) {
		writeJSON(w, http.StatusBadRequest, codeInvalidRequest)
		return
	}
	entry, ok := s.cliCodes.take(code, now)
	if !ok || entry.redirectURI != redirectURI {
		writeJSON(w, http.StatusBadRequest, codeInvalidLogin)
		return
	}
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(computed), []byte(entry.challenge)) != 1 {
		writeJSON(w, http.StatusBadRequest, codeInvalidLogin)
		return
	}
	token, hash, err := identity.NewCLIToken()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, codeInternal)
		return
	}
	expires, err := s.store.cliStart(r.Context(), entry.tenant, entry.issuer, entry.subject, hash)
	switch {
	case errors.Is(err, identity.ErrUnknownLogin):
		writeJSON(w, http.StatusForbidden, codeUnknownLogin)
		return
	case errors.Is(err, identity.ErrNotHuman), errors.Is(err, identity.ErrAmbiguousLogin):
		writeJSON(w, http.StatusForbidden, codeForbidden)
		return
	case err != nil:
		s.log.Warn("a CLI session could not be started")
		writeJSON(w, http.StatusInternalServerError, codeInternal)
		return
	}
	telemetry.SetTenant(r.Context(), entry.tenant)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		ExpiresAt   string `json:"expires_at"`
	}{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresAt:   expires.UTC().Format(time.RFC3339),
	})
}

// cliLogout revokes the CLI session named by the Authorization bearer token.
func (s *Service) cliLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		methodNotAllowed(w, http.MethodPost)
		return
	}
	rawToken, ok := authn.Bearer(r.Header.Get("Authorization"))
	if !ok {
		writeJSON(w, http.StatusUnauthorized, codeInvalidLogin)
		return
	}
	hash, ok := identity.CLITokenHash(rawToken)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, codeInvalidLogin)
		return
	}
	now := s.now()
	if _, _, kept := s.cliKnown.get(s.tenant, hash, now); !kept {
		if wait, ok := s.misses.Allow(s.tenant, now); !ok {
			w.Header().Set("Retry-After", ratelimit.RetryAfter(wait))
			writeJSON(w, http.StatusTooManyRequests, codeRateLimited)
			return
		}
	}
	tenant, err := s.store.cliEnd(r.Context(), hash)
	if err != nil {
		s.log.Warn("a CLI session could not be ended")
		writeJSON(w, http.StatusInternalServerError, codeInternal)
		return
	}
	if tenant != uuid.Nil {
		telemetry.SetTenant(r.Context(), tenant)
	}
	s.cliKnown.remove(s.tenant, hash)
	w.WriteHeader(http.StatusNoContent)
}
