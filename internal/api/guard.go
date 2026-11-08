package api

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/authn"
	"github.com/ipsofacto-io/ipso-server/internal/authz"
	"github.com/ipsofacto-io/ipso-server/internal/identity"
	"github.com/ipsofacto-io/ipso-server/internal/ratelimit"
	"github.com/ipsofacto-io/ipso-server/internal/verification"
)

// maxLoggedSubject bounds the request a log entry records.
const maxLoggedSubject = 200

// guard runs before every route, in the order that reveals least: who sent the request, whether
// that tenant has calls left, whether the query is one the route reads, whether the principal
// exists there, and whether the role policy lets it take the route's action. The body is not read
// for a caller who has not proved anything.
type guard struct {
	db         *sql.DB
	verifier   authn.Verifier
	callers    CallerFunc
	sessions   *Sessions
	uploads    *Uploads
	origin     *http.CrossOriginProtection
	limiter    *ratelimit.Limiter
	policy     *authz.Policy
	principals func(ctx context.Context, tenant, id uuid.UUID) (identity.Principal, error)
	maxBody    int64
	now        func() time.Time
	log        *slog.Logger
}

// mounted is a route on the mux, and whether a CI job calls it instead of a person.
type mounted struct {
	route
	ci bool
}

// mount puts every route on one mux and keeps each route's entry by its pattern, with the catch-all
// that answers 404. The mux holds the handlers bare: serve is the only way in, so no handler runs
// without the guard.
func mount(routes, ciRoutes []route) (*http.ServeMux, map[string]mounted) {
	mux := http.NewServeMux()
	table := make(map[string]mounted, len(routes)+len(ciRoutes)+1)
	add := func(rt route, ci bool) {
		mux.Handle(rt.pattern, rt.handler)
		table[rt.pattern] = mounted{route: rt, ci: ci}
	}
	for _, rt := range routes {
		add(rt, false)
	}
	for _, rt := range ciRoutes {
		add(rt, true)
	}
	// Anything else is 404, and only to a caller who holds a role, so the routes cannot be listed
	// without one.
	add(route{"/", "", authz.Member, nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, errNotFound)
	})}, false)
	return mux, table
}

// serve is the whole API. It finds the route the mux would run, guards the request as that route
// asks, and only then lets the mux run it. A handler that is on the mux without an entry in the table
// would run without the role policy, so it is refused: it gets no action, and no role grants none.
func (g *guard) serve(mux *http.ServeMux, table map[string]mounted) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, pattern := mux.Handler(r)
		rt, ok := table[pattern]
		if !ok {
			g.log.Error("a handler has no route entry, so it is refused", "pattern", pattern)
			rt = mounted{}
		}
		if rt.ci {
			g.guardUpload(w, r, rt.keys, mux)
			return
		}
		g.guardPerson(w, r, rt.route, mux)
	})
}

// guardPerson guards a route that a person or an agent calls, and runs next only when every check
// passed. The role check sits after the principal is confirmed and before the agent log, so a
// refused call is not logged and does not run (ADR-0090, ADR-0108).
func (g *guard) guardPerson(w http.ResponseWriter, r *http.Request, rt route, next http.Handler) {
	caller, ok := g.authenticate(w, r)
	if !ok {
		return
	}
	if wait, ok := g.limiter.Allow(caller.Tenant, g.now()); !ok {
		w.Header().Set("Retry-After", ratelimit.RetryAfter(wait))
		writeError(w, http.StatusTooManyRequests, errRateLimited)
		return
	}
	if !plainQuery(r.URL.RawQuery, rt.keys) {
		writeError(w, http.StatusBadRequest, errInvalidQuery)
		return
	}
	principal, err := g.principals(r.Context(), caller.Tenant, caller.Principal)
	if errors.Is(err, identity.ErrUnknownPrincipal) {
		writeError(w, http.StatusForbidden, errForbidden)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, errInternal)
		return
	}
	allowed, err := g.policy.Allow(r.Context(), authz.Input{Kind: principal.Kind, Grants: principal.Grants, Action: rt.action})
	if err != nil {
		g.log.Error("the role policy could not decide, so the call was refused", "tenant", caller.Tenant, "op", rt.op, "action", rt.action)
		writeError(w, http.StatusInternalServerError, errInternal)
		return
	}
	if !allowed {
		g.log.Info("the role policy refused a call", "tenant", caller.Tenant, "principal", caller.Principal, "op", rt.op, "action", rt.action)
		writeError(w, http.StatusForbidden, errForbidden)
		return
	}
	// An agent's call is logged before it runs, and the log names its sponsor (ADR-0076). A call
	// that cannot be logged does not run.
	if principal.Kind == identity.KindAgent && rt.op != "" {
		if _, err := identity.RecordAction(r.Context(), g.db, caller.Tenant, caller.Principal, "api."+rt.op, loggedSubject(r)); err != nil {
			g.log.Warn("an agent call could not be logged, so it did not run", "tenant", caller.Tenant, "op", rt.op)
			writeError(w, http.StatusInternalServerError, errInternal)
			return
		}
	}
	r.Body = http.MaxBytesReader(w, r.Body, g.maxBody)
	next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), callerKey{}, caller)))
}

// guardUpload guards the route a CI job calls. It runs in the order that reveals least and spends least
// before it knows the tenant: the bearer token, its signature, issuer and audience, then the mapping of its
// repository to a tenant, then that tenant's request budget, then the query, and only then the body. It reads
// no cookie, and there is no principal: the caller is the run, and the run is the one the signed token
// names (ADR-0102).
func (g *guard) guardUpload(w http.ResponseWriter, r *http.Request, keys []string, next http.Handler) {
	token, ok := authn.Bearer(r.Header.Get("Authorization"))
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer realm="ipso"`)
		writeError(w, http.StatusUnauthorized, errUnauthorized)
		return
	}
	claims, err := g.uploads.Verifier.VerifyRun(r.Context(), token)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="ipso", error="invalid_token"`)
		writeError(w, http.StatusUnauthorized, errUnauthorized)
		return
	}
	mapping, status := g.uploads.Lookup(r.Context(), claims)
	switch status {
	case MappingFound:
	case MappingBusy:
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusTooManyRequests, errRateLimited)
		return
	case MappingFailed:
		g.log.Warn("an upload could not be mapped to a tenant, so it was refused", "repository_id", claims.RepositoryID, "run_id", claims.RunID)
		writeError(w, http.StatusServiceUnavailable, errUnavailable)
		return
	default:
		writeError(w, http.StatusForbidden, errForbidden)
		return
	}
	if mapping.Tenant == uuid.Nil || mapping.Installation <= 0 {
		writeError(w, http.StatusForbidden, errForbidden)
		return
	}
	if wait, ok := g.limiter.Allow(mapping.Tenant, g.now()); !ok {
		w.Header().Set("Retry-After", ratelimit.RetryAfter(wait))
		writeError(w, http.StatusTooManyRequests, errRateLimited)
		return
	}
	if !plainQuery(r.URL.RawQuery, keys) {
		writeError(w, http.StatusBadRequest, errInvalidQuery)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, g.maxBody)
	ctx := context.WithValue(r.Context(), callerKey{}, Caller{Tenant: mapping.Tenant})
	ctx = context.WithValue(ctx, runKey{}, verification.Run{
		Installation: mapping.Installation,
		RepositoryID: claims.RepositoryID,
		Repo:         strings.ToLower(claims.Owner + "/" + claims.Name),
		RunID:        claims.RunID,
		RunAttempt:   claims.RunAttempt,
		SHA:          claims.SHA,
		Ref:          claims.Ref,
		Event:        claims.Event,
		WorkflowRef:  claims.WorkflowRef,
	})
	next.ServeHTTP(w, r.WithContext(ctx))
}

// authenticate answers who is calling, or writes the refusal and returns false. A request that carries
// an Authorization header is a bearer call, whatever else it carries. Without one, and only when
// sign-in is configured, the session cookie is the credential (ADR-0099).
func (g *guard) authenticate(w http.ResponseWriter, r *http.Request) (Caller, bool) {
	if g.sessions != nil && r.Header.Get("Authorization") == "" {
		return g.authenticateSession(w, r)
	}
	token, ok := authn.Bearer(r.Header.Get("Authorization"))
	if !ok {
		w.Header().Set("WWW-Authenticate", `Bearer realm="ipso"`)
		writeError(w, http.StatusUnauthorized, errUnauthorized)
		return Caller{}, false
	}
	claims, err := g.verifier.Verify(r.Context(), token)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="ipso", error="invalid_token"`)
		writeError(w, http.StatusUnauthorized, errUnauthorized)
		return Caller{}, false
	}
	caller, ok := g.callers(r.Context(), claims)
	if !ok || caller.Tenant == uuid.Nil || caller.Principal == uuid.Nil {
		writeError(w, http.StatusForbidden, errForbidden)
		return Caller{}, false
	}
	return caller, true
}

// authenticateSession checks the cookie in the order that costs least: its shape, then the origin of a
// request that could change state, and only then the store, behind the bucket that Lookup charges. A
// cookie is a credential a browser sends by itself, so the origin check is what stops another site from
// using it.
func (g *guard) authenticateSession(w http.ResponseWriter, r *http.Request) (Caller, bool) {
	token, err := authn.SessionToken(r)
	if errors.Is(err, authn.ErrNoSession) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="ipso"`)
		writeError(w, http.StatusUnauthorized, errUnauthorized)
		return Caller{}, false
	}
	if err != nil {
		return Caller{}, g.refuseSession(w)
	}
	if err := g.origin.Check(r); err != nil {
		writeError(w, http.StatusForbidden, errForbidden)
		return Caller{}, false
	}
	caller, status := g.sessions.Lookup(r.Context(), token)
	switch status {
	case SessionFound:
	case SessionBusy:
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusTooManyRequests, errRateLimited)
		return Caller{}, false
	case SessionFailed:
		g.log.Warn("a session could not be looked up, so the call was refused")
		writeError(w, http.StatusInternalServerError, errInternal)
		return Caller{}, false
	default:
		return Caller{}, g.refuseSession(w)
	}
	if caller.Tenant == uuid.Nil || caller.Principal == uuid.Nil {
		writeError(w, http.StatusForbidden, errForbidden)
		return Caller{}, false
	}
	return caller, true
}

// refuseSession answers 401 for a cookie that is no session, and clears it so the browser stops sending
// it. It returns false for the caller to return.
func (g *guard) refuseSession(w http.ResponseWriter) bool {
	http.SetCookie(w, authn.ClearedSessionCookie())
	w.Header().Set("WWW-Authenticate", `Bearer realm="ipso", error="invalid_token"`)
	writeError(w, http.StatusUnauthorized, errUnauthorized)
	return false
}

// plainQuery holds for a query the route reads as sent: it parses, no key repeats, so a second value
// cannot hide behind the first, and every key is one of the route's, so a misspelt time or limit
// cannot fall back to its default unnoticed. No route reads a tenant key, since the tenant is the
// token's.
func plainQuery(raw string, keys []string) bool {
	values, err := url.ParseQuery(raw)
	if err != nil {
		return false
	}
	for key, list := range values {
		if len(list) != 1 || !slices.Contains(keys, key) {
			return false
		}
	}
	return true
}

// loggedSubject is the request target as one bounded line. A body is never logged.
func loggedSubject(r *http.Request) string {
	cleaned := strings.Map(func(c rune) rune {
		if unicode.IsControl(c) {
			return ' '
		}
		return c
	}, r.URL.RequestURI())
	if runes := []rune(cleaned); len(runes) > maxLoggedSubject {
		return string(runes[:maxLoggedSubject])
	}
	return cleaned
}
