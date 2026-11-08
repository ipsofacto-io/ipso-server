package api

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"mime"
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
	"github.com/ipsofacto-io/ipso-server/internal/registry"
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
	// decisionScopes and chains read what a scoped call acts on, and are fields so that a test can stand in
	// for the store: the scopes the decisions name and how many of them the tenant has no row for, and the
	// ancestor chains of the scopes (ADR-0109).
	decisionScopes func(ctx context.Context, tenant uuid.UUID, decisions []uuid.UUID) ([]uuid.UUID, int, error)
	chains         func(ctx context.Context, tenant uuid.UUID, scopes []uuid.UUID) ([][]uuid.UUID, error)
	maxBody        int64
	now            func() time.Time
	log            *slog.Logger
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
	add(route{"/", "", authz.Member, nil, nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
	in := authz.Input{Kind: principal.Kind, Grants: principal.Grants, Action: rt.action}
	// A scoped action reads its body before the policy can decide, because the scopes it acts on are in the
	// body. The body is read only for a principal who could take the action somewhere, and the handler gets the
	// bytes the targets were read from.
	var body []byte
	if authz.Scoped(rt.action) {
		var ok bool
		if body, ok = g.coverTargets(w, r, rt, caller, in); !ok {
			return
		}
	} else if !g.allow(w, r, rt, caller, in) {
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
	if body != nil {
		r.Body = io.NopCloser(bytes.NewReader(body))
	} else {
		r.Body = http.MaxBytesReader(w, r.Body, g.maxBody)
	}
	next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), callerKey{}, caller)))
}

// allow asks the role policy about an action that names no scope, and writes the refusal when the call may not run.
func (g *guard) allow(w http.ResponseWriter, r *http.Request, rt route, caller Caller, in authz.Input) bool {
	allowed, err := g.policy.Allow(r.Context(), in)
	if err != nil {
		g.log.Error("the role policy could not decide, so the call was refused", "tenant", caller.Tenant, "op", rt.op, "action", rt.action)
		writeError(w, http.StatusInternalServerError, errInternal)
		return false
	}
	return allowed || g.refuse(w, caller, rt)
}

// refuse writes the plain 403 of ADR-0108 and logs the refusal. It returns false for the caller to return.
func (g *guard) refuse(w http.ResponseWriter, caller Caller, rt route) bool {
	g.log.Info("the role policy refused a call", "tenant", caller.Tenant, "principal", caller.Principal, "op", rt.op, "action", rt.action)
	writeError(w, http.StatusForbidden, errForbidden)
	return false
}

// maxCallTargets bounds the scopes one call may name. A decision names at most 100, and a supersession names
// two decisions, so a call that names more is refused rather than judged in part.
const maxCallTargets = 1000

// named is what a scoped route acts on, as the request names it. root is set when the call acts on the
// tenant as a whole, such as creating an org or rejecting a proposal, which only a binding over the whole
// tenant covers.
type named struct {
	scopes    []uuid.UUID
	decisions []uuid.UUID
	root      bool
}

// targetsFunc reads from a request, after the guard has read its body whole, what the route acts on. params
// are the wildcards of the route's pattern. The handler reads the same bytes with the same decoder, so what
// the role policy covers is what the handler writes (ADR-0109).
type targetsFunc func(params map[string]string, body []byte) (named, error)

// coverTargets decides a scoped action. It asks, in the order that reveals least and spends least, whether
// the principal could take the action anywhere, which needs no body. Only then does it read the body, read
// the targets from it, turn the decisions into their scopes, read the ancestor chains, and ask the policy
// about every one, in chunks of authz.MaxTargets. It returns the body for the handler, or false after it has
// written the refusal. A route with no targets function is refused, and so is a call with no target.
func (g *guard) coverTargets(w http.ResponseWriter, r *http.Request, rt route, caller Caller, in authz.Input) ([]byte, bool) {
	ctx := r.Context()
	may, err := g.policy.MayTake(ctx, in)
	if err != nil {
		g.log.Error("the role policy could not decide, so the call was refused", "tenant", caller.Tenant, "op", rt.op, "action", rt.action)
		writeError(w, http.StatusInternalServerError, errInternal)
		return nil, false
	}
	if !may {
		return nil, g.refuse(w, caller, rt)
	}
	if rt.targets == nil {
		g.log.Error("a scoped route names no targets, so it is refused", "op", rt.op, "action", rt.action)
		return nil, g.refuse(w, caller, rt)
	}
	body, ok := g.readBody(w, r)
	if !ok {
		return nil, false
	}
	params, ok := pathParams(rt.pattern, r.URL.EscapedPath())
	if !ok {
		writeError(w, http.StatusBadRequest, errInvalidQuery)
		return nil, false
	}
	n, err := rt.targets(params, body)
	if err != nil {
		writeError(w, http.StatusBadRequest, errInvalidQuery)
		return nil, false
	}
	scopes := slices.Clone(n.scopes)
	root := n.root
	if len(n.decisions) > 0 {
		fromDecisions, missing, err := g.decisionScopes(ctx, caller.Tenant, n.decisions)
		if err != nil {
			g.log.Error("the scopes of a call could not be read, so it was refused", "tenant", caller.Tenant, "op", rt.op)
			writeError(w, http.StatusInternalServerError, errInternal)
			return nil, false
		}
		scopes = append(scopes, fromDecisions...)
		// A decision the tenant has no row for is covered by nothing but a binding over the whole tenant, so a
		// scoped principal cannot tell it from a decision outside its scope.
		root = root || missing > 0
	}
	scopes = registry.UniqueIDs(scopes)
	if len(scopes) > maxCallTargets {
		g.log.Warn("a call names too many scopes, so it was refused", "tenant", caller.Tenant, "op", rt.op, "scopes", len(scopes))
		return nil, g.refuse(w, caller, rt)
	}
	var chains [][]uuid.UUID
	if root {
		chains = append(chains, nil)
	}
	for chunk := range slices.Chunk(scopes, authz.MaxTargets) {
		read, err := g.chains(ctx, caller.Tenant, chunk)
		if err != nil {
			g.log.Error("the ancestors of a call could not be read, so it was refused", "tenant", caller.Tenant, "op", rt.op)
			writeError(w, http.StatusInternalServerError, errInternal)
			return nil, false
		}
		chains = append(chains, read...)
	}
	if len(chains) == 0 {
		return nil, g.refuse(w, caller, rt)
	}
	for chunk := range slices.Chunk(chains, authz.MaxTargets) {
		in.Targets = chunk
		allowed, err := g.policy.Allow(ctx, in)
		if err != nil {
			g.log.Error("the role policy could not decide, so the call was refused", "tenant", caller.Tenant, "op", rt.op, "action", rt.action)
			writeError(w, http.StatusInternalServerError, errInternal)
			return nil, false
		}
		if !allowed {
			return nil, g.refuse(w, caller, rt)
		}
	}
	return body, true
}

// readBody reads the whole body of a write, within the request cap. A route that takes a body takes JSON,
// and DELETE takes none. The bytes come back non-nil, so the guard knows to hand them on.
func (g *guard) readBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	if r.Method == http.MethodPost || r.Method == http.MethodPut {
		if mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type")); err != nil || mediaType != "application/json" {
			writeError(w, http.StatusUnsupportedMediaType, errUnsupportedMedia)
			return nil, false
		}
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, g.maxBody))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, errTooLarge)
		} else {
			writeError(w, http.StatusBadRequest, errInvalidQuery)
		}
		return nil, false
	}
	if data == nil {
		data = []byte{}
	}
	return data, true
}

// pathParams reads the wildcards of a route's pattern from the escaped path of a request, the way the mux
// does, so a value with an escaped slash stays one value. It reports false for a path the pattern does not
// match, which the mux would not have routed here.
func pathParams(pattern, escapedPath string) (map[string]string, bool) {
	_, pat, found := strings.Cut(pattern, " ")
	if !found {
		pat = pattern
	}
	want := strings.Split(strings.Trim(pat, "/"), "/")
	got := strings.Split(strings.Trim(escapedPath, "/"), "/")
	if len(want) != len(got) {
		return nil, false
	}
	out := make(map[string]string)
	for i, segment := range want {
		if name, ok := strings.CutPrefix(segment, "{"); ok {
			value, err := url.PathUnescape(got[i])
			if err != nil || value == "" {
				return nil, false
			}
			out[strings.TrimSuffix(name, "}")] = value
			continue
		}
		if segment != got[i] {
			return nil, false
		}
	}
	return out, true
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
