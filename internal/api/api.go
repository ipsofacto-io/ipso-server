// Package api is the control plane HTTP API of ADR-0090: the routes of each bounded context
// behind one chain that authenticates the caller, takes the tenant from the token, and bounds every
// request. api/openapi.yaml describes exactly the routes mounted here.
//
// ipso-server --role=api serves this handler after internal/rls.Check and the tenant check
// (ADR-0094). A token maps to a tenant and a principal only through a stored login for its issuer
// and subject (ADR-0093). Most routes read. POST /v1/verdicts stores the verdicts of a CI job, behind its
// own guard, and takes its tenant from the installation of the job's repository (ADR-0102). Every other
// route names an action, and the guard asks the role policy for it before the route runs (ADR-0108). The
// routes that write are in writes.go (ADR-0109): each is an action only a person takes, the guard reads
// the scopes the request names and has the policy cover every one, and the write and its entry in the
// action log are one transaction.
package api

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"time"

	"github.com/google/uuid"
	"golang.org/x/time/rate"

	"github.com/ipsofacto-io/ipso-server/internal/audit"
	"github.com/ipsofacto-io/ipso-server/internal/authn"
	"github.com/ipsofacto-io/ipso-server/internal/authz"
	"github.com/ipsofacto-io/ipso-server/internal/identity"
	"github.com/ipsofacto-io/ipso-server/internal/proposals"
	"github.com/ipsofacto-io/ipso-server/internal/ratelimit"
	"github.com/ipsofacto-io/ipso-server/internal/registry"
	"github.com/ipsofacto-io/ipso-server/internal/verification"
)

// Caller is who a verified token speaks for. A nil tenant or principal is refused.
type Caller struct {
	Tenant    uuid.UUID
	Principal uuid.UUID
}

// CallerFunc maps verified claims to a caller. internal/controlplane supplies it from the stored
// logins (ADR-0093). The tenant comes from here and never from the request. A false result is 403.
type CallerFunc func(context.Context, authn.Claims) (Caller, bool)

// SessionStatus is what a lookup of a session token found.
type SessionStatus int

const (
	// SessionFound means the token is an unexpired session, and the caller speaks for it.
	SessionFound SessionStatus = iota
	// SessionUnknown means the token is no session, or the session has ended. The guard answers 401 and
	// clears the cookie.
	SessionUnknown
	// SessionBusy means the process refused the lookup without asking the store, because it looks up too
	// many tokens it has not kept. The guard answers 429, not 401, so a page does not sign the person out.
	SessionBusy
	// SessionFailed means the store could not answer. The guard answers 500.
	SessionFailed
)

// Sessions turns the token of a session cookie into a caller (ADR-0099). internal/login supplies it.
type Sessions struct {
	// Origin is the origin the control plane is reached at. A request that could change state and comes
	// from another origin is refused, and this one is trusted.
	Origin string
	// Lookup returns the caller of a session token the guard has checked is well formed. The tenant is
	// the process's, never the request's.
	Lookup func(ctx context.Context, token []byte) (Caller, SessionStatus)
}

// MappingStatus is what the mapping of a CI run to its tenant found.
type MappingStatus int

const (
	// MappingFound means the repository of the run belongs to an installation of this process's tenant.
	MappingFound MappingStatus = iota
	// MappingUnknown means no installation of this tenant covers the repository. The guard answers 403.
	MappingUnknown
	// MappingBusy means the process refused the mapping without asking GitHub, because it makes too many
	// calls for repositories it has not kept. The guard answers 429.
	MappingBusy
	// MappingFailed means GitHub or the store could not answer. The guard answers 503.
	MappingFailed
)

// Mapping is the installation of the repository a CI run belongs to and the tenant that owns it.
type Mapping struct {
	Tenant       uuid.UUID
	Installation int64
}

// Uploads turns on POST /v1/verdicts (ADR-0102). Nil leaves the route unmounted, so it is an unknown route.
type Uploads struct {
	// Verifier checks the OIDC token of a CI job. A token from any other issuer fails it.
	Verifier authn.RunVerifier
	// Lookup maps a verified run to its tenant through the installation of its repository (ADR-0101). It
	// must answer MappingUnknown for a tenant other than the one this process serves. The tenant comes from
	// here and never from the request.
	Lookup func(ctx context.Context, run authn.RunClaims) (Mapping, MappingStatus)
}

// Limits bound every request. A zero field takes its default.
type Limits struct {
	// Timeout bounds a whole request, the database reads included. Default 10 seconds.
	Timeout time.Duration
	// RequestBytes bounds a request body. Default 1 MiB.
	RequestBytes int64
	// ResponseBytes bounds an answer. A larger one is refused whole, never sent cut short. Default 4 MiB.
	ResponseBytes int
	// Rate is the requests per second one tenant may make on this process. Default 10.
	Rate rate.Limit
	// Burst is how many requests one tenant may make at once. Default 20.
	Burst int
}

// WithDefaults returns the limits with every zero field set to its default.
func (l Limits) WithDefaults() Limits {
	if l.Timeout <= 0 {
		l.Timeout = 10 * time.Second
	}
	if l.RequestBytes <= 0 {
		l.RequestBytes = 1 << 20
	}
	if l.ResponseBytes <= 0 {
		l.ResponseBytes = 4 << 20
	}
	if l.Rate <= 0 {
		l.Rate = 10
	}
	if l.Burst <= 0 {
		l.Burst = 20
	}
	return l
}

// Config is what the handler needs. DB connects as the application role.
type Config struct {
	DB       *sql.DB
	Verifier authn.Verifier
	Callers  CallerFunc
	// Sessions turns on the session cookie as a second way to authenticate. Nil leaves the cookie unread,
	// so a session outlives the removal of sign-in by no time at all.
	Sessions *Sessions
	// Uploads turns on the CI upload route. The session cookie is never read on it.
	Uploads *Uploads
	// Policy is the role policy every route but the upload asks (ADR-0108). It is required.
	Policy *authz.Policy
	Limits Limits
	// Now is the clock that a read without valid or known defaults to. Default time.Now.
	Now func() time.Time
	// Log receives what an operator needs: refused answers and calls that could not be logged. It
	// never receives a token, a body, or an answer. Default discards.
	Log *slog.Logger
}

// route is one operation. op is its operationId in api/openapi.yaml and, for an agent's call, the
// action written to the log as "api." + op. action is what the guard asks the role policy for, and a
// route with none is refused to everyone. keys are the query keys it reads, the ones the document
// lists, and the guard refuses any other. targets is set on a route whose action names the scopes it
// acts on: it reads them from the request, and the guard asks the policy to cover each one (ADR-0109).
// A scoped action with no targets function is refused.
type route struct {
	pattern string
	op      string
	action  authz.Action
	keys    []string
	targets targetsFunc
	handler http.Handler
}

// New returns the API.
func New(cfg Config) (http.Handler, error) {
	g, limits, err := newGuard(cfg)
	if err != nil {
		return nil, err
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	var ci []route
	if g.uploads != nil {
		ci = ciRoutes(cfg.DB, g.log)
	}
	mux, table := mount(routes(cfg.DB, cfg.Now, g.log), ci)
	guarded := g.serve(mux, table)
	capped := bounded(guarded, limits, g.log)
	stream := streamed(guarded, limits)
	return split(mux, capped, stream), nil
}

// split sends a request that would run the archive route to stream and every other request to capped. The
// archive of an export is the one answer that is not held to the response cap and the request deadline
// (ADR-0111). The mux says which route a request would run, as the guard asks it, and both chains hold the
// same guard.
func split(mux *http.ServeMux, capped, stream http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, pattern := mux.Handler(r); pattern == archivePattern {
			stream.ServeHTTP(w, r)
			return
		}
		capped.ServeHTTP(w, r)
	})
}

// newGuard checks the configuration and builds the guard every request passes.
func newGuard(cfg Config) (*guard, Limits, error) {
	if cfg.DB == nil || cfg.Verifier == nil || cfg.Callers == nil || cfg.Policy == nil {
		return nil, Limits{}, errors.New("a database, a verifier, a caller function, and a role policy are required")
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	limits := cfg.Limits.WithDefaults()
	db := cfg.DB
	g := &guard{
		db:       db,
		verifier: cfg.Verifier,
		callers:  cfg.Callers,
		sessions: cfg.Sessions,
		limiter:  ratelimit.New(limits.Rate, limits.Burst),
		policy:   cfg.Policy,
		principals: func(ctx context.Context, tenant, id uuid.UUID) (identity.Principal, error) {
			return identity.Get(ctx, db, tenant, id)
		},
		decisionScopes: func(ctx context.Context, tenant uuid.UUID, decisions []uuid.UUID) ([]uuid.UUID, int, error) {
			return registry.DecisionScopes(ctx, db, tenant, decisions)
		},
		chains: func(ctx context.Context, tenant uuid.UUID, scopes []uuid.UUID) ([][]uuid.UUID, error) {
			return authz.Targets(ctx, db, tenant, scopes)
		},
		maxBody: limits.RequestBytes,
		now:     time.Now,
		log:     cfg.Log,
	}
	if cfg.Sessions != nil {
		if cfg.Sessions.Lookup == nil {
			return nil, Limits{}, errors.New("sessions need a lookup")
		}
		origin, err := authn.NewOriginCheck(cfg.Sessions.Origin)
		if err != nil {
			return nil, Limits{}, fmt.Errorf("sessions need an origin: %w", err)
		}
		g.origin = origin
	}
	if cfg.Uploads != nil {
		if cfg.Uploads.Verifier == nil || cfg.Uploads.Lookup == nil {
			return nil, Limits{}, errors.New("uploads need a verifier and a lookup")
		}
		g.uploads = cfg.Uploads
	}
	return g, limits, nil
}

// routes is every operation the API serves. Each reads the tenant from the caller that wrap put in
// the request context. The reads come first, and the writes of ADR-0109 after them.
func routes(db *sql.DB, now func() time.Time, log *slog.Logger) []route {
	reg := &registryRoutes{db: db, now: now}
	audits := audit.Handler(db, tenantOf)
	reviews := proposals.Handler(db, tenantOf)
	verdicts := &verdictRoutes{db: db}
	reads := []route{
		{"POST /v1/resolve", "resolve", authz.RegistryRead, nil, nil, http.HandlerFunc(reg.resolve)},
		{"GET /v1/decisions", "list_decisions", authz.RegistryRead, []string{"valid", "known", "limit", "before"}, nil, http.HandlerFunc(reg.decisions)},
		{"GET /v1/decisions/{ref}", "get_decision", authz.RegistryRead, []string{"valid", "known"}, nil, http.HandlerFunc(reg.decision)},
		{"GET /v1/scopes", "list_scopes", authz.RegistryRead, []string{"known", "limit", "before"}, nil, http.HandlerFunc(reg.scopes)},
		{"GET /v1/waivers", "list_waivers", authz.RegistryRead, []string{"valid", "known", "limit", "before"}, nil, http.HandlerFunc(reg.waivers)},
		{"GET /v1/proposals", "list_proposals", authz.ProposalsRead, []string{"limit", "before"}, nil, reviews},
		{"GET /v1/agent-proposals", "list_agent_proposals", authz.ProposalsRead, []string{"limit", "before"}, nil, reviews},
		{"GET /v1/check-proposals", "list_check_proposals", authz.ProposalsRead, []string{"limit", "before"}, nil, reviews},
		{"GET /v1/audit/decisions", "audit_decisions", authz.AuditRead, []string{"repo", "path", "env", "valid", "known"}, nil, audits},
		{"GET /v1/audit/beliefs", "audit_beliefs", authz.AuditRead, []string{"repo", "path", "env", "valid", "then", "now"}, nil, audits},
		{"GET /v1/audit/merges", "audit_merges", authz.AuditRead, []string{"repo", "path", "env", "at", "known"}, nil, audits},
		{"GET /v1/audit/supersessions/{decisionID}", "audit_supersessions", authz.AuditRead, []string{"known"}, nil, audits},
		{"GET /v1/audit/waivers", "audit_waivers", authz.AuditRead, []string{"known", "now"}, nil, audits},
		{"GET /v1/verdicts", "list_verdicts", authz.VerdictsRead, []string{"repo", "decision", "limit", "before"}, nil, http.HandlerFunc(verdicts.list)},
	}
	return slices.Concat(reads, writeRoutes(db, log), exportRoutes(db, log))
}

// ciRoutes are the operations a CI job calls with its own OIDC token instead of a person's. They are
// mounted only when uploads are on (ADR-0102). The CI identity and the installation mapping authorize
// them, not a role, so they name no action.
func ciRoutes(db *sql.DB, log *slog.Logger) []route {
	verdicts := &verdictRoutes{db: db, log: log}
	return []route{
		{"POST /v1/verdicts", "upload_verdicts", "", nil, nil, http.HandlerFunc(verdicts.upload)},
	}
}

type callerKey struct{}

// runKey carries the CI run that wrapUpload verified and mapped. Only the upload route reads it.
type runKey struct{}

// runOf is the run of an upload, as the token and the installation mapping describe it.
func runOf(r *http.Request) (verification.Run, bool) {
	run, ok := r.Context().Value(runKey{}).(verification.Run)
	return run, ok
}

// tenantOf is the TenantFunc of every route: the tenant of the authenticated caller, never one the
// request names.
func tenantOf(r *http.Request) (uuid.UUID, bool) {
	caller, ok := r.Context().Value(callerKey{}).(Caller)
	return caller.Tenant, ok && caller.Tenant != uuid.Nil
}
