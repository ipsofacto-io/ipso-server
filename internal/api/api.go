// Package api is the control plane HTTP API of ADR-0090: the read routes of each bounded context
// behind one chain that authenticates the caller, takes the tenant from the token, and bounds every
// request. api/openapi.yaml describes exactly the routes mounted here.
//
// The binary does not serve this handler. Row-level security is in place (IPSO-61, ADR-0050).
// A token maps to a tenant and a principal only once login exists (IPSO-65), and IPSO-133
// serves this handler with --role=api after internal/rls.Check. Every route reads. No endpoint
// writes before authorization (IPSO-66).
package api

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/google/uuid"
	"golang.org/x/time/rate"

	"github.com/ipsofacto-io/ipso-server/internal/audit"
	"github.com/ipsofacto-io/ipso-server/internal/authn"
	"github.com/ipsofacto-io/ipso-server/internal/proposals"
)

// Caller is who a verified token speaks for. A nil tenant or principal is refused.
type Caller struct {
	Tenant    uuid.UUID
	Principal uuid.UUID
}

// CallerFunc maps verified claims to a caller. The mapping belongs to the login work (IPSO-65). The
// tenant comes from here and never from the request. A false result is 403.
type CallerFunc func(context.Context, authn.Claims) (Caller, bool)

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

func (l Limits) withDefaults() Limits {
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
	Limits   Limits
	// Now is the clock that a read without valid or known defaults to. Default time.Now.
	Now func() time.Time
	// Log receives what an operator needs: refused answers and calls that could not be logged. It
	// never receives a token, a body, or an answer. Default discards.
	Log *slog.Logger
}

// route is one operation. op is its operationId in api/openapi.yaml and, for an agent's call, the
// action written to the log as "api." + op. keys are the query keys it reads, the ones the document
// lists, and the guard refuses any other.
type route struct {
	pattern string
	op      string
	keys    []string
	handler http.Handler
}

// New returns the API.
func New(cfg Config) (http.Handler, error) {
	if cfg.DB == nil || cfg.Verifier == nil || cfg.Callers == nil {
		return nil, errors.New("a database, a verifier, and a caller function are required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	limits := cfg.Limits.withDefaults()
	g := &guard{
		db:       cfg.DB,
		verifier: cfg.Verifier,
		callers:  cfg.Callers,
		limiter:  newTenantLimiter(limits.Rate, limits.Burst),
		maxBody:  limits.RequestBytes,
		now:      time.Now,
		log:      cfg.Log,
	}
	mux := http.NewServeMux()
	for _, rt := range routes(cfg.DB, cfg.Now) {
		mux.Handle(rt.pattern, g.wrap(rt.op, rt.keys, rt.handler))
	}
	// Anything else is 404, and only to a caller with a token, so the routes cannot be listed without one.
	mux.Handle("/", g.wrap("", nil, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeError(w, http.StatusNotFound, errNotFound)
	})))
	return bounded(mux, limits, cfg.Log), nil
}

// routes is every operation the API serves. Each reads the tenant from the caller that wrap put in
// the request context.
func routes(db *sql.DB, now func() time.Time) []route {
	reg := &registryRoutes{db: db, now: now}
	audits := audit.Handler(db, tenantOf)
	reviews := proposals.Handler(db, tenantOf)
	return []route{
		{"POST /v1/resolve", "resolve", nil, http.HandlerFunc(reg.resolve)},
		{"GET /v1/decisions", "list_decisions", []string{"valid", "known", "limit", "before"}, http.HandlerFunc(reg.decisions)},
		{"GET /v1/decisions/{ref}", "get_decision", []string{"valid", "known"}, http.HandlerFunc(reg.decision)},
		{"GET /v1/scopes", "list_scopes", []string{"known", "limit", "before"}, http.HandlerFunc(reg.scopes)},
		{"GET /v1/waivers", "list_waivers", []string{"valid", "known", "limit", "before"}, http.HandlerFunc(reg.waivers)},
		{"GET /v1/proposals", "list_proposals", []string{"limit", "before"}, reviews},
		{"GET /v1/agent-proposals", "list_agent_proposals", []string{"limit", "before"}, reviews},
		{"GET /v1/check-proposals", "list_check_proposals", []string{"limit", "before"}, reviews},
		{"GET /v1/audit/decisions", "audit_decisions", []string{"repo", "path", "env", "valid", "known"}, audits},
		{"GET /v1/audit/beliefs", "audit_beliefs", []string{"repo", "path", "env", "valid", "then", "now"}, audits},
		{"GET /v1/audit/merges", "audit_merges", []string{"repo", "path", "env", "at", "known"}, audits},
		{"GET /v1/audit/supersessions/{decisionID}", "audit_supersessions", []string{"known"}, audits},
		{"GET /v1/audit/waivers", "audit_waivers", []string{"known", "now"}, audits},
	}
}

type callerKey struct{}

// tenantOf is the TenantFunc of every route: the tenant of the authenticated caller, never one the
// request names.
func tenantOf(r *http.Request) (uuid.UUID, bool) {
	caller, ok := r.Context().Value(callerKey{}).(Caller)
	return caller.Tenant, ok && caller.Tenant != uuid.Nil
}
