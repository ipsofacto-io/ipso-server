// Package controlplane starts the HTTP side of the control plane: the API of ADR-0090 and, when its own
// issuer is configured, the remote MCP handler of ADR-0077 (ADR-0094). Nothing is served until the
// start gates pass, in this order: the connected role cannot bypass row-level security, the tenant has
// a row, and each authorization server answers its metadata over https.
package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso/pkg/mcptools"

	"github.com/ipsofacto-io/ipso-server/internal/api"
	"github.com/ipsofacto-io/ipso-server/internal/authn"
	"github.com/ipsofacto-io/ipso-server/internal/httpserve"
	"github.com/ipsofacto-io/ipso-server/internal/identity"
	"github.com/ipsofacto-io/ipso-server/internal/mcpremote"
	"github.com/ipsofacto-io/ipso-server/internal/ratelimit"
	"github.com/ipsofacto-io/ipso-server/internal/rls"
	"github.com/ipsofacto-io/ipso-server/internal/tenancy"
)

const (
	healthTimeout = 2 * time.Second
	healthTTL     = time.Second
)

// Config is what the control plane needs to start.
type Config struct {
	// DB connects as the application role. Start refuses a role that can bypass row-level security.
	DB *sql.DB
	// Tenant is the one tenant this process serves (single-tenant mode, ADR-0093). It must have a row.
	Tenant uuid.UUID
	// Issuer is the authorization server of the API, and Audience is what its tokens name. Audience is
	// opaque: a URL for a resource server, a client id for an issuer that mints no resource audience.
	Issuer   string
	Audience string
	// MCPIssuer and MCPResourceURL turn on the remote MCP handler. Both or neither. The issuer has to
	// offer PKCE with S256 and Client ID Metadata Documents, which an OIDC issuer such as Dex does not.
	MCPIssuer      string
	MCPResourceURL string
	// Limits bound every request of both handlers. A zero field takes its default.
	Limits api.Limits
	// Client reads the authorization servers' metadata. Default: a client with a 10 second timeout.
	Client  *http.Client
	Version string
	Log     *slog.Logger
}

// New runs the start gates and returns the handler to serve. It fails before any request is answered.
func New(ctx context.Context, cfg Config) (http.Handler, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if cfg.Log == nil {
		cfg.Log = slog.New(slog.DiscardHandler)
	}
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 10 * time.Second}
	}
	if err := rls.Check(ctx, cfg.DB); err != nil {
		return nil, err
	}
	if err := tenancy.Require(ctx, cfg.DB, cfg.Tenant); err != nil {
		return nil, err
	}

	svc := newService(cfg.DB, cfg.Tenant, cfg.Log, cfg.Limits)
	mcpOn := cfg.MCPIssuer != ""

	apiVerifier, _, err := authn.Discover(ctx, cfg.Client, cfg.Issuer, cfg.Audience)
	if err != nil {
		return nil, fmt.Errorf("the API authorization server: %w", err)
	}
	var verifier authn.Verifier = apiVerifier
	if mcpOn {
		// A token that names both resources would pass both checks, so each refuses the other's.
		verifier = authn.Exclusive(apiVerifier, cfg.MCPResourceURL)
	}
	apiHandler, err := api.New(api.Config{
		DB:       cfg.DB,
		Verifier: verifier,
		Callers: func(ctx context.Context, claims authn.Claims) (api.Caller, bool) {
			principal, ok := svc.principal(ctx, claims)
			return api.Caller{Tenant: cfg.Tenant, Principal: principal}, ok
		},
		Limits: cfg.Limits,
		Log:    cfg.Log,
	})
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", svc.health)
	// Anything else is the API's, which answers 401 before it says whether a route exists.
	mux.Handle("/", apiHandler)

	if mcpOn {
		mcpVerifier, err := mcpremote.Discover(ctx, cfg.Client, cfg.MCPIssuer, cfg.MCPResourceURL)
		if err != nil {
			return nil, fmt.Errorf("the MCP authorization server: %w", err)
		}
		mcpConfig := mcpremote.Config{
			ResourceURL:          cfg.MCPResourceURL,
			AuthorizationServers: []string{cfg.MCPIssuer},
			Version:              cfg.Version,
			Timeout:              cfg.Limits.Timeout,
			Rate:                 cfg.Limits.Rate,
			Burst:                cfg.Limits.Burst,
		}
		mcpHandler, err := mcpremote.NewHandler(mcpConfig,
			authn.Exclusive(mcpVerifier, cfg.Audience),
			func(ctx context.Context, claims authn.Claims) (mcpremote.Caller, bool) {
				principal, ok := svc.principal(ctx, claims)
				return mcpremote.Caller{Tenant: cfg.Tenant, Principal: principal}, ok
			},
			func(caller mcpremote.Caller) mcptools.Backend {
				return &mcpremote.Backend{DB: cfg.DB, Caller: caller, Now: time.Now}
			})
		if err != nil {
			return nil, err
		}
		for _, path := range mcpConfig.Paths() {
			mux.Handle(path, mcpHandler)
		}
	}
	return mux, nil
}

// Serve runs the start gates, then serves until ctx ends.
func Serve(ctx context.Context, listener net.Listener, cfg Config) error {
	handler, err := New(ctx, cfg)
	if err != nil {
		return err
	}
	return httpserve.Serve(ctx, listener, handler, nil)
}

func (c Config) validate() error {
	switch {
	case c.DB == nil:
		return errors.New("a database is required")
	case c.Tenant == uuid.Nil:
		return errors.New("a tenant is required")
	case c.Issuer == "":
		return errors.New("an issuer is required")
	case c.Audience == "":
		return errors.New("an audience is required")
	case (c.MCPIssuer == "") != (c.MCPResourceURL == ""):
		return errors.New("the MCP issuer and the MCP resource URL are set together or not at all")
	case c.MCPResourceURL != "" && c.MCPResourceURL == c.Audience:
		return errors.New("the API and the remote MCP handler need distinct audiences")
	}
	return nil
}

type service struct {
	db     *sql.DB
	tenant uuid.UUID
	log    *slog.Logger

	// lookup reads a login from the database. Tests replace it.
	lookup func(ctx context.Context, issuer, subject string) (uuid.UUID, error)
	// known keeps the logins that were found, and misses limits the lookups that reach the database
	// for a login not kept, whether or not the database knows it.
	known  *loginCache
	misses *ratelimit.Limiter
	now    func() time.Time

	// The answer of the last ping is kept for healthTTL, so a stream of health checks costs the
	// database one ping a second and not one each.
	healthMu sync.Mutex
	healthAt time.Time
	healthy  bool
}

func newService(db *sql.DB, tenant uuid.UUID, log *slog.Logger, limits api.Limits) *service {
	limits = limits.WithDefaults()
	s := &service{
		db:     db,
		tenant: tenant,
		log:    log,
		known:  newLoginCache(loginTTL, maxKnownLogins),
		misses: ratelimit.New(limits.Rate, limits.Burst),
		now:    time.Now,
	}
	s.lookup = func(ctx context.Context, issuer, subject string) (uuid.UUID, error) {
		return identity.PrincipalFor(ctx, db, tenant, issuer, subject)
	}
	return s
}

// principal is the only way a token becomes a caller: the principal this tenant bound to the token's
// issuer and subject. The tenant is the process's, never the token's or the request's.
//
// A login never changes once written, so a found one is kept for loginTTL. Every other lookup is
// charged to a bucket of the tenant before it reaches the database, so a stream of valid tokens for
// subjects the tenant never bound costs the database no more than that bucket allows. While the
// bucket is empty, a login not yet kept is refused like an unbound one.
func (s *service) principal(ctx context.Context, claims authn.Claims) (uuid.UUID, bool) {
	key := loginKey{issuer: claims.Issuer, subject: claims.Subject}
	now := s.now()
	if principal, ok := s.known.get(key, now); ok {
		return principal, true
	}
	if _, ok := s.misses.Allow(s.tenant, now); !ok {
		s.log.Warn("lookups of unknown logins are over their limit, so a login was refused", "tenant", s.tenant)
		return uuid.Nil, false
	}
	principal, err := s.lookup(ctx, claims.Issuer, claims.Subject)
	if err != nil {
		if !errors.Is(err, identity.ErrUnknownLogin) {
			s.log.Warn("a login could not be read, so the call was refused", "tenant", s.tenant)
		}
		return uuid.Nil, false
	}
	s.known.put(key, principal, now)
	return principal, true
}

// health answers 204 when the database answers. It is outside the API's guard and says nothing else.
func (s *service) health(w http.ResponseWriter, r *http.Request) {
	if !s.databaseAnswers(r.Context()) {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *service) databaseAnswers(parent context.Context) bool {
	s.healthMu.Lock()
	defer s.healthMu.Unlock()
	if !s.healthAt.IsZero() && s.now().Sub(s.healthAt) < healthTTL {
		return s.healthy
	}
	ctx, cancel := context.WithTimeout(parent, healthTimeout)
	defer cancel()
	s.healthy = s.db.PingContext(ctx) == nil
	s.healthAt = s.now()
	return s.healthy
}
