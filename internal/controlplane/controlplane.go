// Package controlplane starts the HTTP side of the control plane: the API of ADR-0090, the remote MCP
// handler of ADR-0077 when its own issuer is configured (ADR-0094), the browser sign-in of ADR-0099
// when providers are configured, and the web app of ADR-0106 at every other path. Nothing is served
// until the start gates pass, in this order: the connected role cannot bypass row-level security,
// either the configured tenant has a row (single-tenant mode) or the cross-tenant lookup functions
// exist (multi-tenant mode, ADR-0170), and each authorization server and sign-in provider answers
// its metadata over https.
package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso/pkg/mcptools"

	"github.com/ipsofacto-io/ipso-server/eehooks"
	"github.com/ipsofacto-io/ipso-server/internal/api"
	"github.com/ipsofacto-io/ipso-server/internal/authn"
	"github.com/ipsofacto-io/ipso-server/internal/authz"
	"github.com/ipsofacto-io/ipso-server/internal/httpserve"
	"github.com/ipsofacto-io/ipso-server/internal/identity"
	"github.com/ipsofacto-io/ipso-server/internal/llmgw"
	"github.com/ipsofacto-io/ipso-server/internal/login"
	"github.com/ipsofacto-io/ipso-server/internal/mcpremote"
	"github.com/ipsofacto-io/ipso-server/internal/ratelimit"
	"github.com/ipsofacto-io/ipso-server/internal/rls"
	"github.com/ipsofacto-io/ipso-server/internal/telemetry"
	"github.com/ipsofacto-io/ipso-server/internal/tenancy"
	"github.com/ipsofacto-io/ipso-server/internal/verification"
	"github.com/ipsofacto-io/ipso-server/internal/webapp"
	"github.com/ipsofacto-io/ipso-server/trackers"
)

const (
	healthTimeout        = 2 * time.Second
	healthTTL            = time.Second
	maxKnownPins         = 256
	maxKnownPinsPerTenant = 64
	pinCacheTTL          = 15 * time.Second
)

// Config is what the control plane needs to start.
type Config struct {
	// DB connects as the application role. Start refuses a role that can bypass row-level security.
	DB *sql.DB
	// Tenant is the one tenant this process serves in single-tenant mode (ADR-0093). It must have a
	// row. Mutually exclusive with MultiTenant.
	Tenant uuid.UUID
	// MultiTenant serves every tenant in DB by resolving each request's tenant from its verified
	// credential or stored mapping (ADR-0170). Mutually exclusive with Tenant.
	MultiTenant bool
	// Issuer is the authorization server of the API, and Audience is what its tokens name. Audience is
	// opaque: a URL for a resource server, a client id for an issuer that mints no resource audience.
	Issuer   string
	Audience string
	// MCPIssuer and MCPResourceURL turn on the remote MCP handler. Both or neither. The issuer has to
	// offer PKCE with S256 and Client ID Metadata Documents, which an OIDC issuer such as Dex does not.
	MCPIssuer      string
	MCPResourceURL string
	// PublicURL and Providers turn on browser sign-in (ADR-0099), and are set together or not at all.
	// PublicURL is the origin people reach the control plane at. Secrets reads the client secret a
	// provider names.
	PublicURL string
	Providers []login.ProviderConfig
	Secrets   func(name string) string
	// CIAudience and Repositories turn on verdict uploads (ADR-0102), and are set together or not at all.
	// CIAudience is what the OIDC tokens of CI jobs name, and it has to differ from Audience and from
	// MCPResourceURL. Repositories is the GitHub App that says which installation covers a repository.
	// CIIssuer is the issuer of those tokens, and defaults to GitHub Actions. Only a test sets it.
	CIAudience   string
	CIIssuer     string
	Repositories Repositories
	// Web is the built web app, rooted at its index.html (webapp.Files). Nil serves a sentence at the paths
	// the app would have, and logs it once at start.
	Web fs.FS
	// Limits bound every request of both handlers. A zero field takes its default.
	Limits api.Limits
	// Client reads the authorization servers' metadata. Default: a client with a 10 second timeout.
	Client  *http.Client
	Version string
	Log     *slog.Logger
	// Telemetry observes every request except /healthz (ADR-0155). Nil observes nothing.
	Telemetry *telemetry.Telemetry
	// Gateway serves tenant-opted-in LLM calls for verifiability analysis and engine: llm evaluation.
	Gateway *llmgw.Gateway
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
	if cfg.MultiTenant {
		if err := identity.RequireMultiTenantLookups(ctx, cfg.DB); err != nil {
			return nil, err
		}
		if err := verification.RequireAgentPinLookup(ctx, cfg.DB); err != nil {
			return nil, err
		}
		if cfg.CIAudience != "" {
			if err := tenancy.RequireInstallationLookup(ctx, cfg.DB); err != nil {
				return nil, err
			}
		}
	} else {
		if err := tenancy.Require(ctx, cfg.DB, cfg.Tenant); err != nil {
			return nil, err
		}
	}

	policy, err := authz.New(ctx)
	if err != nil {
		return nil, err
	}
	svc := newService(cfg.DB, cfg.Tenant, cfg.MultiTenant, cfg.Log, cfg.Limits)
	mcpOn := cfg.MCPIssuer != ""
	limits := cfg.Limits.WithDefaults()

	apiVerifier, _, err := authn.Discover(ctx, cfg.Client, cfg.Issuer, cfg.Audience)
	if err != nil {
		return nil, fmt.Errorf("the API authorization server: %w", err)
	}
	var verifier authn.Verifier = apiVerifier
	if mcpOn {
		// A token that names both resources would pass both checks, so each refuses the other's.
		verifier = authn.Exclusive(apiVerifier, cfg.MCPResourceURL)
	}
	var (
		sessions *api.Sessions
		signIn   *login.Service
	)
	if len(cfg.Providers) > 0 {
		signIn, err = login.New(ctx, login.Options{
			DB:          cfg.DB,
			Tenant:      cfg.Tenant,
			MultiTenant: cfg.MultiTenant,
			PublicURL:   cfg.PublicURL,
			Providers:   cfg.Providers,
			Secret:      cfg.Secrets,
			// An ID token must never pass as a bearer token of either handler.
			Forbidden: []string{cfg.Audience, cfg.MCPResourceURL},
			Client:    cfg.Client,
			Rate:      limits.Rate,
			Burst:     limits.Burst,
			Log:       cfg.Log,
		})
		if err != nil {
			return nil, fmt.Errorf("sign-in: %w", err)
		}
		sessions = &api.Sessions{
			Origin:    signIn.Origin(),
			Lookup:    sessionCaller(signIn, cfg.Tenant),
			LookupCLI: cliSessionCaller(signIn, cfg.Tenant),
		}
	}
	installDirectory(cfg, signIn)
	livePinCache := newKnownPinCache(maxKnownPins, maxKnownPinsPerTenant, pinCacheTTL)
	livePinMisses := ratelimit.New(limits.Rate, limits.Burst)
	liveUploads := &api.LiveUploads{
		LookupPin: func(ctx context.Context, pinHex string) (verification.AgentPin, api.SessionStatus) {
			now := time.Now()
			if pin, ok := livePinCache.get(cfg.Tenant, pinHex, now); ok {
				return pin, api.SessionFound
			}
			if _, ok := livePinMisses.Allow(cfg.Tenant, now); !ok {
				return verification.AgentPin{}, api.SessionBusy
			}
			var (
				pin verification.AgentPin
				err error
			)
			if cfg.MultiTenant {
				pin, err = verification.LookupAgentPinAnyTenant(ctx, cfg.DB, pinHex)
			} else {
				pin, err = verification.LookupAgentPin(ctx, cfg.DB, cfg.Tenant, pinHex)
			}
			if errors.Is(err, verification.ErrUnknownPin) {
				return verification.AgentPin{}, api.SessionUnknown
			}
			if err != nil {
				return verification.AgentPin{}, api.SessionFailed
			}
			livePinCache.put(cfg.Tenant, pinHex, pin, now)
			return pin, api.SessionFound
		},
		EvictPin: livePinCache.evictByID,
	}
	var uploads *api.Uploads
	if cfg.CIAudience != "" {
		if cfg.CIIssuer == "" {
			cfg.CIIssuer = authn.GitHubActionsIssuer
		}
		ciVerifier, _, err := authn.Discover(ctx, cfg.Client, cfg.CIIssuer, cfg.CIAudience)
		if err != nil {
			return nil, fmt.Errorf("the CI authorization server: %w", err)
		}
		if err := cfg.Repositories.Verify(ctx); err != nil {
			return nil, fmt.Errorf("the GitHub App: %w", err)
		}
		uploads = &api.Uploads{Verifier: ciVerifier, Lookup: newUploadMapper(cfg.DB, cfg.Tenant, cfg.Repositories, cfg.Log).lookup}
	}
	if key := eehooks.ConnectorKey(); len(key) == 32 {
		if eehooks.Allow(eehooks.FeatureTrackers) {
			eehooks.SetTrackerAdmin(trackers.NewAdmin(cfg.DB, cfg.Tenant, key))
		}
		if eehooks.Allow(eehooks.FeatureChat) {
			eehooks.SetChatAdmin(chatAdmin{db: cfg.DB, fixedTenant: cfg.Tenant, key: key})
		}
	}
	apiHandler, err := api.New(api.Config{
		DB:          cfg.DB,
		Verifier:    verifier,
		Uploads:     uploads,
		LiveUploads: liveUploads,
		Gateway:     cfg.Gateway,
		Callers: func(ctx context.Context, claims authn.Claims) (api.Caller, bool) {
			tenant, principal, ok := svc.caller(ctx, claims)
			return api.Caller{Tenant: tenant, Principal: principal}, ok
		},
		Sessions: sessions,
		Policy:   policy,
		Limits:   cfg.Limits,
		Log:      cfg.Log,
	})
	if err != nil {
		return nil, err
	}

	var web http.Handler
	if cfg.Web != nil {
		if web, err = webapp.New(cfg.Web); err != nil {
			return nil, fmt.Errorf("the web app: %w", err)
		}
	} else {
		cfg.Log.Warn("the web app is not built into this binary, so / serves a sentence and the API is served at /v1")
		web = webapp.Missing()
	}

	mux := http.NewServeMux()
	eehooks.Mount(eehooks.MountContext{
		Mux:         mux,
		Log:         cfg.Log,
		DB:          cfg.DB,
		Tenant:      cfg.Tenant,
		MultiTenant: cfg.MultiTenant,
		SetTenant:   telemetry.SetTenant,
	})
	mux.HandleFunc("GET /healthz", svc.health)
	// Every route of the API is under /v1. It answers 401 before it says whether a route exists.
	mux.Handle("/v1/", apiHandler)
	if signIn != nil {
		// Outside the API's document and its guard, like /healthz: a person who has not signed in has
		// no token to show. Remote MCP never reads the session cookie.
		mux.Handle("/auth/", telemetry.Routed(signIn.Handler()))
	} else {
		// With no provider there is no /auth, and the API's own 401 answers, as it does at /v1.
		mux.Handle("/auth/", apiHandler)
	}
	// Anything else is the web app's: a file of the build, or the page, whose router draws the view.
	mux.Handle("/", web)

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
			Telemetry:            cfg.Telemetry,
		}
		mcpHandler, err := mcpremote.NewHandler(mcpConfig,
			authn.Exclusive(mcpVerifier, cfg.Audience),
			func(ctx context.Context, claims authn.Claims) (mcpremote.Caller, bool) {
				tenant, principal, ok := svc.caller(ctx, claims)
				return mcpremote.Caller{Tenant: tenant, Principal: principal}, ok
			},
			func(caller mcpremote.Caller) mcptools.Backend {
				return &mcpremote.Backend{DB: cfg.DB, Caller: caller, Now: time.Now, Gateway: cfg.Gateway}
			},
			func(ctx context.Context, caller mcpremote.Caller, action authz.Action) (bool, error) {
				return authorize(ctx, cfg.DB, policy, caller.Tenant, caller.Principal, action)
			})
		if err != nil {
			return nil, err
		}
		for _, path := range mcpConfig.Paths() {
			mux.Handle(path, mcpHandler)
		}
	}
	return cfg.Telemetry.Handler(cfg.Tenant, mux), nil
}

// authorize reads the principal and its role bindings and asks the policy. An unknown principal is
// refused, not an error.
func authorize(ctx context.Context, db *sql.DB, policy *authz.Policy, tenant, id uuid.UUID, action authz.Action) (bool, error) {
	principal, err := identity.Get(ctx, db, tenant, id)
	if errors.Is(err, identity.ErrUnknownPrincipal) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return policy.Allow(ctx, authz.Input{Kind: principal.Kind, Grants: principal.Grants, Action: action})
}

// Serve runs the start gates, then serves until ctx ends.
func Serve(ctx context.Context, listener net.Listener, cfg Config) error {
	handler, err := New(ctx, cfg)
	if err != nil {
		return err
	}
	return httpserve.Serve(ctx, listener, handler, nil)
}

// sessionCaller adapts the sign-in's answer to the API's. When fixedTenant is non-nil (single-tenant
// mode), any other tenant is rejected as defense in depth.
func sessionCaller(signIn *login.Service, fixedTenant uuid.UUID) func(context.Context, []byte) (api.Caller, api.SessionStatus) {
	return func(ctx context.Context, token []byte) (api.Caller, api.SessionStatus) {
		tenant, principal, status := signIn.Lookup(ctx, token)
		if status != login.Found {
			return api.Caller{}, sessionStatus(status)
		}
		if tenant == uuid.Nil || (fixedTenant != uuid.Nil && tenant != fixedTenant) {
			return api.Caller{}, api.SessionUnknown
		}
		return api.Caller{Tenant: tenant, Principal: principal}, api.SessionFound
	}
}

func cliSessionCaller(signIn *login.Service, fixedTenant uuid.UUID) func(context.Context, string) (api.Caller, api.SessionStatus) {
	return func(ctx context.Context, token string) (api.Caller, api.SessionStatus) {
		tenant, principal, status := signIn.LookupCLI(ctx, token)
		if status != login.Found {
			return api.Caller{}, sessionStatus(status)
		}
		if tenant == uuid.Nil || (fixedTenant != uuid.Nil && tenant != fixedTenant) {
			return api.Caller{}, api.SessionUnknown
		}
		return api.Caller{Tenant: tenant, Principal: principal}, api.SessionFound
	}
}

func sessionStatus(status login.Status) api.SessionStatus {
	switch status {
	case login.Found:
		return api.SessionFound
	case login.Busy:
		return api.SessionBusy
	case login.Failed:
		return api.SessionFailed
	default:
		return api.SessionUnknown
	}
}

type pinCacheKey struct {
	scope  uuid.UUID
	pinHex string
}

type cachedAgentPin struct {
	pin       verification.AgentPin
	expiresAt time.Time
}

type knownPinCache struct {
	mu           sync.Mutex
	max          int
	maxPerTenant int
	ttl          time.Duration
	entries      map[pinCacheKey]cachedAgentPin
	byTenant     map[uuid.UUID]map[pinCacheKey]struct{}
}

func newKnownPinCache(max, maxPerTenant int, ttl time.Duration) *knownPinCache {
	if maxPerTenant <= 0 || maxPerTenant > max {
		maxPerTenant = max
	}
	return &knownPinCache{
		max:          max,
		maxPerTenant: maxPerTenant,
		ttl:          ttl,
		entries:      make(map[pinCacheKey]cachedAgentPin),
		byTenant:     make(map[uuid.UUID]map[pinCacheKey]struct{}),
	}
}

func (c *knownPinCache) get(scope uuid.UUID, pinHex string, now time.Time) (verification.AgentPin, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := pinCacheKey{scope: scope, pinHex: pinHex}
	entry, ok := c.entries[key]
	if !ok {
		return verification.AgentPin{}, false
	}
	if !now.Before(entry.expiresAt) {
		c.deleteLocked(key, entry.pin.Tenant)
		return verification.AgentPin{}, false
	}
	return entry.pin, true
}

func (c *knownPinCache) put(scope uuid.UUID, pinHex string, pin verification.AgentPin, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := pinCacheKey{scope: scope, pinHex: pinHex}
	tenant := pin.Tenant
	if prev, exists := c.entries[key]; exists {
		if prev.pin.Tenant != tenant {
			c.deleteLocked(key, prev.pin.Tenant)
		} else {
			c.entries[key] = cachedAgentPin{pin: pin, expiresAt: now.Add(c.ttl)}
			return
		}
	}
	if keys := c.byTenant[tenant]; len(keys) >= c.maxPerTenant {
		for k := range keys {
			if !now.Before(c.entries[k].expiresAt) {
				c.deleteLocked(k, tenant)
			}
		}
		for len(c.byTenant[tenant]) >= c.maxPerTenant {
			c.evictOldestFromTenantLocked(tenant)
		}
	}
	if len(c.entries) >= c.max {
		for k, v := range c.entries {
			if !now.Before(v.expiresAt) {
				c.deleteLocked(k, v.pin.Tenant)
			}
		}
		for len(c.entries) >= c.max {
			largest := c.largestTenantLocked()
			if largest == uuid.Nil && len(c.byTenant[uuid.Nil]) == 0 {
				break
			}
			c.evictOldestFromTenantLocked(largest)
		}
	}
	c.entries[key] = cachedAgentPin{pin: pin, expiresAt: now.Add(c.ttl)}
	keys := c.byTenant[tenant]
	if keys == nil {
		keys = make(map[pinCacheKey]struct{})
		c.byTenant[tenant] = keys
	}
	keys[key] = struct{}{}
}

func (c *knownPinCache) evictByID(id uuid.UUID) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for k, v := range c.entries {
		if v.pin.ID == id {
			c.deleteLocked(k, v.pin.Tenant)
		}
	}
}

func (c *knownPinCache) deleteLocked(key pinCacheKey, tenant uuid.UUID) {
	delete(c.entries, key)
	if keys := c.byTenant[tenant]; keys != nil {
		delete(keys, key)
		if len(keys) == 0 {
			delete(c.byTenant, tenant)
		}
	}
}

func (c *knownPinCache) largestTenantLocked() uuid.UUID {
	var best uuid.UUID
	bestCount := -1
	for tenant, keys := range c.byTenant {
		if len(keys) > bestCount {
			best = tenant
			bestCount = len(keys)
		}
	}
	return best
}

func (c *knownPinCache) evictOldestFromTenantLocked(tenant uuid.UUID) {
	var oldestKey pinCacheKey
	var oldestTime time.Time
	found := false
	for k := range c.byTenant[tenant] {
		expires := c.entries[k].expiresAt
		if !found || expires.Before(oldestTime) {
			oldestKey = k
			oldestTime = expires
			found = true
		}
	}
	if found {
		c.deleteLocked(oldestKey, tenant)
	}
}

func (c Config) validate() error {
	switch {
	case c.DB == nil:
		return errors.New("a database is required")
	case c.MultiTenant && c.Tenant != uuid.Nil:
		return errors.New("multi-tenant mode and a tenant cannot both be set")
	case !c.MultiTenant && c.Tenant == uuid.Nil:
		return errors.New("a tenant is required")
	case c.Issuer == "":
		return errors.New("an issuer is required")
	case c.Audience == "":
		return errors.New("an audience is required")
	case (c.MCPIssuer == "") != (c.MCPResourceURL == ""):
		return errors.New("the MCP issuer and the MCP resource URL are set together or not at all")
	case c.MCPResourceURL != "" && c.MCPResourceURL == c.Audience:
		return errors.New("the API and the remote MCP handler need distinct audiences")
	case (c.CIAudience == "") != (c.Repositories == nil):
		return errors.New("the CI audience and the GitHub App are set together or not at all")
	case c.CIAudience != "" && (c.CIAudience == c.Audience || c.CIAudience == c.MCPResourceURL):
		return errors.New("verdict uploads need an audience of their own, distinct from the API and the remote MCP handler")
	case (len(c.Providers) == 0) != (c.PublicURL == ""):
		return errors.New("the public URL and the login providers are set together or not at all")
	}
	return nil
}

type service struct {
	db          *sql.DB
	tenant      uuid.UUID
	multiTenant bool
	log         *slog.Logger

	// lookup reads a login from the database. Tests replace it.
	lookup func(ctx context.Context, issuer, subject string) (uuid.UUID, uuid.UUID, error)
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

func newService(db *sql.DB, tenant uuid.UUID, multiTenant bool, log *slog.Logger, limits api.Limits) *service {
	limits = limits.WithDefaults()
	s := &service{
		db:          db,
		tenant:      tenant,
		multiTenant: multiTenant,
		log:         log,
		known:       newLoginCache(loginTTL, maxKnownLogins, maxKnownLoginsPerTenant),
		misses:      ratelimit.New(limits.Rate, limits.Burst),
		now:         time.Now,
	}
	s.lookup = func(ctx context.Context, issuer, subject string) (uuid.UUID, uuid.UUID, error) {
		target := tenant
		if multiTenant {
			var err error
			target, err = identity.LoginTenant(ctx, db, issuer, subject)
			if err != nil {
				return uuid.Nil, uuid.Nil, err
			}
		}
		principal, err := identity.PrincipalFor(ctx, db, target, issuer, subject)
		if err != nil {
			return uuid.Nil, uuid.Nil, err
		}
		return target, principal, nil
	}
	return s
}

// caller is the only way a bearer token becomes a caller: the tenant and principal bound to the
// token's issuer and subject. In single-tenant mode, the tenant is the process's; in multi-tenant
// mode, the tenant comes from identity.login_tenants and an ambiguous subject bound in two or more
// tenants is refused fail-closed (ADR-0170).
//
// A closed login is unknown on the next database read. A found one is kept for loginTTL, which does
// not keep a role (ADR-0131). Every other lookup is charged to a miss bucket before it reaches the
// database, so a stream of valid tokens for unbound subjects costs the database no more than that
// bucket allows.
func (s *service) caller(ctx context.Context, claims authn.Claims) (uuid.UUID, uuid.UUID, bool) {
	key := loginKey{scope: s.tenant, issuer: claims.Issuer, subject: claims.Subject}
	now := s.now()
	if found, ok := s.known.get(key, now); ok {
		return found.tenant, found.principal, true
	}
	if _, ok := s.misses.Allow(s.tenant, now); !ok {
		s.log.Warn("lookups of unknown logins are over their limit, so a login was refused", "tenant", s.tenant)
		return uuid.Nil, uuid.Nil, false
	}
	tenant, principal, err := s.lookup(ctx, claims.Issuer, claims.Subject)
	if err != nil {
		switch {
		case errors.Is(err, identity.ErrUnknownLogin):
		case errors.Is(err, identity.ErrAmbiguousLogin):
			s.log.Info("a login is bound in several tenants, so the call was refused")
		default:
			s.log.Warn("a login could not be read, so the call was refused", "tenant", s.tenant)
		}
		return uuid.Nil, uuid.Nil, false
	}
	s.known.put(key, resolvedLogin{tenant: tenant, principal: principal}, now)
	return tenant, principal, true
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
