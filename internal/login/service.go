package login

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/time/rate"

	"github.com/ipsofacto-io/ipso-server/eehooks"
	"github.com/ipsofacto-io/ipso-server/internal/authn"
	"github.com/ipsofacto-io/ipso-server/internal/identity"
	"github.com/ipsofacto-io/ipso-server/internal/ratelimit"
)

const (
	// sessionTTL is how long a session found in the database is kept in memory. A closed login is
	// unknown on the next database read. The cache may still name the principal for this long, and
	// it does not keep a role (ADR-0131).
	sessionTTL = time.Minute
	// maxKnownSessions bounds the total cache entries across all tenants.
	maxKnownSessions = 4096
	// maxKnownSessionsPerTenant bounds one tenant's share of the cache so one tenant cannot evict
	// another tenant's hot entries (ADR-0170).
	maxKnownSessionsPerTenant = 512
	callbackTimeout           = 10 * time.Second
)

// Options are what the sign-in needs to start.
type Options struct {
	// DB connects as the application role.
	DB *sql.DB
	// Tenant is the one tenant this process serves in single-tenant mode (ADR-0093, ADR-0099).
	// Mutually exclusive with MultiTenant.
	Tenant uuid.UUID
	// MultiTenant enables multi-tenant mode where sessions, logins, and invitations resolve their
	// tenant from verified credentials through narrow SECURITY DEFINER lookups (ADR-0170).
	MultiTenant bool
	// PublicURL is the origin people reach the control plane at, such as https://ipso.example.com.
	PublicURL string
	// Providers are the ways to sign in.
	Providers []ProviderConfig
	// Secret reads a client secret by the name a provider gives. Default: no secrets, which fails.
	Secret func(name string) string
	// Forbidden are the audiences of the API and of remote MCP. A client id may not equal one.
	Forbidden []string
	// Client reaches the providers. Its redirects are never followed. Default: a 10 second timeout.
	Client *http.Client
	// Rate and Burst limit the lookups a process makes for a session it has not kept, and its
	// callbacks. Zero takes 10 a second with a burst of 20, the API's limit.
	Rate  rate.Limit
	Burst int
	Log   *slog.Logger
	Now   func() time.Time

	// store replaces the database in tests.
	store store
}

// store is the part of the database a session uses.
type store interface {
	// start opens a session and returns its verified tenant and expiry. invitation is the hash of the
	// invitation the sign-in carries, or nil: with one, a login that is not bound yet is bound to the
	// person the invitation names (ADR-0127).
	start(ctx context.Context, issuer, subject string, hash, previous, invitation []byte) (uuid.UUID, time.Time, error)
	// check says whether an open invitation with this hash exists and returns its tenant, changing nothing.
	check(ctx context.Context, invitation []byte) (uuid.UUID, error)
	principal(ctx context.Context, hash []byte) (uuid.UUID, uuid.UUID, time.Time, error)
	end(ctx context.Context, hash []byte) (uuid.UUID, error)
	cliCheck(ctx context.Context, issuer, subject string) (uuid.UUID, error)
	cliStart(ctx context.Context, tenant uuid.UUID, issuer, subject string, hash []byte) (time.Time, error)
	cliPrincipal(ctx context.Context, hash []byte) (uuid.UUID, uuid.UUID, time.Time, error)
	cliEnd(ctx context.Context, hash []byte) (uuid.UUID, error)
}

type dbStore struct {
	db          *sql.DB
	tenant      uuid.UUID
	multiTenant bool
	log         *slog.Logger
}

func (s dbStore) start(ctx context.Context, issuer, subject string, hash, previous, invitation []byte) (uuid.UUID, time.Time, error) {
	if !s.multiTenant {
		var expires time.Time
		var err error
		if invitation != nil {
			expires, err = identity.AcceptInvitation(ctx, s.db, s.tenant, issuer, subject, invitation, hash, previous)
		} else {
			expires, err = identity.StartSession(ctx, s.db, s.tenant, issuer, subject, hash, previous)
		}
		if err != nil {
			return uuid.Nil, time.Time{}, err
		}
		return s.tenant, expires, nil
	}

	var target uuid.UUID
	var err error
	if invitation != nil {
		var ok bool
		target, ok, err = identity.InvitationTenant(ctx, s.db, invitation)
		if err != nil {
			return uuid.Nil, time.Time{}, err
		}
		if !ok {
			return uuid.Nil, time.Time{}, identity.ErrUnknownInvitation
		}
	} else {
		target, err = identity.LoginTenant(ctx, s.db, issuer, subject)
		if err != nil {
			return uuid.Nil, time.Time{}, err
		}
	}

	sameTenantPrevious := previous
	var crossTenant uuid.UUID
	if previous != nil {
		prevTenant, ok, err := identity.SessionTenant(ctx, s.db, previous)
		if err != nil {
			return uuid.Nil, time.Time{}, err
		}
		if ok && prevTenant != target {
			sameTenantPrevious = nil
			crossTenant = prevTenant
		} else if !ok {
			sameTenantPrevious = nil
		}
	}

	var expires time.Time
	if invitation != nil {
		expires, err = identity.AcceptInvitation(ctx, s.db, target, issuer, subject, invitation, hash, sameTenantPrevious)
	} else {
		expires, err = identity.StartSession(ctx, s.db, target, issuer, subject, hash, sameTenantPrevious)
	}
	if err != nil {
		return uuid.Nil, time.Time{}, err
	}
	if crossTenant != uuid.Nil {
		if err := identity.EndSession(ctx, s.db, crossTenant, previous); err != nil && s.log != nil {
			s.log.Warn("a previous session in another tenant could not be ended after sign-in", "tenant", crossTenant)
		}
	}
	return target, expires, nil
}

func (s dbStore) check(ctx context.Context, invitation []byte) (uuid.UUID, error) {
	if !s.multiTenant {
		if err := identity.CheckInvitation(ctx, s.db, s.tenant, invitation); err != nil {
			return uuid.Nil, err
		}
		return s.tenant, nil
	}
	tenant, ok, err := identity.InvitationTenant(ctx, s.db, invitation)
	if err != nil {
		return uuid.Nil, err
	}
	if !ok {
		return uuid.Nil, identity.ErrUnknownInvitation
	}
	if err := identity.CheckInvitation(ctx, s.db, tenant, invitation); err != nil {
		return uuid.Nil, err
	}
	return tenant, nil
}

func (s dbStore) principal(ctx context.Context, hash []byte) (uuid.UUID, uuid.UUID, time.Time, error) {
	tenant := s.tenant
	if s.multiTenant {
		var ok bool
		var err error
		tenant, ok, err = identity.SessionTenant(ctx, s.db, hash)
		if err != nil {
			return uuid.Nil, uuid.Nil, time.Time{}, err
		}
		if !ok {
			return uuid.Nil, uuid.Nil, time.Time{}, identity.ErrUnknownSession
		}
	}
	principal, expires, err := identity.SessionPrincipal(ctx, s.db, tenant, hash)
	if err != nil {
		return uuid.Nil, uuid.Nil, time.Time{}, err
	}
	return tenant, principal, expires, nil
}

func (s dbStore) end(ctx context.Context, hash []byte) (uuid.UUID, error) {
	tenant := s.tenant
	if s.multiTenant {
		var ok bool
		var err error
		tenant, ok, err = identity.SessionTenant(ctx, s.db, hash)
		if err != nil {
			return uuid.Nil, err
		}
		if !ok {
			return uuid.Nil, nil
		}
	}
	if err := identity.EndSession(ctx, s.db, tenant, hash); err != nil {
		return uuid.Nil, err
	}
	return tenant, nil
}

func (s dbStore) cliCheck(ctx context.Context, issuer, subject string) (uuid.UUID, error) {
	tenant := s.tenant
	if s.multiTenant {
		var err error
		tenant, err = identity.LoginTenant(ctx, s.db, issuer, subject)
		if err != nil {
			return uuid.Nil, err
		}
	}
	if err := identity.CheckHumanLogin(ctx, s.db, tenant, issuer, subject); err != nil {
		return uuid.Nil, err
	}
	return tenant, nil
}

func (s dbStore) cliStart(ctx context.Context, tenant uuid.UUID, issuer, subject string, hash []byte) (time.Time, error) {
	if !s.multiTenant {
		if tenant != s.tenant {
			return time.Time{}, fmt.Errorf("%w: tenant mismatch", identity.ErrInvalidQuery)
		}
		tenant = s.tenant
	} else if tenant == uuid.Nil {
		return time.Time{}, fmt.Errorf("%w: a tenant is required", identity.ErrInvalidQuery)
	}
	return identity.StartCLISession(ctx, s.db, tenant, issuer, subject, hash)
}

func (s dbStore) cliPrincipal(ctx context.Context, hash []byte) (uuid.UUID, uuid.UUID, time.Time, error) {
	tenant := s.tenant
	if s.multiTenant {
		var ok bool
		var err error
		tenant, ok, err = identity.CLISessionTenant(ctx, s.db, hash)
		if err != nil {
			return uuid.Nil, uuid.Nil, time.Time{}, err
		}
		if !ok {
			return uuid.Nil, uuid.Nil, time.Time{}, identity.ErrUnknownCLISession
		}
	}
	principal, expires, err := identity.CLISessionPrincipal(ctx, s.db, tenant, hash)
	if err != nil {
		return uuid.Nil, uuid.Nil, time.Time{}, err
	}
	return tenant, principal, expires, nil
}

func (s dbStore) cliEnd(ctx context.Context, hash []byte) (uuid.UUID, error) {
	tenant := s.tenant
	if s.multiTenant {
		var ok bool
		var err error
		tenant, ok, err = identity.CLISessionTenant(ctx, s.db, hash)
		if err != nil {
			return uuid.Nil, err
		}
		if !ok {
			return uuid.Nil, nil
		}
	}
	if err := identity.EndCLISession(ctx, s.db, tenant, hash); err != nil {
		return uuid.Nil, err
	}
	return tenant, nil
}

// Service signs people in and answers whether a session cookie is one.
type Service struct {
	tenant      uuid.UUID
	multiTenant bool
	origin      string
	check       *http.CrossOriginProtection
	providers   map[string]provider
	// listed is what /auth/providers answers: the id and kind of each provider, by id.
	listed []listedProvider
	store  store
	log    *slog.Logger
	now    func() time.Time

	known    *sessionCache
	cliKnown *sessionCache
	cliCodes *cliCodeStore
	// misses charges the lookups of a session this process has not kept, and callbacks charges each
	// code exchange. Both are keyed by s.tenant (fixed tenant in single-tenant, uuid.Nil process-wide
	// in multi-tenant).
	misses    *ratelimit.Limiter
	callbacks *ratelimit.Limiter
	// lists charges GET /auth/providers, which needs no session, in a bucket of its own: a client that
	// reads the list must not be able to spend the callbacks' bucket and stop people signing in.
	lists *ratelimit.Limiter
	// invitations charges POST /auth/invitation/{provider}, which needs no session and reads the database for
	// each token it is given, in a bucket of its own so that guessing tokens cannot stop people signing in.
	invitations *ratelimit.Limiter
}

// New validates the configuration, discovers every OpenID Connect provider, and returns the service.
// It fails when a provider cannot be reached, so a process does not start with a login that does not
// work.
func New(ctx context.Context, opts Options) (*Service, error) {
	if opts.Log == nil {
		opts.Log = slog.New(slog.DiscardHandler)
	}
	if opts.MultiTenant && opts.Tenant != uuid.Nil {
		return nil, errors.New("multi-tenant mode and a tenant cannot both be set")
	}
	if !opts.MultiTenant && opts.Tenant == uuid.Nil {
		return nil, errors.New("a tenant is required")
	}
	if opts.store == nil {
		if opts.DB == nil {
			return nil, errors.New("a database is required")
		}
		opts.store = dbStore{db: opts.DB, tenant: opts.Tenant, multiTenant: opts.MultiTenant, log: opts.Log}
	}
	if opts.Secret == nil {
		opts.Secret = func(string) string { return "" }
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Rate <= 0 {
		opts.Rate = 10
	}
	if opts.Burst <= 0 {
		opts.Burst = 20
	}
	if opts.Client == nil {
		opts.Client = &http.Client{Timeout: 10 * time.Second}
	}
	origin, err := CanonicalOrigin(opts.PublicURL)
	if err != nil {
		return nil, err
	}
	check, err := authn.NewOriginCheck(origin)
	if err != nil {
		return nil, err
	}
	if err := validate(opts.Providers, opts.Forbidden, opts.Secret); err != nil {
		return nil, err
	}
	// A provider's answer that redirects is an answer this process does not follow.
	client := *opts.Client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	providers := map[string]provider{}
	listed := make([]listedProvider, 0, len(opts.Providers))
	for _, cfg := range opts.Providers {
		if factory, ok := eehooks.LookupKind(cfg.Kind); ok {
			if !eehooks.Allow(eehooks.FeatureSAML) {
				opts.Log.Warn("sso.saml is not granted, so the provider is not mounted", "provider", cfg.ID)
				continue
			}
			browser, err := factory(ctx, eehooks.KindConfig{
				ID:          cfg.ID,
				MetadataURL: cfg.MetadataURL,
				ACS:         fmt.Sprintf("%s/auth/callback/%s", origin, cfg.ID),
				EntityID:    cfg.ClientID,
				Client:      &client,
			})
			if err != nil {
				return nil, err
			}
			providers[cfg.ID] = newSAML(browser)
			listed = append(listed, listedProvider{ID: cfg.ID, Kind: cfg.Kind})
			continue
		}
		secret := opts.Secret(cfg.ClientSecretEnv)
		switch cfg.Kind {
		case KindOIDC:
			p, err := newOIDC(ctx, &client, cfg, secret)
			if err != nil {
				return nil, err
			}
			providers[cfg.ID] = p
		case KindGitHub:
			providers[cfg.ID] = newGitHub(&client, cfg, secret)
		}
		listed = append(listed, listedProvider{ID: cfg.ID, Kind: cfg.Kind})
	}
	slices.SortFunc(listed, func(a, b listedProvider) int { return strings.Compare(a.ID, b.ID) })
	return &Service{
		tenant:      opts.Tenant,
		multiTenant: opts.MultiTenant,
		origin:      origin,
		check:       check,
		providers:   providers,
		listed:      listed,
		store:       opts.store,
		log:         opts.Log,
		now:         opts.Now,
		known:       newSessionCache(sessionTTL, maxKnownSessions, maxKnownSessionsPerTenant),
		cliKnown:    newSessionCache(sessionTTL, maxKnownSessions, maxKnownSessionsPerTenant),
		cliCodes:    newCLICodeStore(),
		misses:      ratelimit.New(opts.Rate, opts.Burst),
		callbacks:   ratelimit.New(opts.Rate, opts.Burst),
		lists:       ratelimit.New(opts.Rate, opts.Burst),
		invitations: ratelimit.New(opts.Rate, opts.Burst),
	}, nil
}

// Origin is the canonical public origin. The cross-origin check trusts it.
func (s *Service) Origin() string { return s.origin }

// Status is the answer of Lookup.
type Status int

const (
	// Found means the token is an unexpired session.
	Found Status = iota
	// Unknown means it is not, or it has expired.
	Unknown
	// Busy means this process is looking up too many sessions it has not kept, and refused this one
	// without asking the database. It says nothing about the token.
	Busy
	// Failed means the database could not answer.
	Failed
)

// Lookup returns the tenant and principal a session token speaks for. A token found is kept for a
// minute or until the session ends, whichever is first. Every other lookup is charged to a miss
// bucket before it reaches the database, so a stream of random cookies, which no signature rules out
// the way it does for a bearer token, costs the database no more than the bucket allows
// (ADR-0090 point 5, ADR-0099, ADR-0170).
func (s *Service) Lookup(ctx context.Context, token []byte) (uuid.UUID, uuid.UUID, Status) {
	hash := authn.SessionHash(token)
	now := s.now()
	if tenant, principal, ok := s.known.get(s.tenant, hash, now); ok {
		return tenant, principal, Found
	}
	if _, ok := s.misses.Allow(s.tenant, now); !ok {
		s.log.Warn("lookups of sessions not kept are over their limit, so one was refused", "tenant", s.tenant)
		return uuid.Nil, uuid.Nil, Busy
	}
	tenant, principal, expires, err := s.store.principal(ctx, hash)
	if errors.Is(err, identity.ErrUnknownSession) {
		return uuid.Nil, uuid.Nil, Unknown
	}
	if err != nil {
		s.log.Warn("a session could not be read, so the call was refused", "tenant", s.tenant)
		return uuid.Nil, uuid.Nil, Failed
	}
	s.known.put(s.tenant, hash, tenant, principal, minTime(now.Add(sessionTTL), expires), now)
	return tenant, principal, Found
}

func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

// EnterpriseIssuer is the issuer of the one mounted SAML provider. Zero or several means SCIM
// stays unmounted (ADR-0131).
func (s *Service) EnterpriseIssuer() (string, bool) {
	var issuer string
	n := 0
	for _, p := range s.providers {
		posted, ok := p.(postedLogin)
		if !ok {
			continue
		}
		n++
		issuer = posted.idpIssuer()
	}
	if n != 1 || issuer == "" {
		return "", false
	}
	return issuer, true
}

func (s *Service) redirectURI(id string) string {
	return fmt.Sprintf("%s/auth/callback/%s", s.origin, id)
}

type sessionCacheKey struct {
	scope uuid.UUID
	hash  [authn.SessionTokenSize]byte
}

type cachedSession struct {
	tenant    uuid.UUID
	principal uuid.UUID
	until     time.Time
}

// sessionCache keeps the sessions that were found, partitioned by tenant with a per-tenant cap so
// one tenant cannot evict another tenant's hot entries. It never keeps a miss.
type sessionCache struct {
	ttl          time.Duration
	max          int
	maxPerTenant int

	mu       sync.Mutex
	entries  map[sessionCacheKey]cachedSession
	byTenant map[uuid.UUID]map[sessionCacheKey]struct{}
}

func newSessionCache(ttl time.Duration, max, maxPerTenant int) *sessionCache {
	if maxPerTenant <= 0 || maxPerTenant > max {
		maxPerTenant = max
	}
	return &sessionCache{
		ttl:          ttl,
		max:          max,
		maxPerTenant: maxPerTenant,
		entries:      map[sessionCacheKey]cachedSession{},
		byTenant:     map[uuid.UUID]map[sessionCacheKey]struct{}{},
	}
}

func (c *sessionCache) get(scope uuid.UUID, hash []byte, now time.Time) (uuid.UUID, uuid.UUID, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := sessionCacheKey{scope: scope, hash: [authn.SessionTokenSize]byte(hash)}
	entry, ok := c.entries[key]
	if !ok {
		return uuid.Nil, uuid.Nil, false
	}
	if !now.Before(entry.until) {
		c.deleteLocked(key, entry.tenant)
		return uuid.Nil, uuid.Nil, false
	}
	return entry.tenant, entry.principal, true
}

func (c *sessionCache) put(scope uuid.UUID, hash []byte, tenant, principal uuid.UUID, until, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := sessionCacheKey{scope: scope, hash: [authn.SessionTokenSize]byte(hash)}
	if prev, kept := c.entries[key]; kept {
		if prev.tenant != tenant {
			c.deleteLocked(key, prev.tenant)
		} else {
			c.entries[key] = cachedSession{tenant: tenant, principal: principal, until: until}
			return
		}
	}
	if keys := c.byTenant[tenant]; len(keys) >= c.maxPerTenant {
		c.pruneTenantExpiredLocked(tenant, now)
		for len(c.byTenant[tenant]) >= c.maxPerTenant {
			c.evictOldestFromTenantLocked(tenant)
		}
	}
	if len(c.entries) >= c.max {
		c.pruneAllExpiredLocked(now)
		for len(c.entries) >= c.max {
			largest := c.largestTenantLocked()
			if largest == uuid.Nil && len(c.byTenant[uuid.Nil]) == 0 {
				break
			}
			c.evictOldestFromTenantLocked(largest)
		}
	}
	c.entries[key] = cachedSession{tenant: tenant, principal: principal, until: until}
	keys := c.byTenant[tenant]
	if keys == nil {
		keys = map[sessionCacheKey]struct{}{}
		c.byTenant[tenant] = keys
	}
	keys[key] = struct{}{}
}

func (c *sessionCache) remove(scope uuid.UUID, hash []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := sessionCacheKey{scope: scope, hash: [authn.SessionTokenSize]byte(hash)}
	if entry, ok := c.entries[key]; ok {
		c.deleteLocked(key, entry.tenant)
	}
}

func (c *sessionCache) deleteLocked(key sessionCacheKey, tenant uuid.UUID) {
	delete(c.entries, key)
	if keys := c.byTenant[tenant]; keys != nil {
		delete(keys, key)
		if len(keys) == 0 {
			delete(c.byTenant, tenant)
		}
	}
}

func (c *sessionCache) pruneTenantExpiredLocked(tenant uuid.UUID, now time.Time) {
	for key := range c.byTenant[tenant] {
		if !now.Before(c.entries[key].until) {
			c.deleteLocked(key, tenant)
		}
	}
}

func (c *sessionCache) pruneAllExpiredLocked(now time.Time) {
	for key, entry := range c.entries {
		if !now.Before(entry.until) {
			c.deleteLocked(key, entry.tenant)
		}
	}
}

func (c *sessionCache) largestTenantLocked() uuid.UUID {
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

func (c *sessionCache) evictOldestFromTenantLocked(tenant uuid.UUID) {
	var oldestKey sessionCacheKey
	var oldestUntil time.Time
	found := false
	for key := range c.byTenant[tenant] {
		until := c.entries[key].until
		if !found || until.Before(oldestUntil) {
			oldestKey = key
			oldestUntil = until
			found = true
		}
	}
	if found {
		c.deleteLocked(oldestKey, tenant)
	}
}
