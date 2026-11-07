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

	"github.com/ipsofacto-io/ipso-server/internal/authn"
	"github.com/ipsofacto-io/ipso-server/internal/identity"
	"github.com/ipsofacto-io/ipso-server/internal/ratelimit"
)

const (
	// sessionTTL is how long a session found in the database is kept in memory. It is also the delay
	// before a logout on another process, or a future revocation of a login, takes effect (ADR-0093).
	sessionTTL = time.Minute
	// maxKnownSessions bounds the cache. A full cache is emptied, which only costs lookups.
	maxKnownSessions = 4096
	callbackTimeout  = 10 * time.Second
)

// Options are what the sign-in needs to start.
type Options struct {
	// DB connects as the application role.
	DB *sql.DB
	// Tenant is the one tenant this process serves. A session belongs to it (ADR-0093, ADR-0099).
	Tenant uuid.UUID
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
	// Rate and Burst limit the lookups a tenant's process makes for a session it has not kept, and its
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
	start(ctx context.Context, issuer, subject string, hash, previous []byte) (time.Time, error)
	principal(ctx context.Context, hash []byte) (uuid.UUID, time.Time, error)
	end(ctx context.Context, hash []byte) error
}

type dbStore struct {
	db     *sql.DB
	tenant uuid.UUID
}

func (s dbStore) start(ctx context.Context, issuer, subject string, hash, previous []byte) (time.Time, error) {
	return identity.StartSession(ctx, s.db, s.tenant, issuer, subject, hash, previous)
}

func (s dbStore) principal(ctx context.Context, hash []byte) (uuid.UUID, time.Time, error) {
	return identity.SessionPrincipal(ctx, s.db, s.tenant, hash)
}

func (s dbStore) end(ctx context.Context, hash []byte) error {
	return identity.EndSession(ctx, s.db, s.tenant, hash)
}

// Service signs people in and answers whether a session cookie is one.
type Service struct {
	tenant    uuid.UUID
	origin    string
	check     *http.CrossOriginProtection
	providers map[string]provider
	// listed is what /auth/providers answers: the id and kind of each provider, by id.
	listed []listedProvider
	store  store
	log    *slog.Logger
	now    func() time.Time

	known *sessionCache
	// misses charges the lookups of a session this process has not kept, and callbacks charges each
	// code exchange. Both are per process, like the API's own limit.
	misses    *ratelimit.Limiter
	callbacks *ratelimit.Limiter
	// lists charges GET /auth/providers, which needs no session, in a bucket of its own: a client that
	// reads the list must not be able to spend the callbacks' bucket and stop people signing in.
	lists *ratelimit.Limiter
}

// New validates the configuration, discovers every OpenID Connect provider, and returns the service.
// It fails when a provider cannot be reached, so a process does not start with a login that does not
// work.
func New(ctx context.Context, opts Options) (*Service, error) {
	if opts.store == nil {
		if opts.DB == nil {
			return nil, errors.New("a database is required")
		}
		opts.store = dbStore{db: opts.DB, tenant: opts.Tenant}
	}
	if opts.Tenant == uuid.Nil {
		return nil, errors.New("a tenant is required")
	}
	if opts.Secret == nil {
		opts.Secret = func(string) string { return "" }
	}
	if opts.Log == nil {
		opts.Log = slog.New(slog.DiscardHandler)
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
		tenant:    opts.Tenant,
		origin:    origin,
		check:     check,
		providers: providers,
		listed:    listed,
		store:     opts.store,
		log:       opts.Log,
		now:       opts.Now,
		known:     newSessionCache(sessionTTL, maxKnownSessions),
		misses:    ratelimit.New(opts.Rate, opts.Burst),
		callbacks: ratelimit.New(opts.Rate, opts.Burst),
		lists:     ratelimit.New(opts.Rate, opts.Burst),
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

// Lookup returns the principal a session token speaks for. A token found is kept for a minute or until
// the session ends, whichever is first. Every other lookup is charged to a bucket of the tenant before
// it reaches the database, so a stream of random cookies, which no signature rules out the way it does
// for a bearer token, costs the database no more than the bucket allows (ADR-0090 point 5, ADR-0099).
func (s *Service) Lookup(ctx context.Context, token []byte) (uuid.UUID, Status) {
	hash := authn.SessionHash(token)
	now := s.now()
	if principal, ok := s.known.get(hash, now); ok {
		return principal, Found
	}
	if _, ok := s.misses.Allow(s.tenant, now); !ok {
		s.log.Warn("lookups of sessions not kept are over their limit, so one was refused", "tenant", s.tenant)
		return uuid.Nil, Busy
	}
	principal, expires, err := s.store.principal(ctx, hash)
	if errors.Is(err, identity.ErrUnknownSession) {
		return uuid.Nil, Unknown
	}
	if err != nil {
		s.log.Warn("a session could not be read, so the call was refused", "tenant", s.tenant)
		return uuid.Nil, Failed
	}
	s.known.put(hash, principal, minTime(now.Add(sessionTTL), expires))
	return principal, Found
}

func minTime(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

func (s *Service) redirectURI(id string) string {
	return fmt.Sprintf("%s/auth/callback/%s", s.origin, id)
}

type cachedSession struct {
	principal uuid.UUID
	until     time.Time
}

// sessionCache keeps the sessions that were found. It never keeps a miss.
type sessionCache struct {
	ttl time.Duration
	max int

	mu      sync.Mutex
	entries map[[authn.SessionTokenSize]byte]cachedSession
}

func newSessionCache(ttl time.Duration, max int) *sessionCache {
	return &sessionCache{ttl: ttl, max: max, entries: map[[authn.SessionTokenSize]byte]cachedSession{}}
}

func (c *sessionCache) get(hash []byte, now time.Time) (uuid.UUID, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := [authn.SessionTokenSize]byte(hash)
	entry, ok := c.entries[key]
	if !ok {
		return uuid.Nil, false
	}
	if !now.Before(entry.until) {
		delete(c.entries, key)
		return uuid.Nil, false
	}
	return entry.principal, true
}

func (c *sessionCache) put(hash []byte, principal uuid.UUID, until time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := [authn.SessionTokenSize]byte(hash)
	if _, kept := c.entries[key]; !kept && len(c.entries) >= c.max {
		clear(c.entries)
	}
	c.entries[key] = cachedSession{principal: principal, until: until}
}

func (c *sessionCache) remove(hash []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, [authn.SessionTokenSize]byte(hash))
}
