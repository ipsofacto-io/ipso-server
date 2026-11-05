package controlplane

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	// loginTTL is how long a found login is kept. A login is insert-only today, so it cannot change,
	// and this is also the delay before a revocation would take effect once one exists (ADR-0093).
	loginTTL = time.Minute
	// maxKnownLogins bounds the cache. A full cache is emptied, which only costs lookups.
	maxKnownLogins = 4096
)

type loginKey struct{ issuer, subject string }

type cachedLogin struct {
	principal uuid.UUID
	until     time.Time
}

// loginCache keeps the logins that were found. It never keeps a miss: the tenant may bind that login
// a moment later.
type loginCache struct {
	ttl time.Duration
	max int

	mu      sync.Mutex
	entries map[loginKey]cachedLogin
}

func newLoginCache(ttl time.Duration, max int) *loginCache {
	return &loginCache{ttl: ttl, max: max, entries: map[loginKey]cachedLogin{}}
}

func (c *loginCache) get(key loginKey, now time.Time) (uuid.UUID, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
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

func (c *loginCache) put(key loginKey, principal uuid.UUID, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, kept := c.entries[key]; !kept && len(c.entries) >= c.max {
		clear(c.entries)
	}
	c.entries[key] = cachedLogin{principal: principal, until: now.Add(c.ttl)}
}
