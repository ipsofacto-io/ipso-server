package controlplane

import (
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	// loginTTL is how long a found login is kept. A closed login is unknown on the next database
	// read. This cache may still return the principal id for a minute, and it does not keep a role
	// (ADR-0131).
	loginTTL = time.Minute
	// maxKnownLogins bounds the total cached logins across all tenants.
	maxKnownLogins = 4096
	// maxKnownLoginsPerTenant bounds one tenant's share of the cache so one tenant cannot evict
	// another tenant's hot entries (ADR-0170).
	maxKnownLoginsPerTenant = 512
)

type loginKey struct {
	scope   uuid.UUID
	issuer  string
	subject string
}

type resolvedLogin struct {
	tenant    uuid.UUID
	principal uuid.UUID
}

type cachedLogin struct {
	value resolvedLogin
	until time.Time
}

// loginCache keeps the logins that were found, partitioned by tenant with a per-tenant eviction cap.
// It never keeps a miss: a tenant may bind that login a moment later.
type loginCache struct {
	ttl          time.Duration
	max          int
	maxPerTenant int

	mu       sync.Mutex
	entries  map[loginKey]cachedLogin
	byTenant map[uuid.UUID]map[loginKey]struct{}
}

func newLoginCache(ttl time.Duration, max, maxPerTenant int) *loginCache {
	if maxPerTenant <= 0 || maxPerTenant > max {
		maxPerTenant = max
	}
	return &loginCache{
		ttl:          ttl,
		max:          max,
		maxPerTenant: maxPerTenant,
		entries:      map[loginKey]cachedLogin{},
		byTenant:     map[uuid.UUID]map[loginKey]struct{}{},
	}
}

func (c *loginCache) get(key loginKey, now time.Time) (resolvedLogin, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		return resolvedLogin{}, false
	}
	if !now.Before(entry.until) {
		c.deleteLocked(key, entry.value.tenant)
		return resolvedLogin{}, false
	}
	return entry.value, true
}

func (c *loginCache) put(key loginKey, value resolvedLogin, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	tenant := value.tenant
	if prev, kept := c.entries[key]; kept {
		if prev.value.tenant != tenant {
			c.deleteLocked(key, prev.value.tenant)
		} else {
			c.entries[key] = cachedLogin{value: value, until: now.Add(c.ttl)}
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
	c.entries[key] = cachedLogin{value: value, until: now.Add(c.ttl)}
	keys := c.byTenant[tenant]
	if keys == nil {
		keys = map[loginKey]struct{}{}
		c.byTenant[tenant] = keys
	}
	keys[key] = struct{}{}
}

func (c *loginCache) delete(key loginKey) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if entry, ok := c.entries[key]; ok {
		c.deleteLocked(key, entry.value.tenant)
	}
}

func (c *loginCache) deleteLocked(key loginKey, tenant uuid.UUID) {
	delete(c.entries, key)
	if keys := c.byTenant[tenant]; keys != nil {
		delete(keys, key)
		if len(keys) == 0 {
			delete(c.byTenant, tenant)
		}
	}
}

func (c *loginCache) pruneTenantExpiredLocked(tenant uuid.UUID, now time.Time) {
	for key := range c.byTenant[tenant] {
		if !now.Before(c.entries[key].until) {
			c.deleteLocked(key, tenant)
		}
	}
}

func (c *loginCache) pruneAllExpiredLocked(now time.Time) {
	for key, entry := range c.entries {
		if !now.Before(entry.until) {
			c.deleteLocked(key, entry.value.tenant)
		}
	}
}

func (c *loginCache) largestTenantLocked() uuid.UUID {
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

func (c *loginCache) evictOldestFromTenantLocked(tenant uuid.UUID) {
	var oldestKey loginKey
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
