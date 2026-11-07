package controlplane

import (
	"sync"
	"time"
)

// ttlCache keeps found answers for a short time. It never keeps a miss, because the thing asked about
// may be created a moment later. A full cache is emptied, which only costs lookups.
type ttlCache[K comparable, V any] struct {
	ttl time.Duration
	max int

	mu      sync.Mutex
	entries map[K]cached[V]
}

type cached[V any] struct {
	value V
	until time.Time
}

func newTTLCache[K comparable, V any](ttl time.Duration, max int) *ttlCache[K, V] {
	return &ttlCache[K, V]{ttl: ttl, max: max, entries: map[K]cached[V]{}}
}

func (c *ttlCache[K, V]) get(key K, now time.Time) (V, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		var zero V
		return zero, false
	}
	if !now.Before(entry.until) {
		delete(c.entries, key)
		var zero V
		return zero, false
	}
	return entry.value, true
}

func (c *ttlCache[K, V]) put(key K, value V, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, kept := c.entries[key]; !kept && len(c.entries) >= c.max {
		clear(c.entries)
	}
	c.entries[key] = cached[V]{value: value, until: now.Add(c.ttl)}
}
