// Package ratelimit is the per-tenant token bucket that the HTTP handlers of the control plane share.
// Each handler holds its own Limiter, so a tenant's calls to the API do not use up its calls to the
// remote MCP handler.
package ratelimit

import (
	"math"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/time/rate"
)

// idleTenant is how long a tenant's bucket is kept without a request. A bucket idle that long has
// refilled, so dropping it changes no answer and keeps the map to the tenants that are calling.
const idleTenant = 10 * time.Minute

// Limiter is a token bucket for each tenant on this process. A deployment with several processes adds
// the shared limit at its front (ADR-0090).
type Limiter struct {
	rate  rate.Limit
	burst int

	mu      sync.Mutex
	tenants map[uuid.UUID]*bucket
	swept   time.Time
}

type bucket struct {
	limiter *rate.Limiter
	seen    time.Time
}

// New returns a Limiter that lets each tenant make r calls a second, with burst calls at once.
func New(r rate.Limit, burst int) *Limiter {
	return &Limiter{rate: r, burst: burst, tenants: map[uuid.UUID]*bucket{}}
}

// RetryAfter is the value of a Retry-After header for a wait: whole seconds, rounded up, and at least
// one, so a client never retries into the same refusal.
func RetryAfter(wait time.Duration) string {
	return strconv.Itoa(max(1, int(math.Ceil(wait.Seconds()))))
}

// Allow takes one call from the tenant's bucket. When the bucket is empty, it returns how long until
// the next call would be allowed.
func (l *Limiter) Allow(tenant uuid.UUID, now time.Time) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.swept) > idleTenant {
		for id, b := range l.tenants {
			if now.Sub(b.seen) > idleTenant {
				delete(l.tenants, id)
			}
		}
		l.swept = now
	}
	b, ok := l.tenants[tenant]
	if !ok {
		b = &bucket{limiter: rate.NewLimiter(l.rate, l.burst)}
		l.tenants[tenant] = b
	}
	b.seen = now
	reservation := b.limiter.ReserveN(now, 1)
	if wait := reservation.DelayFrom(now); wait > 0 {
		reservation.CancelAt(now)
		return wait, false
	}
	return 0, true
}
