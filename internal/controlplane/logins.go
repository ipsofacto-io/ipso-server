package controlplane

import (
	"time"

	"github.com/google/uuid"
)

const (
	// loginTTL is how long a found login is kept. A login is insert-only today, so it cannot change,
	// and this is also the delay before a revocation would take effect once one exists (ADR-0093).
	loginTTL = time.Minute
	// maxKnownLogins bounds the cache.
	maxKnownLogins = 4096
)

type loginKey struct{ issuer, subject string }

// loginCache keeps the logins that were found. It never keeps a miss: the tenant may bind that login
// a moment later.
type loginCache = ttlCache[loginKey, uuid.UUID]

func newLoginCache(ttl time.Duration, max int) *loginCache {
	return newTTLCache[loginKey, uuid.UUID](ttl, max)
}
