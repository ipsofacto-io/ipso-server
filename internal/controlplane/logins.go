package controlplane

import (
	"time"

	"github.com/google/uuid"
)

const (
	// loginTTL is how long a found login is kept. A closed login is unknown on the next database
	// read. This cache may still return the principal id for a minute, and it does not keep a role
	// (ADR-0131).
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
