package api

import (
	"bytes"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"golang.org/x/time/rate"
)

// idleTenant is how long a tenant's bucket is kept without a request. A bucket idle that long has
// refilled, so dropping it changes no answer and keeps the map to the tenants that are calling.
const idleTenant = 10 * time.Minute

// tenantLimiter is a token bucket for each tenant on this process. A deployment with several api
// processes adds the shared limit at its front (ADR-0090).
type tenantLimiter struct {
	rate  rate.Limit
	burst int

	mu      sync.Mutex
	tenants map[uuid.UUID]*tenantBucket
	swept   time.Time
}

type tenantBucket struct {
	limiter *rate.Limiter
	seen    time.Time
}

func newTenantLimiter(r rate.Limit, burst int) *tenantLimiter {
	return &tenantLimiter{rate: r, burst: burst, tenants: map[uuid.UUID]*tenantBucket{}}
}

// allow takes one call from the tenant's bucket. When the bucket is empty, it returns how long until
// the next call would be allowed.
func (l *tenantLimiter) allow(tenant uuid.UUID, now time.Time) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.swept) > idleTenant {
		for id, bucket := range l.tenants {
			if now.Sub(bucket.seen) > idleTenant {
				delete(l.tenants, id)
			}
		}
		l.swept = now
	}
	bucket, ok := l.tenants[tenant]
	if !ok {
		bucket = &tenantBucket{limiter: rate.NewLimiter(l.rate, l.burst)}
		l.tenants[tenant] = bucket
	}
	bucket.seen = now
	reservation := bucket.limiter.ReserveN(now, 1)
	if wait := reservation.DelayFrom(now); wait > 0 {
		reservation.CancelAt(now)
		return wait, false
	}
	return 0, true
}

// bounded gives every request a deadline and holds every answer until it is complete. An answer
// over the cap is refused whole with 500 and never sent cut short, so an audit answer cannot be
// mistaken for a complete one (ADR-0055). A request past its deadline is 503.
func bounded(next http.Handler, limits Limits, log *slog.Logger) http.Handler {
	capped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		answer := &cappedWriter{header: http.Header{}, max: limits.ResponseBytes}
		next.ServeHTTP(answer, r)
		if answer.over {
			log.Warn("an answer was over the response cap and was refused", "path", r.URL.Path, "cap", limits.ResponseBytes)
			writeError(w, http.StatusInternalServerError, errResponseTooLarge)
			return
		}
		for key, values := range answer.header {
			w.Header()[key] = values
		}
		if answer.status == 0 {
			answer.status = http.StatusOK
		}
		w.WriteHeader(answer.status)
		_, _ = w.Write(answer.body.Bytes())
	})
	timed := http.TimeoutHandler(capped, limits.Timeout, errorJSON(errTimeout))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// TimeoutHandler writes its own answer on a timeout and copies the route's headers otherwise,
		// so these are the timeout answer's headers.
		setJSONHeaders(w.Header())
		timed.ServeHTTP(w, r)
	})
}

var errOverCap = errors.New("the answer is over the response cap")

// cappedWriter keeps an answer of up to max bytes and drops the rest.
type cappedWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
	max    int
	over   bool
}

func (c *cappedWriter) Header() http.Header { return c.header }

func (c *cappedWriter) WriteHeader(status int) {
	if c.status == 0 {
		c.status = status
	}
}

func (c *cappedWriter) Write(p []byte) (int, error) {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	if c.over || c.body.Len()+len(p) > c.max {
		c.over = true
		return 0, errOverCap
	}
	return c.body.Write(p)
}
