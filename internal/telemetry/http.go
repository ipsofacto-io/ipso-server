package telemetry

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
)

// healthPath is not observed, so a probe does not count against availability.
const healthPath = "/healthz"

// seen is what a request learns about itself while it runs. The route is known only to the mux that matches
// it, which can sit behind a handler that copies the request, so it is written here and read at the end. The
// first writer wins: the innermost mux finishes first and knows the most.
type seen struct {
	mu     sync.Mutex
	route  string
	tenant uuid.UUID
}

type seenKey struct{}

func seenIn(ctx context.Context) *seen {
	s, _ := ctx.Value(seenKey{}).(*seen)
	return s
}

// SetRoute records the pattern a request matched. It does nothing outside a request that Handler observes,
// and for a pattern that is empty.
func SetRoute(ctx context.Context, pattern string) {
	if s := seenIn(ctx); s != nil && pattern != "" {
		s.mu.Lock()
		if s.route == "" {
			s.route = pattern
		}
		s.mu.Unlock()
	}
}

// SetTenant records the tenant of a request that learns it after it starts, as a webhook delivery does when
// the installation is mapped.
func SetTenant(ctx context.Context, tenant uuid.UUID) {
	if s := seenIn(ctx); s != nil {
		s.mu.Lock()
		s.tenant = tenant
		s.mu.Unlock()
	}
}

// Routed records the pattern the mux inside next matched, for a mux the root mux sends a whole subtree to.
// Without it the route of a sign-in request is the subtree, and not the pattern of the request.
func Routed(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		SetRoute(r.Context(), r.Pattern)
	})
}

// Handler observes every request next serves: a server span named for the method and the route, and the
// duration of the request. tenant is the tenant the process serves, or uuid.Nil for a process that has none.
// Every request starts a trace of its own. A traceparent from the caller is not read, because these are
// public endpoints and nothing here is propagated on.
func (t *Telemetry) Handler(tenant uuid.UUID, next http.Handler) http.Handler {
	if !t.on() {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == healthPath {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		s := &seen{tenant: tenant}
		ctx, span := t.tracer.Start(context.WithValue(r.Context(), seenKey{}, s), methodOf(r.Method),
			trace.WithSpanKind(trace.SpanKindServer), trace.WithNewRoot())
		sw := &statusWriter{ResponseWriter: w}
		served := r.WithContext(ctx)
		panicked := true
		defer func() {
			status := sw.status
			if status == 0 {
				status = http.StatusOK
			}
			failure := ""
			switch {
			case panicked:
				status, failure = http.StatusInternalServerError, "panic"
			case status >= 500:
				failure = strconv.Itoa(status)
			}
			s.mu.Lock()
			route, id := s.route, s.tenant
			s.mu.Unlock()
			if route == "" {
				route = served.Pattern
			}
			route = routeOf(route)
			method := methodOf(r.Method)
			attrs := []attribute.KeyValue{KeyMethod.String(method), KeyRoute.String(route), KeyStatus.Int(status)}
			attrs = withTenant(attrs, id)
			if failure != "" {
				attrs = append(attrs, KeyError.String(failure))
				span.SetStatus(codes.Error, "")
			}
			span.SetName(method + " " + route)
			span.SetAttributes(attrs...)
			t.http.Record(ctx, time.Since(start).Seconds(), metric.WithAttributes(attrs...))
			span.End()
		}()
		next.ServeHTTP(sw, served)
		panicked = false
	})
}

// methodOf keeps the standard methods and gives every other the value the conventions name for it.
func methodOf(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodConnect, http.MethodOptions, http.MethodTrace:
		return method
	}
	return "_OTHER"
}

// routeOf is the path of a pattern. A pattern may start with a method, which is its own attribute, and an
// unmatched request has none.
func routeOf(pattern string) string {
	if _, path, ok := strings.Cut(pattern, " "); ok {
		pattern = path
	}
	if pattern == "" {
		return "_unmatched"
	}
	return pattern
}

func withTenant(attrs []attribute.KeyValue, tenant uuid.UUID) []attribute.KeyValue {
	if tenant == uuid.Nil {
		return attrs
	}
	return append(attrs, KeyTenant.String(tenant.String()))
}

// statusWriter keeps the status of the answer. Unwrap lets http.NewResponseController reach the writer
// below, which the export archive needs to flush.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	// A 1xx answer is followed by the real one, except 101 which ends the exchange.
	if w.status == 0 && (code >= 200 || code == http.StatusSwitchingProtocols) {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
