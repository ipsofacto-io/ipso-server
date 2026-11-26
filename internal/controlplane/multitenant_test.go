package controlplane

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/api"
	"github.com/ipsofacto-io/ipso-server/internal/authn"
	"github.com/ipsofacto-io/ipso-server/internal/identity"
	"github.com/ipsofacto-io/ipso-server/internal/verification"
)

func TestLoginCachePerTenantEvictionCapIsolatesTenants(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	tenantA := uuid.New()
	tenantB := uuid.New()
	principalB := uuid.New()

	cache := newLoginCache(time.Minute, 10, 4)
	keyB := loginKey{scope: uuid.Nil, issuer: "https://idp.example.test", subject: "user-b"}
	cache.put(keyB, resolvedLogin{tenant: tenantB, principal: principalB}, now)

	for i := range 20 {
		keyA := loginKey{scope: uuid.Nil, issuer: "https://idp.example.test", subject: fmt.Sprintf("user-a-%d", i)}
		cache.put(keyA, resolvedLogin{tenant: tenantA, principal: uuid.New()}, now.Add(time.Duration(i)*time.Millisecond))
	}

	got, ok := cache.get(keyB, now)
	if !ok || got.tenant != tenantB || got.principal != principalB {
		t.Fatalf("tenant A flood evicted tenant B login: ok=%v got=%+v", ok, got)
	}
	if countA := len(cache.byTenant[tenantA]); countA > 4 {
		t.Fatalf("tenant A holds %d entries, want at most 4", countA)
	}
}

func TestKnownPinCachePerTenantEvictionCapAndEvictByID(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	tenantA := uuid.New()
	tenantB := uuid.New()
	pinBID := uuid.New()

	cache := newKnownPinCache(10, 4, time.Minute)
	cache.put(uuid.Nil, "pin-b", verification.AgentPin{ID: pinBID, Tenant: tenantB}, now)

	for i := range 20 {
		cache.put(uuid.Nil, fmt.Sprintf("pin-a-%d", i), verification.AgentPin{ID: uuid.New(), Tenant: tenantA}, now.Add(time.Duration(i)*time.Millisecond))
	}
	if got, ok := cache.get(uuid.Nil, "pin-b", now); !ok || got.ID != pinBID {
		t.Fatalf("tenant A flood evicted tenant B pin: ok=%v got=%+v", ok, got)
	}
	cache.evictByID(pinBID)
	if _, ok := cache.get(uuid.Nil, "pin-b", now); ok {
		t.Fatal("evictByID did not remove tenant B pin")
	}
}

func TestMultiTenantCallerRefusesAmbiguousSubjectFailClosed(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	svc := newService(nil, uuid.Nil, true, slog.New(slog.DiscardHandler), api.Limits{Rate: 100, Burst: 100})
	svc.now = func() time.Time { return now }
	calls := 0
	svc.lookup = func(context.Context, string, string) (uuid.UUID, uuid.UUID, error) {
		calls++
		return uuid.Nil, uuid.Nil, identity.ErrAmbiguousLogin
	}
	claims := authn.Claims{Issuer: "https://idp.example.test", Subject: "shared-user"}
	for range 2 {
		if tenant, principal, ok := svc.caller(t.Context(), claims); ok || tenant != uuid.Nil || principal != uuid.Nil {
			t.Fatalf("ambiguous caller = (%v, %v, %v), want refused", tenant, principal, ok)
		}
	}
	if calls != 2 {
		t.Fatalf("ambiguous miss should not be cached: calls=%d, want 2", calls)
	}
}
