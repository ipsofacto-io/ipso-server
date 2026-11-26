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
	svc.resolveTenant = func(context.Context, string, string) (uuid.UUID, error) {
		calls++
		return uuid.Nil, identity.ErrAmbiguousLogin
	}
	svc.lookup = func(context.Context, uuid.UUID, string, string) (uuid.UUID, error) {
		t.Fatal("principal lookup must not run on ambiguous subject")
		return uuid.Nil, nil
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

func TestMultiTenantCallerEvictsCacheWhenLoginMovesBecomesAmbiguousOrCloses(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	tenantA, tenantB := uuid.New(), uuid.New()
	principalA, principalB := uuid.New(), uuid.New()
	svc := newService(nil, uuid.Nil, true, slog.New(slog.DiscardHandler), api.Limits{Rate: 100, Burst: 100})
	svc.now = func() time.Time { return now }

	currentTenant := tenantA
	var currentErr error
	principalReads := 0
	svc.resolveTenant = func(context.Context, string, string) (uuid.UUID, error) {
		return currentTenant, currentErr
	}
	svc.lookup = func(_ context.Context, tenant uuid.UUID, _, _ string) (uuid.UUID, error) {
		principalReads++
		switch tenant {
		case tenantA:
			return principalA, nil
		case tenantB:
			return principalB, nil
		default:
			return uuid.Nil, identity.ErrUnknownLogin
		}
	}
	claims := authn.Claims{Issuer: "https://idp.example.test", Subject: "moving-user"}

	// First two calls resolve tenant A; second call reuses cached principal without re-reading PrincipalFor.
	for range 2 {
		gotT, gotP, ok := svc.caller(t.Context(), claims)
		if !ok || gotT != tenantA || gotP != principalA {
			t.Fatalf("initial call = (%v, %v, %v), want tenant A", gotT, gotP, ok)
		}
	}
	if principalReads != 1 {
		t.Fatalf("principalReads = %d, want 1", principalReads)
	}

	// Login moves to tenant B within loginTTL: stale tenant A entry is evicted and tenant B is served immediately.
	currentTenant = tenantB
	gotT, gotP, ok := svc.caller(t.Context(), claims)
	if !ok || gotT != tenantB || gotP != principalB {
		t.Fatalf("moved call = (%v, %v, %v), want tenant B", gotT, gotP, ok)
	}
	if principalReads != 2 {
		t.Fatalf("principalReads after move = %d, want 2", principalReads)
	}

	// Second tenant also binds the subject within loginTTL: immediately refused and evicted.
	currentErr = identity.ErrAmbiguousLogin
	if gotT, gotP, ok := svc.caller(t.Context(), claims); ok || gotT != uuid.Nil || gotP != uuid.Nil {
		t.Fatalf("newly ambiguous call = (%v, %v, %v), want refused", gotT, gotP, ok)
	}

	// Re-prime tenant B, then close login: immediately refused.
	currentErr = nil
	if gotT, gotP, ok := svc.caller(t.Context(), claims); !ok || gotT != tenantB || gotP != principalB {
		t.Fatalf("re-primed call = (%v, %v, %v), want tenant B", gotT, gotP, ok)
	}
	currentErr = identity.ErrUnknownLogin
	if gotT, gotP, ok := svc.caller(t.Context(), claims); ok || gotT != uuid.Nil || gotP != uuid.Nil {
		t.Fatalf("closed call = (%v, %v, %v), want refused", gotT, gotP, ok)
	}
}
