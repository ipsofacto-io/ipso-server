package ratelimit

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

var (
	tenantA = uuid.MustParse("00000000-0000-4000-8000-00000000000a")
	tenantB = uuid.MustParse("00000000-0000-4000-8000-00000000000b")
)

func TestLimiterRefillsAndForgetsIdleTenants(t *testing.T) {
	limiter := New(1, 1)
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, ok := limiter.Allow(tenantA, start); !ok {
		t.Fatal("the first call was refused")
	}
	wait, ok := limiter.Allow(tenantA, start)
	if ok || wait <= 0 || wait > time.Second {
		t.Fatalf("an empty bucket: wait %v, ok %v", wait, ok)
	}
	// A refused call takes nothing, so the bucket is full again a second later.
	if _, ok := limiter.Allow(tenantA, start.Add(time.Second)); !ok {
		t.Fatal("the bucket did not refill")
	}
	later := start.Add(idleTenant + time.Minute)
	if _, ok := limiter.Allow(tenantB, later); !ok {
		t.Fatal("another tenant was refused")
	}
	if _, kept := limiter.tenants[tenantA]; kept || len(limiter.tenants) != 1 {
		t.Fatalf("an idle tenant was kept: %d buckets", len(limiter.tenants))
	}
}

func TestEachLimiterKeepsItsOwnBuckets(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	api, mcp := New(1, 1), New(1, 1)
	if _, ok := api.Allow(tenantA, now); !ok {
		t.Fatal("the first call was refused")
	}
	if _, ok := api.Allow(tenantA, now); ok {
		t.Fatal("the api bucket should be empty")
	}
	if _, ok := mcp.Allow(tenantA, now); !ok {
		t.Fatal("the mcp bucket was used up by the api")
	}
}

func TestRetryAfterRoundsUpToWholeSeconds(t *testing.T) {
	for wait, want := range map[time.Duration]string{0: "1", time.Millisecond: "1", time.Second: "1", 1500 * time.Millisecond: "2", 90 * time.Second: "90"} {
		if got := RetryAfter(wait); got != want {
			t.Errorf("RetryAfter(%v) = %q, want %q", wait, got, want)
		}
	}
}
