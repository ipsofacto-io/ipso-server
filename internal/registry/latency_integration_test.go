//go:build integration

package registry

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
)

const (
	decisionsPerTenant = 10_000
	warmUpCalls        = 50
	timedCalls         = 500
	p95Budget          = 20 * time.Millisecond
)

// seeded describes the scope tree that seedTenant built, so the test can pick subjects that match it.
type seeded struct {
	repos []seededRepo
}

type seededRepo struct {
	name string
	dir  string
}

// seedTenant writes a tree of 1 org, 10 domains, 50 services, 400 literal repos, 100 glob repos
// and 800 paths, then 10k current decisions that each name two scopes, then updates every
// decision once so that the history table holds 10k closed rows as well.
func seedTenant(t *testing.T, r registryDB, tenant uuid.UUID) seeded {
	t.Helper()
	org := r.scope(t, tenant, uuid.Nil, "org", "acme")
	all := []uuid.UUID{org}

	domains := make([]uuid.UUID, 10)
	for i := range domains {
		domains[i] = r.scope(t, tenant, org, "domain", fmt.Sprintf("domain-%d", i))
	}
	services := make([]uuid.UUID, 50)
	for i := range services {
		services[i] = r.scope(t, tenant, domains[i%len(domains)], "service", fmt.Sprintf("service-%d", i))
	}
	all = append(all, domains...)
	all = append(all, services...)

	var s seeded
	repos := make([]uuid.UUID, 400)
	for i := range repos {
		name := fmt.Sprintf("acme/repo-%d", i)
		repos[i] = r.scope(t, tenant, services[i%len(services)], "repo", name)
		s.repos = append(s.repos, seededRepo{name: name, dir: fmt.Sprintf("dir%d", i%200)})
	}
	all = append(all, repos...)
	for i := range 100 {
		all = append(all, r.scope(t, tenant, org, "repo", fmt.Sprintf("acme/team%d-*", i)))
	}
	for i := range 800 {
		all = append(all, r.scope(t, tenant, repos[i%len(repos)], "path", fmt.Sprintf("dir%d/**", i%200)))
	}
	for _, env := range []string{"prod", "staging", "dev"} {
		all = append(all, r.scope(t, tenant, org, "env", env))
	}

	// Two scopes per decision, spread over the whole tree.
	_, err := r.app.ExecContext(t.Context(), `
		INSERT INTO registry.decision_version (decision_id, version, tenant_id, body, scope_refs, valid_period)
		SELECT gen_random_uuid(), 1, $1::uuid, jsonb_build_object('n', g),
		       ARRAY[($2::uuid[])[1 + (g * 7) % cardinality($2::uuid[])],
		             ($2::uuid[])[1 + (g * 13) % cardinality($2::uuid[])]],
		       '[2026-01-01,)'
		FROM generate_series(1, $3::int) AS g`, tenant, all, decisionsPerTenant)
	if err != nil {
		t.Fatalf("seed decisions: %v", err)
	}
	if _, err := r.app.ExecContext(t.Context(), `UPDATE registry.decision_version SET body = body || '{"revised": true}' WHERE tenant_id = $1`, tenant); err != nil {
		t.Fatalf("seed history: %v", err)
	}
	return s
}

// The acceptance criterion of IPSO-23: resolution under 20 ms p95 at 10k decisions. The tenant
// that is queried holds 10k current and 10k history rows, and a second tenant holds the same, so
// the indexes have to separate them.
func TestResolveP95UnderBudgetAt10kDecisions(t *testing.T) {
	r := newRegistryDB(t)
	a := seedTenant(t, r, tenantA)
	seedTenant(t, r, tenantB)

	for _, table := range []string{"scope", "scope_history", "scope_closure", "scope_closure_history", "decision_version", "decision_version_history"} {
		if _, err := r.admin.ExecContext(t.Context(), `ANALYZE registry.`+table); err != nil {
			t.Fatal(err)
		}
	}
	var current, history int
	if err := r.admin.QueryRowContext(t.Context(), `
		SELECT (SELECT count(*) FROM registry.decision_version WHERE tenant_id = $1),
		       (SELECT count(*) FROM registry.decision_version_history WHERE tenant_id = $1)`, tenantA).Scan(&current, &history); err != nil {
		t.Fatal(err)
	}
	if current != decisionsPerTenant || history != decisionsPerTenant {
		t.Fatalf("seeded %d current and %d history rows, want %d of each", current, history, decisionsPerTenant)
	}

	subject := func(i int) Subject {
		repo := a.repos[(i*31)%len(a.repos)]
		s := Subject{Repo: repo.name, Path: repo.dir + "/src/main.go"}
		switch i % 4 {
		case 0:
			s.Env = "prod"
		case 1:
			s.Env = "dev"
		case 2:
			s.Path = "" // an omitted path widens the answer to every path scope of the repo
		}
		return s
	}
	valid := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	known := time.Now().Add(time.Minute)

	for i := range warmUpCalls {
		if _, err := Resolve(t.Context(), r.app, tenantA, subject(i), valid, known); err != nil {
			t.Fatal(err)
		}
	}
	durations := make([]time.Duration, 0, timedCalls)
	returned := 0
	for i := range timedCalls {
		start := time.Now()
		got, err := Resolve(t.Context(), r.app, tenantA, subject(i), valid, known)
		durations = append(durations, time.Since(start))
		if err != nil {
			t.Fatal(err)
		}
		returned += len(got)
	}
	if returned == 0 {
		t.Fatal("no call returned a decision, so the timing proves nothing")
	}

	slices.Sort(durations)
	p50, p95, p99 := durations[timedCalls/2], durations[timedCalls*95/100], durations[timedCalls*99/100]
	t.Logf("%d calls, %.1f decisions each: p50 %v, p95 %v, p99 %v (budget p95 %v)",
		timedCalls, float64(returned)/timedCalls, p50, p95, p99, p95Budget)
	// Resolve takes five round trips, so the cost of one on this host is part of any reading.
	t.Logf("one round trip on this host: p50 %v", roundTrip(t, r))
	if p95 >= p95Budget {
		t.Errorf("p95 = %v, want under %v", p95, p95Budget)
	}
}

// roundTrip is the median time of an empty query, which is the floor of any call.
func roundTrip(t *testing.T, r registryDB) time.Duration {
	t.Helper()
	const calls = 200
	durations := make([]time.Duration, 0, calls)
	for range calls {
		start := time.Now()
		if _, err := r.app.ExecContext(t.Context(), `SELECT 1`); err != nil {
			t.Fatal(err)
		}
		durations = append(durations, time.Since(start))
	}
	slices.Sort(durations)
	return durations[calls/2]
}
