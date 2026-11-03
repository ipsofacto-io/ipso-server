//go:build integration

package api

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/ipsofacto-io/ipso-server/internal/authn"
	"github.com/ipsofacto-io/ipso-server/internal/authn/authntest"
	"github.com/ipsofacto-io/ipso-server/internal/migrate"
	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
)

var server *pgtest.Server

func TestMain(m *testing.M) {
	os.Exit(runTests(m))
}

func runTests(m *testing.M) int {
	s, err := pgtest.Start(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = s.Terminate() }()
	server = s
	return m.Run()
}

const audience = "https://ipso.example.test/api"

// Who the test tokens speak for, by subject. ghost names a principal that tenant A does not have.
const (
	personA = "person-a"
	agentA  = "agent-a"
	personB = "person-b"
	ghost   = "ghost"
)

// fixture is a migrated database with the same rows in two tenants, so a read that crossed tenants
// would show. Every row is synthetic.
type fixture struct {
	db      *sql.DB
	auth    *authntest.Server
	callers map[string]Caller

	before, known, valid time.Time

	org, repo, docs, prod uuid.UUID
	tls, api, old, other  uuid.UUID
	waiver                uuid.UUID
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	database := server.NewDatabase(t)
	if _, err := migrate.Run(t.Context(), database.DSN(pgtest.Migrate)); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	f := &fixture{
		db:    database.Open(t, pgtest.App),
		auth:  authntest.NewServer(t),
		valid: time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC),
		tls:   uuid.MustParse("00000000-0000-7000-8000-000000000001"),
		api:   uuid.MustParse("00000000-0000-7000-8000-000000000002"),
		old:   uuid.MustParse("00000000-0000-7000-8000-000000000003"),
		other: uuid.MustParse("00000000-0000-7000-8000-0000000000b1"),
	}
	admin := database.Open(t, pgtest.Admin)
	f.before = clock(t, admin)

	people := map[uuid.UUID]uuid.UUID{}
	for _, tenant := range []uuid.UUID{tenantA, tenantB} {
		people[tenant] = f.insert(t, `INSERT INTO identity.principal (tenant_id, kind, name) VALUES ($1, 'human', 'Ada') RETURNING id`, tenant)
	}
	agent := f.insert(t, `INSERT INTO identity.principal (tenant_id, kind, name, sponsor_id) VALUES ($1, 'agent', 'claude-code', $2) RETURNING id`, tenantA, people[tenantA])
	f.callers = map[string]Caller{
		personA: {Tenant: tenantA, Principal: people[tenantA]},
		agentA:  {Tenant: tenantA, Principal: agent},
		personB: {Tenant: tenantB, Principal: people[tenantB]},
		ghost:   {Tenant: tenantA, Principal: people[tenantB]},
	}

	scope := func(tenant uuid.UUID, parent any, kind, selector string) uuid.UUID {
		return f.insert(t, `INSERT INTO registry.scope (tenant_id, parent_id, kind, selector) VALUES ($1, $2, $3, $4) RETURNING id`, tenant, parent, kind, selector)
	}
	f.org = scope(tenantA, nil, "org", "acme")
	f.repo = scope(tenantA, f.org, "repo", "acme/api")
	f.docs = scope(tenantA, f.repo, "path", "docs/**")
	f.prod = scope(tenantA, f.repo, "env", "prod")
	globex := scope(tenantB, nil, "org", "globex")

	decision := func(tenant, id uuid.UUID, slug, valid string, scope uuid.UUID) {
		t.Helper()
		_, err := f.db.ExecContext(t.Context(), `
			INSERT INTO registry.decision_version (decision_id, version, tenant_id, body, scope_refs, valid_period)
			VALUES ($1, 1, $2, jsonb_build_object('slug', $3::text, 'title', $3::text), ARRAY[$4::uuid], $5::text::tstzrange)`,
			id, tenant, slug, scope, valid)
		if err != nil {
			t.Fatalf("insert the decision %s: %v", slug, err)
		}
	}
	decision(tenantA, f.tls, "use-tls", "[2026-01-01,)", f.org)
	decision(tenantA, f.api, "pin-api-versions", "[2026-01-01,)", f.repo)
	decision(tenantA, f.old, "use-tls-1-2", "[2025-01-01,2026-03-01)", f.org)
	decision(tenantB, f.other, "use-tls", "[2026-01-01,)", globex)
	f.exec(t, `INSERT INTO registry.supersession (tenant_id, from_decision, to_decision, effective_at) VALUES ($1, $2, $3, '2026-03-01')`, tenantA, f.old, f.tls)
	f.waiver = f.insert(t, `
		INSERT INTO registry.waiver (tenant_id, decision_id, scope_id, reason, approver, approver_id, valid_period, ticket_ref)
		VALUES ($1, $2, $3, 'synthetic exception', 'team:platform', $4, '[2026-05-01,2026-06-10)', 'OPS-1')
		RETURNING id`, tenantA, f.api, f.repo, people[tenantA])

	for _, tenant := range []uuid.UUID{tenantA, tenantB} {
		f.exec(t, `
			INSERT INTO proposals.proposal
				(tenant_id, payload, confidence, model_id, prompt_version, repo, pr_number, external_id, source_url, source_sha256, candidate_index)
			VALUES ($1, '{"title":"Use Postgres"}', 0.8, 'm', 'p', 'acme/api', 8, 'pull-8', 'https://github.com/acme/api/pull/8', $2, 0)`,
			tenant, make([]byte, 32))
		f.exec(t, `
			INSERT INTO proposals.check_proposal
				(tenant_id, decision_id, decision_version, spec, rego, rego_sha256, fixtures, fixtures_total, fixtures_passed, repaired, model_id, prompt_version)
			VALUES ($1, $2, 1, '{"rules":[]}', 'package p', sha256(convert_to('package p', 'UTF8')), '[{}, {}]', 2, 2, false, 'm', 'p')`,
			tenant, f.tls)
	}
	f.exec(t, `INSERT INTO proposals.agent_proposal (tenant_id, principal_id, payload) VALUES ($1, $2, '{"title":"Pin API versions"}')`, tenantA, agent)
	f.known = clock(t, admin)
	return f
}

func (f *fixture) insert(t *testing.T, query string, args ...any) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := f.db.QueryRowContext(t.Context(), query, args...).Scan(&id); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return id
}

func (f *fixture) exec(t *testing.T, query string, args ...any) {
	t.Helper()
	if _, err := f.db.ExecContext(t.Context(), query, args...); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
}

// clock reads the database clock between two pauses, so that no row shares its microsecond.
func clock(t *testing.T, db *sql.DB) time.Time {
	t.Helper()
	pause := func() {
		if _, err := db.ExecContext(t.Context(), `SELECT pg_sleep(0.02)`); err != nil {
			t.Fatal(err)
		}
	}
	pause()
	var now time.Time
	if err := db.QueryRowContext(t.Context(), `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	pause()
	return now
}

// handler is the API as the binary will build it: the issuer's metadata and keys discovered over
// TLS, and tokens mapped to callers by subject.
func (f *fixture) handler(t *testing.T, limits Limits) http.Handler {
	t.Helper()
	verifier, _, err := authn.Discover(t.Context(), f.auth.Server.Client(), f.auth.Server.URL, audience)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := New(Config{
		DB:       f.db,
		Verifier: verifier,
		Callers: func(_ context.Context, claims authn.Claims) (Caller, bool) {
			caller, ok := f.callers[claims.Subject]
			return caller, ok
		},
		Limits: limits,
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

// token is a bearer token for subject.
func (f *fixture) token(t *testing.T, subject string) string {
	t.Helper()
	return "Bearer " + f.auth.Token(audience, nil, func(b *jwt.Builder) *jwt.Builder { return b.Subject(subject) })
}
