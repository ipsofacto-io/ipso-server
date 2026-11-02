//go:build integration

package mcpremote

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso/pkg/mcptools"

	"github.com/ipsofacto-io/ipso-server/internal/identity"
	"github.com/ipsofacto-io/ipso-server/internal/migrate"
	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
)

var server *pgtest.Server

var otherTenant = uuid.MustParse("00000000-0000-4000-8000-00000000000b")

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

type fixture struct {
	db     *sql.DB
	person uuid.UUID
	agent  uuid.UUID
	plain  uuid.UUID
	secret uuid.UUID
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	database := server.NewDatabase(t)
	if _, err := migrate.Run(t.Context(), database.DSN(pgtest.Migrate)); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db := database.Open(t, pgtest.App)
	f := fixture{db: db, plain: uuid.New(), secret: uuid.New()}
	insert := func(query string, args ...any) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		if err := db.QueryRowContext(t.Context(), query, args...).Scan(&id); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
		return id
	}
	principal := `INSERT INTO identity.principal (tenant_id, kind, name, sponsor_id) VALUES ($1, $2, $3, $4) RETURNING id`
	f.person = insert(principal, testTenant, identity.KindHuman, "Ada", nil)
	f.agent = insert(principal, testTenant, identity.KindAgent, "claude-code", f.person)
	org := insert(`INSERT INTO registry.scope (tenant_id, parent_id, kind, selector) VALUES ($1, NULL, 'org', 'acme') RETURNING id`, testTenant)
	decision := func(id uuid.UUID, body string) {
		t.Helper()
		_, err := db.ExecContext(t.Context(), `
			INSERT INTO registry.decision_version (decision_id, version, tenant_id, body, scope_refs, valid_period)
			VALUES ($1, 1, $2, $3::jsonb, $4::uuid[], '[2026-01-01,)')`, id, testTenant, body, []uuid.UUID{org})
		if err != nil {
			t.Fatalf("insert the decision: %v", err)
		}
	}
	decision(f.plain, `{"slug":"use-tls","title":"Use TLS","status":"verified","criticality":"blocking","statement":"All traffic uses TLS.","sources":[{"url":"https://example.test/spec"}],"scope":[{"org":"acme"}],"checks":[{"engine":"opa","target":"agent-edit","mode":"block"}]}`)
	decision(f.secret, `{"slug":"vault-host","title":"Vault at vault.internal","status":"accepted","criticality":"blocking","statement":"Use vault.internal.","tags":["sensitive"],"sources":[{"url":"https://vault.internal/doc"}],"scope":[{"org":"acme"}]}`)
	return f
}

func (f fixture) backend(tenant, principal uuid.UUID) *Backend {
	return &Backend{DB: f.db, Caller: Caller{Tenant: tenant, Principal: principal}, Now: time.Now}
}

func TestBackendAnswersTheToolsFromTheRegistry(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	b := f.backend(testTenant, f.agent)

	out, err := b.Applicable(ctx, mcptools.ApplicableInput{Repo: "ACME/App", Paths: []string{"a.go", "b.go"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Decisions) != 2 {
		t.Fatalf("two paths must not repeat a decision: %+v", out.Decisions)
	}
	for _, item := range out.Decisions {
		switch item.Slug {
		case "use-tls":
			if item.Statement != "All traffic uses TLS." || item.State != "Verified" || len(item.Checks) != 1 || len(item.Sources) != 1 {
				t.Errorf("%+v", item)
			}
		case "vault-host":
			if !item.Sensitive || item.Title != "" || item.Statement != "" || len(item.Sources) != 0 {
				t.Errorf("sensitive text left the registry: %+v", item)
			}
		default:
			t.Errorf("%+v", item)
		}
	}
	if _, err := b.Applicable(ctx, mcptools.ApplicableInput{Repo: "not a repo"}); err == nil || !strings.Contains(err.Error(), "owner/name") {
		t.Fatalf("a bad repo: %v", err)
	}

	for _, ref := range []string{"use-tls", f.plain.String()} {
		got, err := b.Get(ctx, mcptools.GetInput{Ref: ref})
		if err != nil {
			t.Fatalf("%s: %v", ref, err)
		}
		if got.Decision.ID != f.plain.String() || !got.InForce {
			t.Fatalf("%s: %+v", ref, got)
		}
	}
	if _, err := b.Get(ctx, mcptools.GetInput{Ref: "use-tls", AsOfValid: "2020-01-01"}); err == nil {
		t.Fatal("a decision answered for a date before it")
	}
	if _, err := b.Get(ctx, mcptools.GetInput{Ref: "use-tls", AsOfTx: "2020-01-01T00:00:00Z"}); err == nil {
		t.Fatal("a decision answered for a time before it was recorded")
	}
	if _, err := b.Get(ctx, mcptools.GetInput{Ref: "use-tls", AsOfValid: "nope"}); err == nil {
		t.Fatal("a bad date")
	}

	if _, err := b.Evaluate(ctx, mcptools.EvaluateInput{Diff: "x"}); err == nil || !strings.Contains(err.Error(), "ipso mcp") {
		t.Fatalf("evaluate must point at the local server: %v", err)
	}
}

func TestBackendAProposalStaysPendingAndTheLogNamesTheSponsor(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	b := f.backend(testTenant, f.agent)

	out, err := b.Propose(ctx, mcptools.ProposeInput{Title: "Use int64 for money", Statement: "Money is int64 cents.", Rationale: "Rounding."})
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != "proposed" {
		t.Fatalf("%+v", out)
	}
	var status string
	var principal uuid.UUID
	if err := f.db.QueryRowContext(ctx, `SELECT status, principal_id FROM proposals.agent_proposal WHERE tenant_id = $1 AND id = $2`, testTenant, out.ProposalID).Scan(&status, &principal); err != nil {
		t.Fatal(err)
	}
	if status != "pending" || principal != f.agent {
		t.Fatalf("%s %s", status, principal)
	}
	if _, err := f.db.ExecContext(ctx, `INSERT INTO proposals.agent_proposal (tenant_id, principal_id, payload, status) VALUES ($1, $2, '{}', 'accepted')`, testTenant, f.agent); err == nil {
		t.Fatal("a proposal was stored as accepted")
	}
	for _, statement := range []string{`UPDATE proposals.agent_proposal SET status = 'accepted'`, `DELETE FROM proposals.agent_proposal`} {
		if _, err := f.db.ExecContext(ctx, statement); err == nil {
			t.Errorf("the application role ran %s", statement)
		}
	}
	for name, in := range map[string]mcptools.ProposeInput{
		"no title":  {Statement: "s", Rationale: "r"},
		"two lines": {Title: "a\nb", Statement: "s", Rationale: "r"},
		"no text":   {Title: "t", Rationale: "r"},
		"control":   {Title: "t", Statement: "a\x1b[31m", Rationale: "r"},
		"too long":  {Title: "t", Statement: strings.Repeat("x", maxProposalText+1), Rationale: "r"},
	} {
		if _, err := b.Propose(ctx, in); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	if _, err := b.Applicable(ctx, mcptools.ApplicableInput{Repo: "acme/app"}); err != nil {
		t.Fatal(err)
	}
	actions, err := identity.Actions(ctx, f.db, testTenant, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 2 {
		t.Fatalf("%+v", actions)
	}
	for _, item := range actions {
		if item.ResponsibleName != "Ada" || item.PrincipalName != "claude-code" {
			t.Errorf("the log hides the sponsor: %+v", item)
		}
	}
	if actions[0].Action != mcptools.ToolApplicable || actions[1].Action != mcptools.ToolPropose || actions[1].Subject != "Use int64 for money" {
		t.Errorf("%+v", actions)
	}
}

func TestBackendACallThatCannotBeLoggedDoesNotRun(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	stranger := f.backend(testTenant, uuid.New())
	if _, err := stranger.Propose(ctx, mcptools.ProposeInput{Title: "t", Statement: "s", Rationale: "r"}); err == nil || !strings.Contains(err.Error(), "did not run") {
		t.Fatalf("err %v", err)
	}
	var rows int
	if err := f.db.QueryRowContext(ctx, `SELECT count(*) FROM proposals.agent_proposal`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 0 {
		t.Fatalf("%d proposals", rows)
	}
	if _, err := stranger.Applicable(ctx, mcptools.ApplicableInput{Repo: "acme/app"}); err == nil {
		t.Fatal("a read ran without a log entry")
	}
}

func TestBackendAnotherTenantSeesNothing(t *testing.T) {
	f := newFixture(t)
	ctx := t.Context()
	var outsider uuid.UUID
	if err := f.db.QueryRowContext(ctx, `INSERT INTO identity.principal (tenant_id, kind, name) VALUES ($1, 'human', 'Bea') RETURNING id`, otherTenant).Scan(&outsider); err != nil {
		t.Fatal(err)
	}
	b := f.backend(otherTenant, outsider)
	out, err := b.Applicable(ctx, mcptools.ApplicableInput{Repo: "acme/app"})
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Decisions) != 0 {
		t.Fatalf("%+v", out.Decisions)
	}
	if _, err := b.Get(ctx, mcptools.GetInput{Ref: f.plain.String()}); err == nil {
		t.Fatal("another tenant read a decision")
	}
	if _, err := f.backend(otherTenant, f.agent).Applicable(ctx, mcptools.ApplicableInput{Repo: "acme/app"}); err == nil {
		t.Fatal("a principal acted in another tenant")
	}
}
