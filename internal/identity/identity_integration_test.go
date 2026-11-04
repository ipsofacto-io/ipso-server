//go:build integration

package identity_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/identity"
	"github.com/ipsofacto-io/ipso-server/internal/migrate"
	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
)

var server *pgtest.Server

var (
	tenantA = uuid.MustParse("00000000-0000-4000-8000-00000000000a")
	tenantB = uuid.MustParse("00000000-0000-4000-8000-00000000000b")
)

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

func migrated(t *testing.T) *sql.DB {
	t.Helper()
	db := server.NewDatabase(t)
	if _, err := migrate.Run(t.Context(), db.DSN(pgtest.Migrate)); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db.Open(t, pgtest.App)
}

func tryPrincipal(t *testing.T, db *sql.DB, tenant uuid.UUID, kind, name string, sponsor any) (uuid.UUID, error) {
	t.Helper()
	var id uuid.UUID
	err := pgtest.Scan(t.Context(), db, tenant.String(), `
		INSERT INTO identity.principal (tenant_id, kind, name, sponsor_id)
		VALUES ($1, $2, $3, $4) RETURNING id`, []any{tenant, kind, name, sponsor}, &id)
	return id, err
}

func principal(t *testing.T, db *sql.DB, tenant uuid.UUID, kind, name string, sponsor any) uuid.UUID {
	t.Helper()
	id, err := tryPrincipal(t, db, tenant, kind, name, sponsor)
	if err != nil {
		t.Fatalf("insert %s %s: %v", kind, name, err)
	}
	return id
}

func TestAnAgentNeedsAHumanSponsorInItsTenant(t *testing.T) {
	db := migrated(t)
	person := principal(t, db, tenantA, identity.KindHuman, "Ada", nil)
	other := principal(t, db, tenantB, identity.KindHuman, "Bea", nil)
	agent := principal(t, db, tenantA, identity.KindAgent, "claude-code", person)

	for name, tc := range map[string]struct {
		kind    string
		sponsor any
	}{
		"an agent with no sponsor":      {identity.KindAgent, nil},
		"an agent sponsored by agent":   {identity.KindAgent, agent},
		"a sponsor in another tenant":   {identity.KindAgent, other},
		"a sponsor that does not exist": {identity.KindAgent, uuid.New()},
		"a person with a sponsor":       {identity.KindHuman, person},
		"an unknown kind":               {"robot", person},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := tryPrincipal(t, db, tenantA, tc.kind, "refused", tc.sponsor); err == nil {
				t.Fatal("the database accepted it")
			}
		})
	}

	got, err := identity.Get(t.Context(), db, tenantA, agent)
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != identity.KindAgent || got.Name != "claude-code" || got.Sponsor != person {
		t.Fatalf("%+v", got)
	}
	human, err := identity.Get(t.Context(), db, tenantA, person)
	if err != nil {
		t.Fatal(err)
	}
	if human.Sponsor != uuid.Nil {
		t.Fatalf("%+v", human)
	}
	if _, err := identity.Get(t.Context(), db, tenantB, agent); !errors.Is(err, identity.ErrUnknownPrincipal) {
		t.Fatalf("another tenant read a principal: %v", err)
	}
}

// proposal inserts one pending proposal and returns its id.
func proposal(t *testing.T, db *sql.DB, tenant uuid.UUID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := pgtest.Scan(t.Context(), db, tenant.String(), `
		INSERT INTO proposals.proposal
			(tenant_id, payload, confidence, model_id, prompt_version, repo, pr_number, external_id, source_url, source_sha256, candidate_index)
		VALUES ($1, '{}'::jsonb, 0.5, 'model', 'v1', 'acme/app', 1, 'comment-1',
		        'https://github.com/acme/app/pull/1', sha256('x'::bytea), 0)
		RETURNING id`, []any{tenant}, &id)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestAnAgentCannotApproveAProposal(t *testing.T) {
	db := migrated(t)
	person := principal(t, db, tenantA, identity.KindHuman, "Ada", nil)
	agent := principal(t, db, tenantA, identity.KindAgent, "claude-code", person)
	item := proposal(t, db, tenantA)
	approve := func(approver uuid.UUID) error {
		_, err := pgtest.Exec(t.Context(), db, tenantA.String(), `
			INSERT INTO proposals.approval (tenant_id, proposal_id, approver_id, outcome)
			VALUES ($1, $2, $3, 'approved')`, tenantA, item, approver)
		return err
	}
	if err := approve(agent); err == nil || !strings.Contains(err.Error(), "agent cannot approve") {
		t.Fatalf("an agent approved: %v", err)
	}
	if err := approve(uuid.New()); err == nil {
		t.Fatal("an unknown principal approved")
	}
	if err := approve(person); err != nil {
		t.Fatalf("a person must be able to approve: %v", err)
	}
	if err := approve(person); err == nil {
		t.Fatal("a proposal was approved twice")
	}
}

func TestOneTenantsPersonCannotApproveInAnother(t *testing.T) {
	db := migrated(t)
	outsider := principal(t, db, tenantB, identity.KindHuman, "Bea", nil)
	item := proposal(t, db, tenantA)
	_, err := pgtest.Exec(t.Context(), db, tenantA.String(), `
		INSERT INTO proposals.approval (tenant_id, proposal_id, approver_id, outcome)
		VALUES ($1, $2, $3, 'approved')`, tenantA, item, outsider)
	if err == nil {
		t.Fatal("a principal of another tenant approved")
	}
}

func TestTheLogNamesTheSponsorWhateverTheCallerSends(t *testing.T) {
	db := migrated(t)
	ctx := t.Context()
	person := principal(t, db, tenantA, identity.KindHuman, "Ada", nil)
	someoneElse := principal(t, db, tenantA, identity.KindHuman, "Eve", nil)
	agent := principal(t, db, tenantA, identity.KindAgent, "claude-code", person)

	responsible, err := identity.RecordAction(ctx, db, tenantA, agent, "decisions.propose", "proposal 1")
	if err != nil {
		t.Fatal(err)
	}
	if responsible != person {
		t.Fatalf("responsible %s, want the sponsor %s", responsible, person)
	}
	if responsible, err = identity.RecordAction(ctx, db, tenantA, person, "waiver.record", "waiver 1"); err != nil || responsible != person {
		t.Fatalf("a person answers for themself: %s %v", responsible, err)
	}

	var forged uuid.UUID
	if err := pgtest.Scan(ctx, db, tenantA.String(), `
		INSERT INTO identity.action_log (tenant_id, principal_id, responsible_id, action, subject)
		VALUES ($1, $2, $3, 'decisions.get', 'x') RETURNING responsible_id`, []any{tenantA, agent, someoneElse}, &forged); err != nil {
		t.Fatal(err)
	}
	if forged != person {
		t.Fatalf("a caller chose who answers for an agent: %s", forged)
	}

	actions, err := identity.Actions(ctx, db, tenantA, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(actions) != 3 {
		t.Fatalf("%+v", actions)
	}
	for _, item := range actions {
		if item.PrincipalKind == identity.KindAgent && (item.ResponsibleName != "Ada" || item.PrincipalName != "claude-code") {
			t.Errorf("the log hides the sponsor: %+v", item)
		}
		if item.At.IsZero() {
			t.Errorf("no time: %+v", item)
		}
	}
	if other, err := identity.Actions(ctx, db, tenantB, 10); err != nil || len(other) != 0 {
		t.Fatalf("another tenant read the log: %+v %v", other, err)
	}
	if _, err := identity.RecordAction(ctx, db, tenantB, agent, "decisions.get", "x"); err == nil {
		t.Fatal("a principal acted in another tenant")
	}
	if _, err := identity.RecordAction(ctx, db, tenantA, agent, "Bad Action", "x"); err == nil {
		t.Fatal("an action outside the grammar was logged")
	}
	if _, err := identity.RecordAction(ctx, db, tenantA, agent, "a", "line\nbreak"); err == nil {
		t.Fatal("a control character reached the log")
	}
}

func TestApplicationRoleCannotRewriteIdentity(t *testing.T) {
	db := migrated(t)
	person := principal(t, db, tenantA, identity.KindHuman, "Ada", nil)
	principal(t, db, tenantA, identity.KindAgent, "claude-code", person)
	for _, statement := range []string{
		`UPDATE identity.principal SET sponsor_id = NULL`,
		`UPDATE identity.principal SET kind = 'human'`,
		`DELETE FROM identity.principal`,
		`UPDATE identity.action_log SET responsible_id = principal_id`,
		`DELETE FROM identity.action_log`,
		`UPDATE proposals.approval SET outcome = 'approved'`,
		`DELETE FROM proposals.approval`,
	} {
		if _, err := db.ExecContext(t.Context(), statement); err == nil {
			t.Errorf("the application role ran %s", statement)
		}
	}
}
