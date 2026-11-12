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
			INSERT INTO proposals.approval (tenant_id, proposal_id, approver_id, outcome, decision_id)
			VALUES ($1, $2, $3, 'approved', uuidv7())`, tenantA, item, approver)
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
		INSERT INTO proposals.approval (tenant_id, proposal_id, approver_id, outcome, decision_id)
		VALUES ($1, $2, $3, 'approved', uuidv7())`, tenantA, item, outsider)
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
		`UPDATE proposals.agent_approval SET outcome = 'approved'`,
		`DELETE FROM proposals.agent_approval`,
		`UPDATE proposals.check_approval SET outcome = 'approved'`,
		`DELETE FROM proposals.check_approval`,
	} {
		if _, err := db.ExecContext(t.Context(), statement); err == nil {
			t.Errorf("the application role ran %s", statement)
		}
	}
}

const idp = "https://idp.example.test"

func bind(t *testing.T, db *sql.DB, tenant, principal uuid.UUID, issuer, subject string) error {
	t.Helper()
	_, err := pgtest.Exec(t.Context(), db, tenant.String(), `
		INSERT INTO identity.login (tenant_id, principal_id, issuer, subject) VALUES ($1, $2, $3, $4)`,
		tenant, principal, issuer, subject)
	return err
}

func addTenant(t *testing.T, db *sql.DB, tenant uuid.UUID) {
	t.Helper()
	if _, err := pgtest.Exec(t.Context(), db, tenant.String(), `INSERT INTO tenancy.tenant (tenant_id, name) VALUES ($1, 'synthetic tenant')`, tenant); err != nil {
		t.Fatal(err)
	}
}

func TestPrincipalForReadsOnlyTheTenantsOwnLogins(t *testing.T) {
	db := migrated(t)
	addTenant(t, db, tenantA)
	addTenant(t, db, tenantB)
	ada, err := tryPrincipal(t, db, tenantA, "human", "Ada", nil)
	if err != nil {
		t.Fatal(err)
	}
	bea, err := tryPrincipal(t, db, tenantB, "human", "Bea", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := bind(t, db, tenantA, ada, idp, "subject-ada"); err != nil {
		t.Fatal(err)
	}
	if err := bind(t, db, tenantB, bea, idp, "subject-ada"); err != nil {
		t.Fatalf("the same subject in another tenant: %v", err)
	}

	got, err := identity.PrincipalFor(t.Context(), db, tenantA, idp, "subject-ada")
	if err != nil || got != ada {
		t.Fatalf("PrincipalFor = %v, %v, want %v", got, err, ada)
	}
	got, err = identity.PrincipalFor(t.Context(), db, tenantB, idp, "subject-ada")
	if err != nil || got != bea {
		t.Fatalf("PrincipalFor in tenant B = %v, %v, want %v", got, err, bea)
	}
	for name, args := range map[string][2]string{
		"another subject": {idp, "subject-bea"},
		"another issuer":  {"https://other.example.test", "subject-ada"},
	} {
		if _, err := identity.PrincipalFor(t.Context(), db, tenantA, args[0], args[1]); !errors.Is(err, identity.ErrUnknownLogin) {
			t.Errorf("%s: err = %v, want ErrUnknownLogin", name, err)
		}
	}
	if _, err := identity.PrincipalFor(t.Context(), db, uuid.New(), idp, "subject-ada"); !errors.Is(err, identity.ErrUnknownLogin) {
		t.Errorf("an unknown tenant: err = %v, want ErrUnknownLogin", err)
	}
	if _, err := identity.PrincipalFor(t.Context(), db, tenantA, "", "subject-ada"); !errors.Is(err, identity.ErrInvalidQuery) {
		t.Errorf("no issuer: err = %v, want ErrInvalidQuery", err)
	}
}

func TestALoginCannotNameAPrincipalOfAnotherTenantOrBeRebound(t *testing.T) {
	db := migrated(t)
	addTenant(t, db, tenantA)
	addTenant(t, db, tenantB)
	ada, err := tryPrincipal(t, db, tenantA, "human", "Ada", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := bind(t, db, tenantB, ada, idp, "subject-ada"); err == nil {
		t.Error("tenant B bound a principal of tenant A")
	}
	if err := bind(t, db, tenantA, ada, idp, "subject-ada"); err != nil {
		t.Fatal(err)
	}
	if err := bind(t, db, tenantA, ada, idp, "subject-ada"); err == nil {
		t.Error("the same issuer and subject were bound twice")
	}
	for name, args := range map[string][2]string{
		"an http issuer":        {"http://idp.example.test", "s"},
		"an empty subject":      {idp, ""},
		"a padded subject":      {idp, " s"},
		"a subject with a line": {idp, "a\nb"},
		"a long subject":        {idp, strings.Repeat("s", 256)},
	} {
		if err := bind(t, db, tenantA, ada, args[0], args[1]); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	// The application role only adds logins: it cannot change or remove one.
	if _, err := pgtest.Exec(t.Context(), db, tenantA.String(), `UPDATE identity.login SET subject = 'other'`); err == nil {
		t.Error("a login was updated")
	}
	if _, err := pgtest.Exec(t.Context(), db, tenantA.String(), `DELETE FROM identity.login`); err == nil {
		t.Error("a login was deleted")
	}
}

func TestALoginNeedsATenantRow(t *testing.T) {
	db := migrated(t)
	ada, err := tryPrincipal(t, db, tenantA, "human", "Ada", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := bind(t, db, tenantA, ada, idp, "subject-ada"); err == nil {
		t.Error("a login was bound in a tenant that has no row")
	}
}

// A write and its log entry are one transaction: a write that cannot be logged does not run, and an entry
// never outlives a write that failed (ADR-0109).
func TestWithActionLogsTheWriteInTheSameTransaction(t *testing.T) {
	db := migrated(t)
	ctx := t.Context()
	person := principal(t, db, tenantA, identity.KindHuman, "Ada", nil)
	write := func(tx *sql.Tx, subject string) (string, error) {
		_, err := tx.ExecContext(ctx, `INSERT INTO registry.premise_host_allow (tenant_id, host, allowed) VALUES ($1, 'example.com', true)`, tenantA)
		return subject, err
	}
	hosts := func() int {
		var n int
		if err := pgtest.Scan(ctx, db, tenantA.String(), `SELECT count(*) FROM registry.premise_host_allow`, nil, &n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	logged := func() []identity.Action {
		actions, err := identity.Actions(ctx, db, tenantA, 10)
		if err != nil {
			t.Fatal(err)
		}
		return actions
	}

	if err := identity.WithAction(ctx, db, tenantA, person, "api.allow_premise_host", func(tx *sql.Tx) (string, error) { return write(tx, "allowlist row") }); err != nil {
		t.Fatal(err)
	}
	if actions := logged(); hosts() != 1 || len(actions) != 1 || actions[0].Action != "api.allow_premise_host" || actions[0].Principal != person || actions[0].Responsible != person {
		t.Fatalf("a write left %d hosts and %+v", hosts(), logged())
	}

	// An entry the log refuses rolls the write back.
	err := identity.WithAction(ctx, db, tenantA, person, "NOT AN ACTION", func(tx *sql.Tx) (string, error) { return write(tx, "allowlist row") })
	if err == nil || hosts() != 1 || len(logged()) != 1 {
		t.Fatalf("a write that could not be logged ran: %v, %d hosts, %d entries", err, hosts(), len(logged()))
	}
	// So does a subject the log refuses.
	err = identity.WithAction(ctx, db, tenantA, person, "api.allow_premise_host", func(tx *sql.Tx) (string, error) { return write(tx, "line\nbreak") })
	if err == nil || hosts() != 1 || len(logged()) != 1 {
		t.Fatalf("a write with a subject the log refuses ran: %v, %d hosts, %d entries", err, hosts(), len(logged()))
	}
	// A write that fails leaves no entry, and its error comes back as it was.
	boom := errors.New("boom")
	err = identity.WithAction(ctx, db, tenantA, person, "api.allow_premise_host", func(tx *sql.Tx) (string, error) { return "", boom })
	if !errors.Is(err, boom) || len(logged()) != 1 {
		t.Fatalf("a failed write: %v, %d entries", err, len(logged()))
	}
	// A principal of another tenant cannot be logged here, and the write goes with it.
	outsider := principal(t, db, tenantB, identity.KindHuman, "Bea", nil)
	err = identity.WithAction(ctx, db, tenantA, outsider, "api.allow_premise_host", func(tx *sql.Tx) (string, error) { return write(tx, "allowlist row") })
	if err == nil || hosts() != 1 {
		t.Fatalf("a principal of another tenant logged a write: %v, %d hosts", err, hosts())
	}
	// A call with no tenant or principal never starts.
	if err := identity.WithAction(ctx, db, uuid.Nil, person, "api.x", func(*sql.Tx) (string, error) { return "", nil }); !errors.Is(err, identity.ErrInvalidQuery) {
		t.Fatalf("no tenant: %v", err)
	}
	// An agent's write names its sponsor as the one answerable.
	agent := principal(t, db, tenantA, identity.KindAgent, "claude-code", person)
	if err := identity.WithAction(ctx, db, tenantA, agent, "api.allow_premise_host", func(tx *sql.Tx) (string, error) { return "x", nil }); err != nil {
		t.Fatal(err)
	}
	if latest := logged()[0]; latest.Principal != agent || latest.Responsible != person {
		t.Fatalf("an agent's entry names %+v", latest)
	}
}

// An approval names the decision it wrote exactly when it approves, one decision comes from at most one
// approval, and an agent proposal has an approval table of its own with the same rules (ADR-0076, ADR-0109).
func TestAnApprovalCarriesItsDecisionExactlyWhenItApproves(t *testing.T) {
	db := migrated(t)
	ctx := t.Context()
	person := principal(t, db, tenantA, identity.KindHuman, "Ada", nil)
	agent := principal(t, db, tenantA, identity.KindAgent, "claude-code", person)
	var agentProposal uuid.UUID
	if err := pgtest.Scan(ctx, db, tenantA.String(), `
		INSERT INTO proposals.agent_proposal (tenant_id, principal_id, payload) VALUES ($1, $2, '{"title":"Pin"}') RETURNING id`,
		[]any{tenantA, agent}, &agentProposal); err != nil {
		t.Fatal(err)
	}
	decision := uuid.MustParse("00000000-0000-7000-8000-0000000000f1")
	// The cases run in order: the second approval of one decision is refused only after the first stored it.
	for _, c := range []struct {
		name                     string
		table, proposal, outcome string
		decision                 any
		ok                       bool
	}{
		{"an approval with a decision", "proposals.approval", "p1", "approved", decision, true},
		{"an approval with no decision", "proposals.approval", "p2", "approved", nil, false},
		{"a rejection with a decision", "proposals.approval", "p3", "rejected", decision, false},
		{"a rejection with none", "proposals.approval", "p4", "rejected", nil, true},
		{"a second approval of one decision", "proposals.approval", "p5", "approved", decision, false},
		{"an agent approval with a decision", "proposals.agent_approval", "a1", "approved", decision, true},
		{"an agent approval with none", "proposals.agent_approval", "a2", "approved", nil, false},
	} {
		var proposal uuid.UUID
		switch {
		case strings.HasPrefix(c.proposal, "a"):
			proposal = agentProposal
		default:
			proposal = uuidFor(t, db, c.proposal)
		}
		_, err := pgtest.Exec(ctx, db, tenantA.String(),
			`INSERT INTO `+c.table+` (tenant_id, proposal_id, approver_id, outcome, decision_id) VALUES ($1, $2, $3, $4, $5)`,
			tenantA, proposal, person, c.outcome, c.decision)
		if (err == nil) != c.ok {
			t.Errorf("%s: %v, want success %v", c.name, err, c.ok)
		}
	}
	// An agent cannot approve a proposal of the agent queue, and it is decided once.
	if _, err := pgtest.Exec(ctx, db, tenantA.String(),
		`INSERT INTO proposals.agent_approval (tenant_id, proposal_id, approver_id, outcome) VALUES ($1, $2, $3, 'rejected')`, tenantA, agentProposal, agent); err == nil || !strings.Contains(err.Error(), "agent cannot approve") {
		t.Errorf("an agent approved an agent proposal: %v", err)
	}
	if _, err := pgtest.Exec(ctx, db, tenantA.String(),
		`INSERT INTO proposals.agent_approval (tenant_id, proposal_id, approver_id, outcome) VALUES ($1, $2, $3, 'rejected')`, tenantA, agentProposal, person); err == nil {
		t.Error("an agent proposal was decided twice")
	}
	// Another tenant's person cannot approve it.
	outsider := principal(t, db, tenantB, identity.KindHuman, "Bea", nil)
	if _, err := pgtest.Exec(ctx, db, tenantA.String(),
		`INSERT INTO proposals.agent_approval (tenant_id, proposal_id, approver_id, outcome) VALUES ($1, $2, $3, 'rejected')`, tenantA, agentProposal, outsider); err == nil {
		t.Error("a principal of another tenant approved")
	}

	// A check drafted for a decision is answered once, by a person of its tenant (ADR-0116).
	var check uuid.UUID
	if err := pgtest.Scan(ctx, db, tenantA.String(), `
		INSERT INTO proposals.check_proposal
			(tenant_id, decision_id, decision_version, spec, rego, rego_sha256, fixtures, fixtures_total, fixtures_passed, repaired, model_id, prompt_version)
		VALUES ($1, $2, 1, '{}'::jsonb, 'package p', sha256(convert_to('package p', 'UTF8')), '[{},{}]'::jsonb, 2, 2, false, 'm', 'p')
		RETURNING id`, []any{tenantA, decision}, &check); err != nil {
		t.Fatal(err)
	}
	answerCheck := func(approver uuid.UUID, outcome string) error {
		_, err := pgtest.Exec(ctx, db, tenantA.String(),
			`INSERT INTO proposals.check_approval (tenant_id, proposal_id, approver_id, outcome) VALUES ($1, $2, $3, $4)`, tenantA, check, approver, outcome)
		return err
	}
	if err := answerCheck(agent, "approved"); err == nil || !strings.Contains(err.Error(), "agent cannot approve") {
		t.Errorf("an agent approved a drafted check: %v", err)
	}
	if err := answerCheck(outsider, "approved"); err == nil {
		t.Error("a principal of another tenant answered a drafted check")
	}
	if err := answerCheck(person, "maybe"); err == nil {
		t.Error("an outcome of neither was stored")
	}
	if err := answerCheck(person, "rejected"); err != nil {
		t.Errorf("a person could not answer a drafted check: %v", err)
	}
	if err := answerCheck(person, "approved"); err == nil {
		t.Error("a drafted check was decided twice")
	}
}

// uuidFor makes a proposal of tenant A for the named case.
func uuidFor(t *testing.T, db *sql.DB, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := pgtest.Scan(t.Context(), db, tenantA.String(), `
		INSERT INTO proposals.proposal
			(tenant_id, payload, confidence, model_id, prompt_version, repo, pr_number, external_id, source_url, source_sha256, candidate_index)
		VALUES ($1, '{}'::jsonb, 0.5, 'model', 'v1', 'acme/app', 1, $2, 'https://github.com/acme/app/pull/1', sha256($2::text::bytea), 0)
		RETURNING id`, []any{tenantA, "comment-" + strings.TrimPrefix(name, "p")}, &id); err != nil {
		t.Fatal(err)
	}
	return id
}
