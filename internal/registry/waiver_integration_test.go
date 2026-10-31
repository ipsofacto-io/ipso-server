//go:build integration

package registry

import (
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
)

func (r registryDB) addWaiver(t *testing.T, tenant, decision, scope uuid.UUID, valid, ticket string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := r.app.QueryRowContext(t.Context(), `
		INSERT INTO registry.waiver
			(tenant_id, decision_id, scope_id, reason, approver, valid_period, ticket_ref)
		VALUES ($1, $2, $3, 'synthetic exception', 'team:platform', $4::text::tstzrange, $5)
		RETURNING id`, tenant, decision, scope, valid, ticket).Scan(&id)
	if err != nil {
		t.Fatalf("waiver: %v", err)
	}
	return id
}

func (r registryDB) addWaiverBetween(t *testing.T, tenant, decision, scope uuid.UUID, start, end time.Time, ticket string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	err := r.app.QueryRowContext(t.Context(), `
		INSERT INTO registry.waiver
			(tenant_id, decision_id, scope_id, reason, approver, valid_period, ticket_ref)
		VALUES ($1, $2, $3, 'synthetic exception', 'team:platform', tstzrange($4, $5, '[)'), $6)
		RETURNING id`, tenant, decision, scope, start, end, ticket).Scan(&id)
	if err != nil {
		t.Fatalf("waiver: %v", err)
	}
	return id
}

func TestInForceWaiverTurnsAFailIntoWaived(t *testing.T) {
	r := newRegistryDB(t)
	org := r.scope(t, tenantA, uuid.Nil, "org", "acme")
	repo := r.scope(t, tenantA, org, "repo", "acme/payments")
	path := r.scope(t, tenantA, repo, "path", "infra/**")
	decision := uuid.MustParse("00000000-0000-4000-8000-0000000000d1")
	r.decision(t, tenantA, decision, "[2026-01-01,2026-06-01)", repo)
	r.addWaiver(t, tenantA, decision, path, "[2026-02-01,2026-04-01)", "TICKET-1")

	march := at(t, r, "2026-03-01")
	known := soon(t, r)
	inPath := Subject{Repo: "Acme/Payments", Path: "infra/main.tf"}
	got, err := Apply(t.Context(), r.app, tenantA, decision, inPath, OutcomeFail, march, known)
	if err != nil {
		t.Fatal(err)
	}
	if got != OutcomeWaived {
		t.Errorf("in force = %s, want waived", got)
	}

	outside := Subject{Repo: "acme/payments", Path: "docs/readme.md"}
	got, err = Apply(t.Context(), r.app, tenantA, decision, outside, OutcomeFail, march, known)
	if err != nil {
		t.Fatal(err)
	}
	if got != OutcomeFail {
		t.Errorf("outside the path = %s, want fail", got)
	}

	otherRepo := Subject{Repo: "acme/billing"}
	got, err = Apply(t.Context(), r.app, tenantA, decision, otherRepo, OutcomeFail, march, known)
	if err != nil {
		t.Fatal(err)
	}
	if got != OutcomeFail {
		t.Errorf("other repo = %s, want fail", got)
	}

	got, err = Apply(t.Context(), r.app, tenantB, decision, inPath, OutcomeFail, march, known)
	if err != nil {
		t.Fatal(err)
	}
	if got != OutcomeFail {
		t.Errorf("other tenant = %s, want fail", got)
	}

	for _, outcome := range []Outcome{OutcomePass, OutcomeWaived, OutcomeError} {
		got, err = Apply(t.Context(), r.app, tenantA, decision, inPath, outcome, march, known)
		if err != nil || got != outcome {
			t.Errorf("%s: got %s, %v, want it unchanged", outcome, got, err)
		}
	}
}

func TestWaiverExpiresAtTheUpperBound(t *testing.T) {
	r := newRegistryDB(t)
	org := r.scope(t, tenantA, uuid.Nil, "org", "acme")
	repo := r.scope(t, tenantA, org, "repo", "acme/payments")
	decision := uuid.MustParse("00000000-0000-4000-8000-0000000000d1")
	r.decision(t, tenantA, decision, "[2026-01-01,2026-06-01)", repo)
	r.addWaiver(t, tenantA, decision, repo, "[2026-02-01,2026-04-01)", "TICKET-1")

	known := soon(t, r)
	subject := Subject{Repo: "acme/payments", Path: "infra/main.tf"}
	april := at(t, r, "2026-04-01")
	got, err := Apply(t.Context(), r.app, tenantA, decision, subject, OutcomeFail, april, known)
	if err != nil {
		t.Fatal(err)
	}
	if got != OutcomeFail {
		t.Errorf("at the upper bound = %s, want fail", got)
	}
	got, err = Apply(t.Context(), r.app, tenantA, decision, subject, OutcomeFail, april.Add(-time.Microsecond), known)
	if err != nil {
		t.Fatal(err)
	}
	if got != OutcomeWaived {
		t.Errorf("before the upper bound = %s, want waived", got)
	}
	january := at(t, r, "2026-01-15")
	got, err = Apply(t.Context(), r.app, tenantA, decision, subject, OutcomeFail, january, known)
	if err != nil {
		t.Fatal(err)
	}
	if got != OutcomeFail {
		t.Errorf("before the waiver = %s, want fail", got)
	}
}

func TestWaiverRecordedLaterDoesNotChangeAnEarlierAnswer(t *testing.T) {
	r := newRegistryDB(t)
	org := r.scope(t, tenantA, uuid.Nil, "org", "acme")
	repo := r.scope(t, tenantA, org, "repo", "acme/payments")
	decision := uuid.MustParse("00000000-0000-4000-8000-0000000000d1")
	r.decision(t, tenantA, decision, "[2026-01-01,2026-06-01)", repo)
	before := mark(t, r.app)
	r.addWaiver(t, tenantA, decision, repo, "[2026-02-01,2026-04-01)", "TICKET-1")
	after := soon(t, r)

	march := at(t, r, "2026-03-01")
	subject := Subject{Repo: "acme/payments"}
	got, err := Apply(t.Context(), r.app, tenantA, decision, subject, OutcomeFail, march, before)
	if err != nil {
		t.Fatal(err)
	}
	if got != OutcomeFail {
		t.Errorf("as known before the waiver = %s, want fail", got)
	}
	got, err = Apply(t.Context(), r.app, tenantA, decision, subject, OutcomeFail, march, after)
	if err != nil {
		t.Fatal(err)
	}
	if got != OutcomeWaived {
		t.Errorf("as known after the waiver = %s, want waived", got)
	}
}

func TestApplyFailsClosedOnADamagedClosure(t *testing.T) {
	r := newRegistryDB(t)
	ctx := t.Context()
	org := r.scope(t, tenantA, uuid.Nil, "org", "acme")
	repo := r.scope(t, tenantA, org, "repo", "acme/payments")
	path := r.scope(t, tenantA, repo, "path", "infra/**")
	decision := uuid.MustParse("00000000-0000-4000-8000-0000000000d1")
	r.decision(t, tenantA, decision, "[2026-01-01,2026-06-01)", repo)
	r.addWaiver(t, tenantA, decision, path, "[2026-02-01,2026-04-01)", "TICKET-1")

	march := at(t, r, "2026-03-01")
	known := soon(t, r)
	subject := Subject{Repo: "acme/payments", Path: "infra/main.tf"}
	got, err := Apply(ctx, r.app, tenantA, decision, subject, OutcomeFail, march, known)
	if err != nil || got != OutcomeWaived {
		t.Fatalf("before the damage: %s, err %v, want waived and none", got, err)
	}
	if _, err := r.admin.ExecContext(ctx, `
		DELETE FROM registry.scope_closure WHERE descendant_id = $1 AND ancestor_id = $1`, path); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(ctx, r.app, tenantA, decision, subject, OutcomeFail, march, known); !errors.Is(err, ErrDamagedClosure) {
		t.Errorf("err = %v, want ErrDamagedClosure", err)
	}
}

func TestWaiverDoesNotApplyWhereTheDecisionNoLongerCovers(t *testing.T) {
	r := newRegistryDB(t)
	ctx := t.Context()
	org := r.scope(t, tenantA, uuid.Nil, "org", "acme")
	var now time.Time
	if err := r.admin.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		t.Fatal(err)
	}
	start := now.Add(-40 * 24 * time.Hour)
	waiverEnd := now.Add(-time.Hour)
	decisionEnd := now.Add(10 * 24 * time.Hour)
	effective := now.Add(-10 * 24 * time.Hour)
	oldID := uuid.MustParse("00000000-0000-4000-8000-0000000000a1")
	newID := uuid.MustParse("00000000-0000-4000-8000-0000000000b1")
	r.decisionBetween(t, tenantA, oldID, start, decisionEnd, org)
	r.decisionBetween(t, tenantA, newID, effective, effective.Add(30*24*time.Hour), org)
	r.addWaiverBetween(t, tenantA, oldID, org, start, waiverEnd, "TICKET-9")

	subject := Subject{Repo: "acme/payments"}
	stillCovered := now.Add(-20 * 24 * time.Hour)
	stuckOut := now.Add(-2 * time.Hour)
	beforeClose := mark(t, r.app)
	if _, err := r.app.ExecContext(ctx, `
		INSERT INTO registry.supersession (tenant_id, from_decision, to_decision, effective_at)
		VALUES ($1, $2, $3, $4)`, tenantA, oldID, newID, effective); err != nil {
		t.Fatalf("supersede: %v", err)
	}
	afterClose := soon(t, r)

	got, err := Apply(ctx, r.app, tenantA, oldID, subject, OutcomeFail, stuckOut, beforeClose)
	if err != nil {
		t.Fatal(err)
	}
	if got != OutcomeWaived {
		t.Errorf("as known before the supersession = %s, want waived", got)
	}
	got, err = Apply(ctx, r.app, tenantA, oldID, subject, OutcomeFail, stillCovered, afterClose)
	if err != nil {
		t.Fatal(err)
	}
	if got != OutcomeWaived {
		t.Errorf("inside the shortened decision = %s, want waived", got)
	}
	got, err = Apply(ctx, r.app, tenantA, oldID, subject, OutcomeFail, stuckOut, afterClose)
	if err != nil {
		t.Fatal(err)
	}
	if got != OutcomeFail {
		t.Errorf("past the shortened decision = %s, want fail", got)
	}
	n, err := Notify(ctx, r.app, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("notices for a waiver outside the decision = %d, want 0", n)
	}
}

func (r registryDB) decisionBetween(t *testing.T, tenant, id uuid.UUID, start, end time.Time, scopes ...uuid.UUID) {
	t.Helper()
	_, err := r.app.ExecContext(t.Context(), `
		INSERT INTO registry.decision_version (decision_id, version, tenant_id, body, scope_refs, valid_period)
		VALUES ($1, 1, $2, jsonb_build_object('id', $1::uuid::text), $3::uuid[], tstzrange($4, $5, '[)'))`,
		id, tenant, scopes, start, end)
	if err != nil {
		t.Fatalf("insert decision: %v", err)
	}
}

func TestNotifyRecordsEachDueOffsetOnce(t *testing.T) {
	r := newRegistryDB(t)
	ctx := t.Context()
	org := r.scope(t, tenantA, uuid.Nil, "org", "acme")
	decision := uuid.MustParse("00000000-0000-4000-8000-0000000000d1")
	if _, err := r.app.ExecContext(ctx, `
		INSERT INTO registry.decision_version (decision_id, version, tenant_id, body, scope_refs, valid_period)
		VALUES ($1, 1, $2, '{}', ARRAY[$3::uuid], tstzrange(clock_timestamp() - interval '50 days', NULL, '[)'))`,
		decision, tenantA, org); err != nil {
		t.Fatalf("decision: %v", err)
	}

	insert := func(span, ticket string) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		err := r.app.QueryRowContext(ctx, `
			INSERT INTO registry.waiver
				(tenant_id, decision_id, scope_id, reason, approver, valid_period, ticket_ref)
			VALUES ($1, $2, $3, 'synthetic exception', 'team:platform', `+span+`, $4)
			RETURNING id`, tenantA, decision, org, ticket).Scan(&id)
		if err != nil {
			t.Fatalf("waiver %s: %v", ticket, err)
		}
		return id
	}
	only14 := insert(`tstzrange(clock_timestamp() - interval '2 days', clock_timestamp() + interval '13 days', '[)')`, "TICKET-14")
	allThree := insert(`tstzrange(clock_timestamp() - interval '30 days', clock_timestamp() - interval '1 hour', '[)')`, "TICKET-ALL")
	_ = insert(`tstzrange(clock_timestamp(), clock_timestamp() + interval '20 days', '[)')`, "TICKET-LATER")
	only0 := insert(`tstzrange(clock_timestamp() - interval '2 days', clock_timestamp() - interval '1 hour', '[)')`, "TICKET-0")

	n, err := Notify(ctx, r.app, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Fatalf("notices = %d, want 5", n)
	}
	n, err = Notify(ctx, r.app, tenantB)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("other tenant notices = %d, want 0", n)
	}
	n, err = Notify(ctx, r.app, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("second sweep = %d, want 0", n)
	}

	offsets := func(id uuid.UUID) []int {
		t.Helper()
		rows, err := r.app.QueryContext(ctx, `
			SELECT days_before FROM registry.waiver_notice
			WHERE tenant_id = $1 AND waiver_id = $2
			ORDER BY days_before`, tenantA, id)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = rows.Close() }()
		var got []int
		for rows.Next() {
			var days int
			if err := rows.Scan(&days); err != nil {
				t.Fatal(err)
			}
			got = append(got, days)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return got
	}
	if got := offsets(only14); !slices.Equal(got, []int{14}) {
		t.Errorf("14-day waiver offsets = %v, want [14]", got)
	}
	if got := offsets(allThree); !slices.Equal(got, []int{0, 3, 14}) {
		t.Errorf("expired waiver offsets = %v, want [0 3 14]", got)
	}
	if got := offsets(only0); !slices.Equal(got, []int{0}) {
		t.Errorf("short waiver offsets = %v, want [0]", got)
	}
	var ticket string
	if err := r.app.QueryRowContext(ctx, `
		SELECT ticket_ref FROM registry.waiver_notice
		WHERE tenant_id = $1 AND waiver_id = $2 AND days_before = 14`, tenantA, only14).Scan(&ticket); err != nil {
		t.Fatal(err)
	}
	if ticket != "TICKET-14" {
		t.Errorf("ticket_ref = %q, want TICKET-14", ticket)
	}
}

func TestApplyKeepsTheParentChainAsKnownBeforeAMove(t *testing.T) {
	r := newRegistryDB(t)
	org := r.scope(t, tenantA, uuid.Nil, "org", "acme")
	payments := r.scope(t, tenantA, org, "domain", "payments")
	labs := r.scope(t, tenantA, org, "domain", "labs")
	repo := r.scope(t, tenantA, payments, "repo", "acme/payments")
	decision := uuid.MustParse("00000000-0000-4000-8000-0000000000d1")
	r.decision(t, tenantA, decision, "[2026-01-01,2026-06-01)", payments)
	r.addWaiver(t, tenantA, decision, payments, "[2026-02-01,2026-04-01)", "TICKET-MOVE")

	before := mark(t, r.admin)
	if _, err := r.app.ExecContext(t.Context(), `
		WITH cfg AS (SELECT set_config('ipso.tenant', $1::text, true))
		UPDATE registry.scope AS s SET parent_id = $3 FROM cfg WHERE s.id = $2`, tenantA, repo, labs); err != nil {
		t.Fatal(err)
	}
	after := mark(t, r.admin)
	march := at(t, r, "2026-03-01")
	subject := Subject{Repo: "acme/payments"}

	got, err := Apply(t.Context(), r.app, tenantA, decision, subject, OutcomeFail, march, before)
	if err != nil {
		t.Fatal(err)
	}
	if got != OutcomeWaived {
		t.Errorf("as known before the move = %s, want waived", got)
	}
	got, err = Apply(t.Context(), r.app, tenantA, decision, subject, OutcomeFail, march, after)
	if err != nil {
		t.Fatal(err)
	}
	if got != OutcomeFail {
		t.Errorf("as known after the move = %s, want fail", got)
	}
}

func TestApplyStopsWaivingARetiredScope(t *testing.T) {
	r := newRegistryDB(t)
	org := r.scope(t, tenantA, uuid.Nil, "org", "acme")
	repo := r.scope(t, tenantA, org, "repo", "acme/payments")
	decision := uuid.MustParse("00000000-0000-4000-8000-0000000000d1")
	r.decision(t, tenantA, decision, "[2026-01-01,2026-06-01)", repo)
	r.addWaiver(t, tenantA, decision, repo, "[2026-02-01,2026-04-01)", "TICKET-RETIRE")

	before := mark(t, r.admin)
	if _, err := r.app.ExecContext(t.Context(), `
		WITH cfg AS (SELECT set_config('ipso.tenant', $1::text, true))
		DELETE FROM registry.scope AS s USING cfg WHERE s.id = $2`, tenantA, repo); err != nil {
		t.Fatal(err)
	}
	after := mark(t, r.admin)
	march := at(t, r, "2026-03-01")
	subject := Subject{Repo: "acme/payments"}

	got, err := Apply(t.Context(), r.app, tenantA, decision, subject, OutcomeFail, march, before)
	if err != nil {
		t.Fatal(err)
	}
	if got != OutcomeWaived {
		t.Errorf("as known before retirement = %s, want waived", got)
	}
	got, err = Apply(t.Context(), r.app, tenantA, decision, subject, OutcomeFail, march, after)
	if err != nil {
		t.Fatal(err)
	}
	if got != OutcomeFail {
		t.Errorf("as known after retirement = %s, want fail", got)
	}
}
