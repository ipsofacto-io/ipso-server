//go:build integration

package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
	"github.com/ipsofacto-io/ipso-server/internal/verification"
)

// waiverRig sends the uploads, the waivers and the reads of these tests through the routes. Every call is checked
// against the document on both sides.
type waiverRig struct {
	t       *testing.T
	f       *fixture
	c       contract
	handler http.Handler
	runs    *ci
}

func newWaiverRig(t *testing.T) *waiverRig {
	t.Helper()
	f := newFixture(t)
	handler, runs := f.uploadHandler(t, Limits{Rate: 1000, Burst: 1000})
	runs.maps[501] = Mapping{Tenant: tenantA, Installation: 42}
	return &waiverRig{t: t, f: f, c: newContract(t), handler: handler, runs: runs}
}

// upload stores run n of the repository, with the verdicts of uploadBody changed by mutate.
func (r *waiverRig) upload(n int64, mutate func(report map[string]any, verdicts []any)) {
	r.t.Helper()
	body := uploadBody(r.t, func(_, report map[string]any) {
		if mutate != nil {
			mutate(report, report["verdicts"].([]any))
		}
	})
	if w := r.c.exchange(r.t, r.handler, http.MethodPost, "/v1/verdicts", r.runs.token(uploadedRepo, 501, n, 1), "application/json", body); w.Code != http.StatusCreated {
		r.t.Fatalf("upload of run %d: status %d: %s", n, w.Code, w.Body.String())
	}
}

// waive records a waiver as an approver.
func (r *waiverRig) waive(decision, scope uuid.UUID, from, to time.Time, ticket string) {
	r.t.Helper()
	body, err := json.Marshal(map[string]any{
		"decision_id": decision, "scope_id": scope, "reason": "synthetic exception", "ticket_ref": ticket,
		"valid_from": from.Format(time.RFC3339Nano), "expires_at": to.Format(time.RFC3339Nano),
	})
	if err != nil {
		r.t.Fatal(err)
	}
	if w := r.c.exchange(r.t, r.handler, http.MethodPost, "/v1/waivers", r.f.token(r.t, approverA), "application/json", body); w.Code != http.StatusCreated {
		r.t.Fatalf("waiver %s: status %d: %s", ticket, w.Code, w.Body.String())
	}
}

// read lists the verdicts of the repository as known at a time, by run and then by the EDR id of the decision.
func (r *waiverRig) read(known time.Time) map[float64]map[string]map[string]any {
	r.t.Helper()
	w := r.c.exchange(r.t, r.handler, http.MethodGet, "/v1/verdicts?repo=acme%2Fuploaded&known="+at(known), r.f.token(r.t, personA), "", nil)
	if w.Code != http.StatusOK {
		r.t.Fatalf("read as known at %s: status %d: %s", known, w.Code, w.Body.String())
	}
	out := map[float64]map[string]map[string]any{}
	for _, item := range list(answerOf(r.t, w), "verdicts") {
		v := item.(map[string]any)
		run := v["run_id"].(float64)
		if out[run] == nil {
			out[run] = map[string]map[string]any{}
		}
		out[run][v["decision_id"].(string)] = v
	}
	return out
}

// waiverOf is the waiver reading of a verdict, or nil when it has none.
func waiverOf(t *testing.T, got map[float64]map[string]map[string]any, run float64, decision string) map[string]any {
	t.Helper()
	v := got[run][decision]
	if v == nil {
		t.Fatalf("run %v holds no verdict of %s: %v", run, decision, got[run])
	}
	reading, _ := v["waiver"].(map[string]any)
	return reading
}

func requireReading(t *testing.T, name string, reading map[string]any, result string, end *time.Time) {
	t.Helper()
	if reading == nil || reading["result"] != result {
		t.Errorf("%s: reads %v, want %s", name, reading, result)
		return
	}
	switch {
	case end == nil && reading["expires_at"] != nil:
		t.Errorf("%s: ends at %v, want no end", name, reading["expires_at"])
	case end != nil:
		got, err := time.Parse(time.RFC3339Nano, fmt.Sprint(reading["expires_at"]))
		if err != nil || !got.Equal(end.Truncate(time.Microsecond)) {
			t.Errorf("%s: ends at %v, want %s", name, reading["expires_at"], end)
		}
	}
}

// A waiver that a person recorded is applied to the verdicts of a run when they are read, as known at the time the
// reader gives, and a waiver recorded after a run does not change an answer read as known before it (ADR-0123).
func TestARecordedWaiverIsAppliedToTheVerdictsOfARunWhenTheyAreRead(t *testing.T) {
	r := newWaiverRig(t)
	f := r.f
	tls := f.seedDecisionVersions(t, tenantA, f.org, "tls-waiver", decisionTLS, "[2026-01-01,)")
	pin := f.seedDecisionVersions(t, tenantA, f.org, "pin-waiver", decisionPin, "[2026-01-01,)")

	// Run 1 is stored before any waiver is recorded: its check fails and the other passes.
	r.upload(1, nil)
	beforeWaiver := clock(t, f.db)

	// A waiver of the decision TLS starts before the run was stored, and one of the decision pin starts tomorrow.
	end := beforeWaiver.Add(30 * 24 * time.Hour)
	r.waive(tls, f.org, beforeWaiver.Add(-time.Hour), end, "OPS-1")
	r.waive(pin, f.org, beforeWaiver.Add(24*time.Hour), beforeWaiver.Add(30*24*time.Hour), "OPS-2")
	afterWaiver := clock(t, f.db)

	// Run 2 reports digests for its failing check, and its second check as waived by a local waiver of its own.
	r.upload(2, func(report map[string]any, verdicts []any) {
		report["report_version"] = 2
		verdicts[0].(map[string]any)["fingerprints"] = []any{fmt.Sprintf("%064x", 1), fmt.Sprintf("%064x", 2), fmt.Sprintf("%064x", 3)}
		second := verdicts[1].(map[string]any)
		second["result"], second["violations"], second["fingerprints"] = "waived", 1, []any{}
	})
	// Run 3 has nothing to waive: one check passes and the other did not finish.
	r.upload(3, func(_ map[string]any, verdicts []any) {
		first := verdicts[0].(map[string]any)
		first["result"], first["violations"] = "pass", 0
		second := verdicts[1].(map[string]any)
		second["result"], second["violations"] = "error", 0
	})
	now := clock(t, f.db)

	got := r.read(now)
	if len(got) != 3 {
		t.Fatalf("%d runs read, want 3: %v", len(got), got)
	}
	// Run 1 was stored before the waiver, inside its period, and a waiver that exists when a verdict is read applies.
	requireReading(t, "a failing check, stored before the waiver, inside its period", waiverOf(t, got, 1, decisionTLS), "waived", &end)
	// A passing check has nothing to waive.
	if reading := waiverOf(t, got, 1, decisionPin); reading != nil {
		t.Errorf("a passing check reads %v, want none", reading)
	}
	// Run 2 carries both readings: the baseline that nobody recorded, and the waiver that somebody did.
	requireReading(t, "a failing check, stored after the waiver", waiverOf(t, got, 2, decisionTLS), "waived", &end)
	if b, _ := got[2][decisionTLS]["baseline"].(map[string]any); b == nil || b["result"] != "fail" || b["fingerprints"] != float64(3) || b["waived"] != float64(0) {
		t.Errorf("the same verdict reads %v against the baseline, want fail with none of three matched", got[2][decisionTLS]["baseline"])
	}
	// A check that the run reported as waived is read like a fail: the waiver of its decision starts tomorrow.
	requireReading(t, "a run waived by its local file, with a waiver that has not started", waiverOf(t, got, 2, decisionPin), "fail", nil)
	if got[2][decisionPin]["result"] != "waived" || got[2][decisionPin]["violations"] != float64(1) {
		t.Errorf("a verdict reads %v, %v, want what the run reported", got[2][decisionPin]["result"], got[2][decisionPin]["violations"])
	}
	// A pass and an error have no reading.
	for _, decision := range []string{decisionTLS, decisionPin} {
		if reading := waiverOf(t, got, 3, decision); reading != nil {
			t.Errorf("run 3, %s: reads %v, want none", decision, reading)
		}
	}

	// As known after the waiver and before the later runs, only run 1 is listed and its waiver applies.
	laterRuns := r.read(afterWaiver)
	if len(laterRuns) != 1 {
		t.Fatalf("as known after the waiver: %d runs, want 1", len(laterRuns))
	}
	requireReading(t, "as known after the waiver", waiverOf(t, laterRuns, 1, decisionTLS), "waived", &end)

	// As known before the waiver was recorded, the same run reads fail, and still does after the waiver exists.
	for _, attempt := range []string{"first", "again"} {
		earlier := r.read(beforeWaiver)
		if len(earlier) != 1 {
			t.Fatalf("as known before the waiver (%s): %d runs, want 1", attempt, len(earlier))
		}
		requireReading(t, "as known before the waiver ("+attempt+")", waiverOf(t, earlier, 1, decisionTLS), "fail", nil)
	}
}

// A waiver covers a run when its scope covers every path of the repository: a waiver of an environment covers a run
// that names it and no other, and a waiver of a path covers none, because a report holds no path (ADR-0123).
func TestAWaiverOfAnEnvironmentOrAPathDoesNotWidenToTheRunsOfTheRepository(t *testing.T) {
	r := newWaiverRig(t)
	f := r.f
	scope := func(parent uuid.UUID, kind, selector string) uuid.UUID {
		return f.insert(t, `INSERT INTO registry.scope (tenant_id, parent_id, kind, selector) VALUES ($1, $2, $3, $4) RETURNING id`, tenantA, parent, kind, selector)
	}
	prod := scope(f.org, "env", "prod")
	repo := scope(f.org, "repo", uploadedRepo)
	infra := scope(repo, "path", "infra/**")
	tls := f.seedDecisionVersions(t, tenantA, f.org, "tls-env", decisionTLS, "[2026-01-01,)")
	pin := f.seedDecisionVersions(t, tenantA, f.org, "pin-path", decisionPin, "[2026-01-01,)")

	start := clock(t, f.db)
	r.waive(tls, prod, start.Add(-time.Hour), start.Add(30*24*time.Hour), "OPS-3")
	r.waive(pin, infra, start.Add(-time.Hour), start.Add(30*24*time.Hour), "OPS-4")
	// Both checks fail in every run, for the environments the first run names, and for one that is not a name.
	for run, env := range map[int64]string{1: "prod", 2: "stage", 3: "Not A Name"} {
		r.upload(run, func(report map[string]any, verdicts []any) {
			report["env"] = env
			second := verdicts[1].(map[string]any)
			second["result"], second["violations"] = "fail", 1
		})
	}
	got := r.read(clock(t, f.db))
	if len(got) != 3 {
		t.Fatalf("%d runs read, want 3", len(got))
	}
	end := start.Add(30 * 24 * time.Hour)
	requireReading(t, "an environment waiver, a run of that environment", waiverOf(t, got, 1, decisionTLS), "waived", &end)
	requireReading(t, "an environment waiver, a run of another environment", waiverOf(t, got, 2, decisionTLS), "fail", nil)
	requireReading(t, "an environment waiver, an environment that is not a name", waiverOf(t, got, 3, decisionTLS), "fail", nil)
	for run := float64(1); run <= 3; run++ {
		requireReading(t, "a path waiver, run "+strconv.FormatFloat(run, 'f', 0, 64), waiverOf(t, got, run, decisionPin), "fail", nil)
	}
}

// A failing check whose EDR id names no decision, or more than one, reads fail even when a waiver is recorded for
// one of the decisions that hold the id, because the read never guesses between two decisions (ADR-0123).
func TestAVerdictWhoseDecisionIsUnknownOrAmbiguousReadsFail(t *testing.T) {
	r := newWaiverRig(t)
	f := r.f
	one := f.seedDecisionVersions(t, tenantA, f.org, "tls-one", decisionTLS, "[2026-01-01,)")
	f.seedDecisionVersions(t, tenantA, f.org, "tls-two", decisionTLS, "[2026-01-01,)")
	start := clock(t, f.db)
	// A waiver of the first decision would cover the run if the id named it alone, as the first test of this file shows.
	r.waive(one, f.org, start.Add(-time.Hour), start.Add(30*24*time.Hour), "OPS-5")
	// The decision of the pin check does not exist, and the two that hold the EDR id of the TLS check are
	// ambiguous, so the waiver of one of them does not apply to the verdict.
	r.upload(1, func(_ map[string]any, verdicts []any) {
		second := verdicts[1].(map[string]any)
		second["result"], second["violations"] = "fail", 1
	})
	got := r.read(clock(t, f.db))
	requireReading(t, "an ambiguous EDR id", waiverOf(t, got, 1, decisionTLS), "fail", nil)
	requireReading(t, "an unknown EDR id", waiverOf(t, got, 1, decisionPin), "fail", nil)
}

// The seed of the pact state of a verdict that a recorded waiver covers is also proved here, where the Pact library
// need not run (see seedVerdictInBaseline).
func TestThePactStateSeedsAVerdictThatReadsAsCoveredByAWaiver(t *testing.T) {
	f := newFixture(t)
	c := newContract(t)
	handler, _ := f.uploadHandler(t, Limits{Rate: 1000, Burst: 1000})
	if err := f.seedVerdictWaived(t, 1); err != nil {
		t.Fatal(err)
	}
	w := c.exchange(t, handler, http.MethodGet, "/v1/verdicts?decision="+pactWaivedEDRID+"&limit=20", f.token(t, personA), "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	items := list(answerOf(t, w), "verdicts")
	if len(items) != 1 {
		t.Fatalf("%d verdicts, want 1: %s", len(items), w.Body.String())
	}
	reading, _ := items[0].(map[string]any)["waiver"].(map[string]any)
	if reading == nil || reading["result"] != "waived" || reading["expires_at"] == nil {
		t.Errorf("the verdict reads %v, want waived with an end", reading)
	}
}

// pactWaivedEDRID is the EDR id of the decision that the pact state of a verdict covered by a recorded waiver seeds.
// It is not the id of seedVerdictInBaseline, because two decisions that hold one id are ambiguous.
const pactWaivedEDRID = "01M7PACT000000000000000001"

// seedVerdictWaived seeds what the provider state of the pact names: a decision whose body holds pactWaivedEDRID, a
// waiver of its org that a human approver recorded and whose period holds now, and one upload for acme/waived whose
// failing verdict for that decision carries no digest.
func (f *fixture) seedVerdictWaived(t *testing.T, n int64) error {
	t.Helper()
	ctx := t.Context()
	decision := uuid.New()
	body, err := json.Marshal(map[string]any{"slug": "synthetic-waived-" + strconv.FormatInt(n, 10), "title": "A decision with a recorded waiver", "id": pactWaivedEDRID})
	if err != nil {
		return err
	}
	for _, step := range []struct {
		what  string
		query string
		args  []any
	}{
		{"the decision", `
			INSERT INTO registry.decision_version (decision_id, version, tenant_id, body, scope_refs, valid_period)
			VALUES ($1, 1, $2, $3::jsonb, ARRAY[$4::uuid], '[2026-01-01,)'::tstzrange)`, []any{decision, tenantA, string(body), f.org}},
		{"the waiver", `
			INSERT INTO registry.waiver (tenant_id, decision_id, scope_id, reason, approver, approver_id, valid_period, ticket_ref)
			VALUES ($1, $2, $3, 'synthetic exception', 'team:platform', $4,
			        tstzrange(clock_timestamp() - interval '1 day', clock_timestamp() + interval '60 days', '[)'), 'OPS-7')`,
			[]any{tenantA, decision, f.org, f.callers[approverA].Principal}},
	} {
		if _, err := pgtest.Exec(ctx, f.db, tenantA.String(), step.query, step.args...); err != nil {
			return fmt.Errorf("seed %s: %w", step.what, err)
		}
	}
	up, err := verification.Parse(uploadBody(t, func(_, report map[string]any) {
		verdicts := report["verdicts"].([]any)
		failing := verdicts[0].(map[string]any)
		failing["decision_id"], failing["violations"] = pactWaivedEDRID, 2
	}))
	if err != nil {
		return err
	}
	_, err = verification.Store(ctx, f.db, tenantA, verification.Run{
		Installation: 42, RepositoryID: 9200 + n, Repo: "acme/waived", RunID: 9200 + n, RunAttempt: 1,
		SHA: strings.Repeat("ab", 20), Ref: "refs/heads/main", Event: "push",
		WorkflowRef: "acme/waived/.github/workflows/ci.yml@refs/heads/main",
	}, up)
	return err
}
