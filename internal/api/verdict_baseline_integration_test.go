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

// A baseline that a person recorded is applied to the verdicts of a run when they are read, as known at the
// time the reader gives, and only digests were sent (ADR-0122). Every call goes through the routes and is
// checked against the document on both sides.
func TestARecordedBaselineIsAppliedToTheVerdictsOfARunWhenTheyAreRead(t *testing.T) {
	f := newFixture(t)
	c := newContract(t)
	handler, runs := f.uploadHandler(t, Limits{Rate: 1000, Burst: 1000})
	runs.maps[501] = Mapping{Tenant: tenantA, Installation: 42}
	const repo = uploadedRepo
	decision := f.seedDecisionVersions(t, tenantA, f.org, "tls-baseline", decisionTLS, "[2026-01-01,)")
	owner, reader := f.token(t, ownerA), f.token(t, personA)

	digest := func(i int) string { return fmt.Sprintf("%064x", i) }
	digests := func(indexes ...int) []any {
		out := make([]any, len(indexes))
		for i, n := range indexes {
			out[i] = digest(n)
		}
		return out
	}
	// upload sends a version 2 report: the failing check holds the digests, and the passing one has none.
	upload := func(run int64, list []any) {
		t.Helper()
		body := uploadBody(t, func(_, report map[string]any) {
			report["report_version"] = 2
			verdicts := report["verdicts"].([]any)
			verdicts[0].(map[string]any)["fingerprints"] = list
			verdicts[1].(map[string]any)["fingerprints"] = []any{}
		})
		if w := c.exchange(t, handler, http.MethodPost, "/v1/verdicts", runs.token(repo, 501, run, 1), "application/json", body); w.Code != http.StatusCreated {
			t.Fatalf("upload of run %d: status %d: %s", run, w.Code, w.Body.String())
		}
	}
	read := func(known time.Time) map[string]any {
		t.Helper()
		w := c.exchange(t, handler, http.MethodGet, "/v1/verdicts?repo=acme%2Fuploaded&known="+at(known), reader, "", nil)
		if w.Code != http.StatusOK {
			t.Fatalf("read as known at %s: status %d: %s", known, w.Code, w.Body.String())
		}
		return answerOf(t, w)
	}
	// reading returns the reading of the failing check of each run, by run, and whether the passing check
	// of that run has none.
	reading := func(answer map[string]any) map[float64]map[string]any {
		t.Helper()
		out := map[float64]map[string]any{}
		for _, item := range list(answer, "verdicts") {
			v := item.(map[string]any)
			switch v["decision_id"] {
			case decisionTLS:
				baseline, _ := v["baseline"].(map[string]any)
				out[v["run_id"].(float64)] = baseline
			case decisionPin:
				if v["baseline"] != nil {
					t.Errorf("the check with no digest has the reading %v", v["baseline"])
				}
			}
		}
		return out
	}

	// The decision has grandfather terms, and the first run is stored before any baseline is recorded.
	if w := c.exchange(t, handler, http.MethodPost, "/v1/decisions/"+decision.String()+"/grandfather-period", owner, "application/json",
		[]byte(`{"valid_from":"2026-03-01T00:00:00Z"}`)); w.Code != http.StatusCreated {
		t.Fatalf("grandfather period: status %d: %s", w.Code, w.Body.String())
	}
	upload(1, digests(1, 2, 3))
	beforeBaseline := clock(t, f.db)

	baselineBody := fmt.Sprintf(`{"repo":%q,"fingerprints":[%q,%q,%q]}`, repo, digest(1), digest(2), digest(3))
	if w := c.exchange(t, handler, http.MethodPost, "/v1/decisions/"+decision.String()+"/baselines", owner, "application/json", []byte(baselineBody)); w.Code != http.StatusCreated {
		t.Fatalf("baseline: status %d: %s", w.Code, w.Body.String())
	}
	afterBaseline := clock(t, f.db)

	// Two runs after the baseline: one whose violations are all in it, and one with a violation that is not.
	upload(2, digests(1, 2, 3))
	upload(3, digests(2, 3, 4))
	now := clock(t, f.db)

	// Read now, every run is read against the baseline as it stands: the first run was stored before it
	// was recorded, and a baseline that exists when a verdict is read applies to it.
	answer := read(now)
	if echoed, err := time.Parse(time.RFC3339Nano, answer["known"].(string)); err != nil || !echoed.Equal(now) {
		t.Errorf("the answer echoes known = %v, want %s", answer["known"], now)
	}
	expect := func(name string, got map[float64]map[string]any, run float64, result string, sent, matched float64) {
		t.Helper()
		b := got[run]
		if b == nil || b["result"] != result || b["fingerprints"] != sent || b["waived"] != matched {
			t.Errorf("%s: run %v reads %v, want %s with %v of %v digests in the baseline", name, run, b, result, matched, sent)
		}
	}
	now3 := reading(answer)
	if len(now3) != 3 {
		t.Fatalf("%d runs read, want 3: %v", len(now3), now3)
	}
	expect("all recorded, stored before the baseline", now3, 1, "waived(baseline)", 3, 3)
	expect("all recorded, stored after the baseline", now3, 2, "waived(baseline)", 3, 3)
	expect("one violation that is not in the baseline", now3, 3, "fail", 3, 2)

	// As known after the baseline and before the later runs, only the first run is listed.
	laterRuns := reading(read(afterBaseline))
	if len(laterRuns) != 1 {
		t.Fatalf("as known after the baseline: %d runs, want 1", len(laterRuns))
	}
	expect("as known after the baseline", laterRuns, 1, "waived(baseline)", 3, 3)

	// As known before the baseline was recorded, the same run reads fail with none matched, and still does
	// when it is read again after the baseline exists.
	for _, attempt := range []string{"first", "again"} {
		earlier := reading(read(beforeBaseline))
		if len(earlier) != 1 {
			t.Fatalf("as known before the baseline (%s): %d runs, want 1", attempt, len(earlier))
		}
		expect("as known before the baseline ("+attempt+")", earlier, 1, "fail", 3, 0)
	}

	// What the run reported is untouched, whatever the reading says.
	for _, item := range list(read(now), "verdicts") {
		v := item.(map[string]any)
		if v["decision_id"] == decisionTLS && (v["result"] != "fail" || v["violations"] != float64(3)) {
			t.Errorf("a run reads %v, %v, want what it reported", v["result"], v["violations"])
		}
	}
}

// A version 1 report has no digests, so its verdicts have no reading, and a verdict of a run for a decision that
// has no recorded baseline reads fail with none matched.
func TestAVerdictWithNoDigestHasNoReadingAndOneWithNoBaselineReadsFail(t *testing.T) {
	f := newFixture(t)
	c := newContract(t)
	handler, runs := f.uploadHandler(t, Limits{Rate: 1000, Burst: 1000})
	runs.maps[501] = Mapping{Tenant: tenantA, Installation: 42}
	f.seedDecisionVersions(t, tenantA, f.org, "tls-baseline", decisionTLS, "[2026-01-01,)")
	reader := f.token(t, personA)

	if w := c.exchange(t, handler, http.MethodPost, "/v1/verdicts", runs.token(uploadedRepo, 501, 1, 1), "application/json", uploadBody(t, nil)); w.Code != http.StatusCreated {
		t.Fatalf("version 1 upload: status %d: %s", w.Code, w.Body.String())
	}
	version2 := uploadBody(t, func(_, report map[string]any) {
		report["report_version"] = 2
		verdicts := report["verdicts"].([]any)
		verdicts[0].(map[string]any)["fingerprints"] = []any{fmt.Sprintf("%064x", 1), fmt.Sprintf("%064x", 2), fmt.Sprintf("%064x", 3)}
		verdicts[1].(map[string]any)["fingerprints"] = []any{}
		report["env"] = "stage"
	})
	if w := c.exchange(t, handler, http.MethodPost, "/v1/verdicts", runs.token(uploadedRepo, 501, 2, 1), "application/json", version2); w.Code != http.StatusCreated {
		t.Fatalf("version 2 upload: status %d: %s", w.Code, w.Body.String())
	}
	w := c.exchange(t, handler, http.MethodGet, "/v1/verdicts?repo=acme%2Fuploaded&decision="+decisionTLS, reader, "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("read: status %d: %s", w.Code, w.Body.String())
	}
	items := list(answerOf(t, w), "verdicts")
	if len(items) != 2 {
		t.Fatalf("%d verdicts, want 2", len(items))
	}
	for _, item := range items {
		v := item.(map[string]any)
		switch v["run_id"] {
		case float64(1):
			if v["baseline"] != nil {
				t.Errorf("a version 1 verdict has the reading %v", v["baseline"])
			}
		case float64(2):
			if b, _ := v["baseline"].(map[string]any); b == nil || b["result"] != "fail" || b["fingerprints"] != float64(3) || b["waived"] != float64(0) {
				t.Errorf("a verdict with no recorded baseline reads %v, want fail with three digests and none matched", v["baseline"])
			}
		}
	}
}

// The upload refuses a version 2 report that breaks the rules for the digests, and stores nothing.
func TestAnUploadWithBrokenDigestsIsRefusedAndStoresNothing(t *testing.T) {
	f := newFixture(t)
	handler, runs := f.uploadHandler(t, Limits{Rate: 1000, Burst: 1000})
	runs.maps[501] = Mapping{Tenant: tenantA, Installation: 42}
	digest := func(i int) string { return fmt.Sprintf("%064x", i) }
	for name, mutate := range map[string]func(upload, report map[string]any){
		"an unsorted list": func(_, report map[string]any) {
			report["report_version"] = 2
			verdicts := report["verdicts"].([]any)
			verdicts[0].(map[string]any)["fingerprints"] = []any{digest(2), digest(1), digest(3)}
			verdicts[1].(map[string]any)["fingerprints"] = []any{}
		},
		"fewer digests than violations": func(_, report map[string]any) {
			report["report_version"] = 2
			verdicts := report["verdicts"].([]any)
			verdicts[0].(map[string]any)["fingerprints"] = []any{digest(1)}
			verdicts[1].(map[string]any)["fingerprints"] = []any{}
		},
		"digests on a pass": func(_, report map[string]any) {
			report["report_version"] = 2
			verdicts := report["verdicts"].([]any)
			verdicts[0].(map[string]any)["fingerprints"] = []any{}
			verdicts[1].(map[string]any)["fingerprints"] = []any{digest(1)}
		},
		"version 2 with no digests": func(_, report map[string]any) { report["report_version"] = 2 },
		"a list on a version 1 report": func(_, report map[string]any) {
			report["verdicts"].([]any)[0].(map[string]any)["fingerprints"] = []any{digest(1), digest(2), digest(3)}
		},
	} {
		w := raw(handler, http.MethodPost, "/v1/verdicts", runs.token(uploadedRepo, 501, 1, 1), "application/json", uploadBody(t, mutate))
		if w.Code != http.StatusBadRequest || errorOf(t, w) != errInvalidQuery {
			t.Errorf("%s: status %d %s, want 400", name, w.Code, w.Body.String())
		}
	}
	if n := f.count(t, tenantA, "verification.upload", uploadedRepo); n != 0 {
		t.Errorf("%d uploads stored, want none", n)
	}
}

// pactEDRID is the EDR id of the decision that the pact state of a verdict in a recorded baseline seeds.
const pactEDRID = "01M7PACT000000000000000000"

// seedVerdictInBaseline seeds what the provider state of the pact names: a decision whose body holds pactEDRID, its
// grandfather terms, a baseline of two digests for acme/baselined, and one version 2 upload there whose failing
// verdict for that decision carries exactly those digests. It is a helper of the pact and a test of its own, because
// the provider verification needs the Pact library and the seed has to be proved where that cannot run.
func (f *fixture) seedVerdictInBaseline(t *testing.T, n int64) error {
	t.Helper()
	ctx := t.Context()
	decision := uuid.New()
	body, err := json.Marshal(map[string]any{"slug": "synthetic-read-" + strconv.FormatInt(n, 10), "title": "A decision with a recorded baseline", "id": pactEDRID})
	if err != nil {
		return err
	}
	digests := []string{fmt.Sprintf("%064x", 1), fmt.Sprintf("%064x", 2)}
	for _, step := range []struct {
		what  string
		query string
		args  []any
	}{
		{"the decision", `
			INSERT INTO registry.decision_version (decision_id, version, tenant_id, body, scope_refs, valid_period)
			VALUES ($1, 1, $2, $3::jsonb, ARRAY[$4::uuid], '[2026-01-01,)'::tstzrange)`, []any{decision, tenantA, string(body), f.org}},
		{"the grandfather terms", `
			INSERT INTO registry.grandfather_period (tenant_id, decision_id, valid_period)
			VALUES ($1, $2, tstzrange('2026-03-01T00:00:00Z'::timestamptz, NULL, '[)'))`, []any{tenantA, decision}},
		{"the baseline", `
			INSERT INTO registry.baseline (tenant_id, decision_id, repo, fingerprints)
			VALUES ($1, $2, 'acme/baselined', (SELECT array_agg(decode(h, 'hex')) FROM unnest($3::text[]) AS h))`, []any{tenantA, decision, digests}},
	} {
		if _, err := pgtest.Exec(ctx, f.db, tenantA.String(), step.query, step.args...); err != nil {
			return fmt.Errorf("seed %s: %w", step.what, err)
		}
	}
	up, err := verification.Parse(uploadBody(t, func(_, report map[string]any) {
		report["report_version"] = 2
		verdicts := report["verdicts"].([]any)
		failing := verdicts[0].(map[string]any)
		failing["decision_id"], failing["violations"], failing["fingerprints"] = pactEDRID, 2, []any{digests[0], digests[1]}
		verdicts[1].(map[string]any)["fingerprints"] = []any{}
	}))
	if err != nil {
		return err
	}
	_, err = verification.Store(ctx, f.db, tenantA, verification.Run{
		Installation: 42, RepositoryID: 9100 + n, Repo: "acme/baselined", RunID: 9100 + n, RunAttempt: 1,
		SHA: strings.Repeat("ab", 20), Ref: "refs/heads/main", Event: "push",
		WorkflowRef: "acme/baselined/.github/workflows/ci.yml@refs/heads/main",
	}, up)
	return err
}

func TestThePactStateSeedsAVerdictThatReadsAsWaived(t *testing.T) {
	f := newFixture(t)
	c := newContract(t)
	handler, _ := f.uploadHandler(t, Limits{Rate: 1000, Burst: 1000})
	if err := f.seedVerdictInBaseline(t, 1); err != nil {
		t.Fatal(err)
	}
	w := c.exchange(t, handler, http.MethodGet, "/v1/verdicts?decision="+pactEDRID+"&limit=20", f.token(t, personA), "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	items := list(answerOf(t, w), "verdicts")
	if len(items) != 1 {
		t.Fatalf("%d verdicts, want 1: %s", len(items), w.Body.String())
	}
	item := items[0].(map[string]any)
	baseline, _ := item["baseline"].(map[string]any)
	if item["result"] != "fail" || item["violations"] != float64(2) || baseline["result"] != "waived(baseline)" || baseline["fingerprints"] != float64(2) || baseline["waived"] != float64(2) {
		t.Errorf("item = %v", item)
	}
}
