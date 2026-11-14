//go:build integration

package api

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

// rigSHA is the commit that every run of the waiver rig names in its token.
var rigSHA = strings.Repeat("c0", 20)

// merge asks Q3 about the repository of the rig and a commit, as an auditor, with a transaction time. The decisions are
// those of the valid time of the fixture. It returns the status, the answer, and the verdicts of the answer by run and
// then by the EDR id of the decision, the way read lists them.
func (r *waiverRig) merge(known time.Time, sha string) (int, map[string]any, map[float64]map[string]map[string]any) {
	r.t.Helper()
	target := "/v1/audit/merges?repo=acme%2Fuploaded&at=" + at(r.f.valid) + "&known=" + at(known) + "&sha=" + sha
	w := r.c.exchange(r.t, r.handler, http.MethodGet, target, r.f.token(r.t, auditorA), "", nil)
	answer := answerOf(r.t, w)
	out := map[float64]map[string]map[string]any{}
	for _, item := range list(answer, "verdicts") {
		v := item.(map[string]any)
		run := v["run_id"].(float64)
		if out[run] == nil {
			out[run] = map[string]map[string]any{}
		}
		out[run][v["decision_id"].(string)] = v
	}
	return w.Code, answer, out
}

// A verdict on Q3 reads as it does on the verdict list for the same transaction time: the same item, with the same
// baseline and waiver, whether the waiver was recorded before or after the time asked about, and a commit that was not
// stored by then is unknown (ADR-0124).
func TestQ3ReadsTheVerdictsOfACommitAsTheVerdictListReadsThemForTheSameKnownTime(t *testing.T) {
	r := newWaiverRig(t)
	f := r.f
	tls := f.seedDecisionVersions(t, tenantA, f.org, "tls-waiver", decisionTLS, "[2026-01-01,)")
	start := clock(t, f.db)

	r.upload(1, nil)
	beforeWaiver := clock(t, f.db)
	end := beforeWaiver.Add(30 * 24 * time.Hour)
	r.waive(tls, f.org, beforeWaiver.Add(-time.Hour), end, "OPS-1")
	afterWaiver := clock(t, f.db)
	r.upload(2, func(report map[string]any, verdicts []any) {
		report["report_version"] = 2
		// A version 2 report carries the key on every verdict, empty where there is nothing to cover.
		verdicts[0].(map[string]any)["fingerprints"] = []any{strings.Repeat("00", 31) + "01", strings.Repeat("00", 31) + "02", strings.Repeat("00", 31) + "03"}
		verdicts[1].(map[string]any)["fingerprints"] = []any{}
	})
	now := clock(t, f.db)

	// Before any run was stored the commit is unknown: the key is there and it is null, never an empty list.
	status, answer, none := r.merge(start, rigSHA)
	if verdicts, present := answer["verdicts"]; status != http.StatusOK || !present || verdicts != nil || len(none) != 0 {
		t.Fatalf("a commit that no run reported on by then: status %d, verdicts %v (present %v), want null", status, verdicts, present)
	}
	if len(list(answer, "decisions")) == 0 {
		t.Errorf("the decisions are still read: %v", answer)
	}

	for name, known := range map[string]time.Time{"before the waiver": beforeWaiver, "after the waiver": afterWaiver, "after every run": now} {
		onList := r.read(known)
		status, _, onCommit := r.merge(known, rigSHA)
		if status != http.StatusOK || len(onCommit) == 0 {
			t.Fatalf("as known %s: status %d, %d runs", name, status, len(onCommit))
		}
		if !reflect.DeepEqual(onList, onCommit) {
			t.Errorf("as known %s, the commit reads\n%v\nand the list reads\n%v", name, onCommit, onList)
		}
	}

	// The readings themselves: the waiver recorded after run 1 does not change an answer read as known before it, and
	// it applies to the same run once it is known.
	_, _, before := r.merge(beforeWaiver, rigSHA)
	requireReading(t, "as known before the waiver", waiverOf(t, before, 1, decisionTLS), "fail", nil)
	_, _, after := r.merge(now, rigSHA)
	requireReading(t, "as known after the waiver", waiverOf(t, after, 1, decisionTLS), "waived", &end)
	requireReading(t, "a run with digests, as known after the waiver", waiverOf(t, after, 2, decisionTLS), "waived", &end)
	if b, _ := after[2][decisionTLS]["baseline"].(map[string]any); b == nil || b["result"] != "fail" || b["fingerprints"] != float64(3) {
		t.Errorf("the baseline reading of run 2 is %v, want fail with three digests", after[2][decisionTLS]["baseline"])
	}
	// Run 2 was stored after the waiver was recorded and before it was asked about: a read as known between them has
	// only run 1.
	if _, _, between := r.merge(afterWaiver, rigSHA); len(between) != 1 || between[1] == nil {
		t.Errorf("as known after the waiver and before run 2: %v, want run 1 only", between)
	}
}

// A commit that no run named is unknown whatever else the repository holds, a commit is read in either case, and a
// tenant reads only its own uploads.
func TestQ3ReadsAnotherCommitAsUnknownAndAnotherTenantsUploadsNotAtAll(t *testing.T) {
	r := newWaiverRig(t)
	f := r.f
	r.upload(1, nil)
	known := clock(t, f.db)

	if status, answer, _ := r.merge(known, strings.Repeat("d1", 20)); status != http.StatusOK || answer["verdicts"] != nil {
		t.Errorf("another commit of the repository: status %d, verdicts %v, want null", status, answer["verdicts"])
	}
	if status, answer, runs := r.merge(known, strings.ToUpper(rigSHA)); status != http.StatusOK || len(list(answer, "verdicts")) != 2 || len(runs) != 1 {
		t.Errorf("the commit in upper case: status %d, %d verdicts, want the two of run 1", status, len(list(answer, "verdicts")))
	}

	// path and env narrow the decisions and never the verdicts: the run reported the environment prod, and a question that
	// names another environment and a path still reads it, so a failing run in one environment is never hidden (ADR-0124).
	narrowed := "/v1/audit/merges?repo=acme%2Fuploaded&at=" + at(f.valid) + "&known=" + at(known) + "&sha=" + rigSHA + "&env=staging&path=docs%2Fa.md"
	w := r.c.exchange(t, r.handler, http.MethodGet, narrowed, f.token(t, auditorA), "", nil)
	if verdicts := list(answerOf(t, w), "verdicts"); w.Code != http.StatusOK || len(verdicts) != 2 {
		t.Errorf("a question that names another environment and a path: status %d, %d verdicts, want the two of run 1", w.Code, len(verdicts))
	}

	// Tenant A seeded one verdict for acme/api, and tenant B one for globex/web on the same commit.
	for repo, want := range map[string]int{"acme/api": 1, "globex/web": 0} {
		target := "/v1/audit/merges?repo=" + strings.ReplaceAll(repo, "/", "%2F") + "&at=" + at(f.valid) + "&known=" + at(known) + "&sha=" + seededSHA
		w := r.c.exchange(t, r.handler, http.MethodGet, target, f.token(t, auditorA), "", nil)
		answer := answerOf(t, w)
		if w.Code != http.StatusOK || len(list(answer, "verdicts")) != want || (want == 0 && answer["verdicts"] != nil) {
			t.Errorf("%s: status %d, verdicts %v, want %d", repo, w.Code, answer["verdicts"], want)
		}
	}
}

// A commit that is not a commit is refused, and a commit with more verdicts than one answer holds is refused whole.
func TestQ3RefusesABadCommitAndACommitWithTooManyVerdictsWhole(t *testing.T) {
	r := newWaiverRig(t)
	known := clock(t, r.f.db)
	// The document refuses these commits too, so the requests go past the contract check.
	for _, sha := range []string{"main", rigSHA[:7], strings.Repeat("zz", 20), ""} {
		request := httptest.NewRequest(http.MethodGet, "/v1/audit/merges?repo=acme%2Fuploaded&at="+at(r.f.valid)+"&known="+at(known)+"&sha="+sha, nil)
		request.Header.Set("Authorization", r.f.token(t, auditorA))
		w := httptest.NewRecorder()
		r.handler.ServeHTTP(w, request)
		if w.Code != http.StatusBadRequest || errorOf(t, w) != errInvalidQuery {
			t.Errorf("sha %q: status %d, %s, want 400 invalid query", sha, w.Code, w.Body.String())
		}
	}
	// A request with no commit at all is refused the same way.
	request := httptest.NewRequest(http.MethodGet, "/v1/audit/merges?repo=acme%2Fuploaded&at="+at(r.f.valid), nil)
	request.Header.Set("Authorization", r.f.token(t, auditorA))
	w := httptest.NewRecorder()
	r.handler.ServeHTTP(w, request)
	if w.Code != http.StatusBadRequest || errorOf(t, w) != errInvalidQuery {
		t.Errorf("no sha: status %d, %s, want 400 invalid query", w.Code, w.Body.String())
	}

	r.upload(1, func(report map[string]any, _ []any) {
		verdicts := make([]any, 1001)
		for i := range verdicts {
			verdicts[i] = map[string]any{"decision_id": decisionTLS, "slug": "use-tls", "check_index": i, "mode": "warn", "result": "pass", "violations": 0}
		}
		report["verdicts"] = verdicts
	})
	status, answer, _ := r.merge(clock(t, r.f.db), rigSHA)
	if status != http.StatusInternalServerError || answer["error"] != "response too large" || answer["verdicts"] != nil {
		t.Errorf("1001 verdicts: status %d, %v, want 500 response too large and no verdicts", status, answer)
	}
}

// pactMergedEDRID, pactMergedRepo and pactMergedSHA are the decision, the repository and the commit that the pact state of
// a merged commit seeds. The id and the repository are not those of the other waived state, because two decisions that
// hold one id are ambiguous and read fail.
const (
	pactMergedEDRID = "01M7PACT000000000000000002"
	pactMergedRepo  = "acme/merged"
)

var pactMergedSHA = strings.Repeat("ef", 20)

// seedMergedCommit seeds what the provider state of the pact names: a waiver that a person recorded for a decision, and
// one run of pactMergedRepo on pactMergedSHA whose failing verdict for that decision the waiver covers.
func (f *fixture) seedMergedCommit(t *testing.T, n int64) error {
	t.Helper()
	return f.seedWaivedRun(t, n, waivedRun{edrID: pactMergedEDRID, slug: "synthetic-merged-", repo: pactMergedRepo, sha: pactMergedSHA})
}

func TestThePactStateSeedsAMergedCommitThatQ3ReadsAsCoveredByAWaiver(t *testing.T) {
	f := newFixture(t)
	c := newContract(t)
	handler, _ := f.uploadHandler(t, Limits{Rate: 1000, Burst: 1000})
	if err := f.seedMergedCommit(t, 1); err != nil {
		t.Fatal(err)
	}
	target := "/v1/audit/merges?repo=" + strings.ReplaceAll(pactMergedRepo, "/", "%2F") + "&sha=" + pactMergedSHA + "&at=" + at(f.valid) + "&known=2099-01-01T00%3A00%3A00Z"
	w := c.exchange(t, handler, http.MethodGet, target, f.token(t, personA), "", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	answer := answerOf(t, w)
	items := list(answer, "verdicts")
	// Q3 names no decision, so it returns both verdicts of the run: the failing one that the waiver covers, which the pact
	// reads, and the passing one, which has nothing to waive.
	if len(list(answer, "decisions")) == 0 || len(items) != 2 {
		t.Fatalf("%d decisions and %d verdicts, want some and 2: %s", len(list(answer, "decisions")), len(items), w.Body.String())
	}
	covered := 0
	for _, item := range items {
		verdict := item.(map[string]any)
		reading, _ := verdict["waiver"].(map[string]any)
		switch {
		case verdict["decision_id"] == pactMergedEDRID && (reading == nil || reading["result"] != "waived" || reading["expires_at"] == nil):
			t.Errorf("the failing verdict reads %v, want waived with an end", reading)
		case verdict["decision_id"] == pactMergedEDRID:
			covered++
		case reading != nil:
			t.Errorf("a passing verdict reads %v, want none", reading)
		}
	}
	if covered != 1 {
		t.Errorf("%d verdicts of the decision read waived, want 1", covered)
	}
}
