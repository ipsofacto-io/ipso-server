//go:build integration

package verification

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
)

// world is a store with a registry scope for each tenant, so that decisions can be recorded.
type world struct {
	*store
	scope map[uuid.UUID]uuid.UUID
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{store: newStore(t), scope: map[uuid.UUID]uuid.UUID{}}
	for _, tenant := range []uuid.UUID{tenantA, tenantB} {
		var id uuid.UUID
		if err := pgtest.Scan(t.Context(), w.app, tenant.String(),
			`INSERT INTO registry.scope (tenant_id, parent_id, kind, selector) VALUES ($1, NULL, 'org', 'acme') RETURNING id`,
			[]any{tenant}, &id); err != nil {
			t.Fatal(err)
		}
		w.scope[tenant] = id
	}
	return w
}

// decision records a decision whose body holds edrID as its id, valid from the year 2000.
func (w *world) decision(t *testing.T, tenant uuid.UUID, edrID string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := pgtest.Exec(t.Context(), w.app, tenant.String(), `
		INSERT INTO registry.decision_version (decision_id, version, tenant_id, body, scope_refs, valid_period)
		VALUES ($1, 1, $2, jsonb_build_object('id', $3::text, 'slug', 'a-decision'), ARRAY[$4::uuid], '[2000-01-01,)'::tstzrange)`,
		id, tenant, edrID, w.scope[tenant]); err != nil {
		t.Fatalf("record the decision: %v", err)
	}
	return id
}

// period records the grandfather terms of a decision. valid is a tstzrange literal.
func (w *world) period(t *testing.T, tenant, decision uuid.UUID, valid string) {
	t.Helper()
	if _, err := pgtest.Exec(t.Context(), w.app, tenant.String(), `
		INSERT INTO registry.grandfather_period (tenant_id, decision_id, valid_period) VALUES ($1, $2, $3::text::tstzrange)`,
		tenant, decision, valid); err != nil {
		t.Fatalf("record the period: %v", err)
	}
}

func (w *world) baseline(t *testing.T, tenant, decision uuid.UUID, repo string, digests []any) {
	t.Helper()
	hexes := make([]string, len(digests))
	for i, d := range digests {
		hexes[i] = d.(string)
	}
	if _, err := pgtest.Exec(t.Context(), w.app, tenant.String(), `
		INSERT INTO registry.baseline (tenant_id, decision_id, repo, fingerprints)
		VALUES ($1, $2, $3, (SELECT array_agg(decode(h, 'hex')) FROM unnest($4::text[]) AS h))`,
		tenant, decision, repo, hexes); err != nil {
		t.Fatalf("record the baseline: %v", err)
	}
}

// upload stores a version 2 plan report. The fail verdict (idOne, 3 violations) carries fail, and the pass
// verdict (idTwo) carries pass.
func (w *world) upload(t *testing.T, repo string, runID int64, pass, fail []any) {
	t.Helper()
	if _, err := Store(t.Context(), w.app, tenantA, run(repo, runID, 1), parsed(t, "plan", version2(pass, fail))); err != nil {
		t.Fatal(err)
	}
}

func baselineOf(t *testing.T, items []Item, edrID string) *Baseline {
	t.Helper()
	for _, it := range items {
		if it.DecisionID == edrID {
			return it.Baseline
		}
	}
	t.Fatalf("no verdict of %s in %d items", edrID, len(items))
	return nil
}

func TestAVerdictWhoseDigestsAreAllRecordedReadsAsWaivedAndOneWithANewDigestDoesNot(t *testing.T) {
	w := newWorld(t)
	decision := w.decision(t, tenantA, idOne)
	w.period(t, tenantA, decision, "[2000-01-01,)")
	w.baseline(t, tenantA, decision, "acme/api", digestsFrom(1, 3))
	w.upload(t, "acme/api", 1, []any{}, digestsFrom(1, 3))
	w.upload(t, "acme/api", 2, []any{}, digestsFrom(2, 3))

	items, err := List(t.Context(), w.app, tenantA, Filter{Repo: "acme/api", Decision: idOne}, 10, uuid.Nil, w.soon(t))
	if err != nil || len(items) != 2 {
		t.Fatalf("List = %d items, %v", len(items), err)
	}
	// Newest first: the second run holds a digest that is not in the baseline.
	if got := items[0].Baseline; got == nil || got.Result != "fail" || got.Fingerprints != 3 || got.Waived != 2 {
		t.Errorf("a new digest: baseline = %+v, want fail, 3 digests, 2 in the baseline", got)
	}
	if got := items[1].Baseline; got == nil || got.Result != "waived(baseline)" || got.Fingerprints != 3 || got.Waived != 3 {
		t.Errorf("all recorded: baseline = %+v, want waived(baseline), 3 of 3", got)
	}
	// What the run reported is untouched.
	if items[0].Result != "fail" || items[0].Violations != 3 || items[1].Result != "fail" {
		t.Errorf("results = %s and %s, want what the runs reported", items[0].Result, items[1].Result)
	}
	// A verdict with no digest has no reading.
	all, err := List(t.Context(), w.app, tenantA, Filter{Repo: "acme/api", Decision: idTwo}, 10, uuid.Nil, w.soon(t))
	if err != nil || len(all) != 2 || all[0].Baseline != nil || all[1].Baseline != nil {
		t.Errorf("the pass verdicts = %+v, %v, want no reading", all, err)
	}
}

func TestABaselineRecordedAfterAVerdictDoesNotChangeAnAnswerReadAsKnownBeforeIt(t *testing.T) {
	w := newWorld(t)
	decision := w.decision(t, tenantA, idOne)
	w.period(t, tenantA, decision, "[2000-01-01,)")

	beforeUpload := w.mark(t)
	w.upload(t, "acme/api", 1, []any{}, digestsFrom(1, 3))
	beforeBaseline := w.mark(t)
	w.baseline(t, tenantA, decision, "acme/api", digestsFrom(1, 3))
	afterBaseline := w.mark(t)

	items, err := List(t.Context(), w.app, tenantA, Filter{}, 10, uuid.Nil, beforeUpload)
	if err != nil || len(items) != 0 {
		t.Errorf("as known before the upload = %d items, %v, want none", len(items), err)
	}
	items, err = List(t.Context(), w.app, tenantA, Filter{}, 10, uuid.Nil, beforeBaseline)
	if err != nil || len(items) != 2 {
		t.Fatalf("as known before the baseline = %d items, %v", len(items), err)
	}
	if got := baselineOf(t, items, idOne); got == nil || got.Result != "fail" || got.Waived != 0 {
		t.Errorf("as known before the baseline: %+v, want fail with none matched", got)
	}
	items, err = List(t.Context(), w.app, tenantA, Filter{}, 10, uuid.Nil, afterBaseline)
	if err != nil {
		t.Fatal(err)
	}
	if got := baselineOf(t, items, idOne); got == nil || got.Result != "waived(baseline)" || got.Waived != 3 {
		t.Errorf("as known after the baseline: %+v, want waived(baseline)", got)
	}
	// The earlier answer is the same when it is asked for again after the baseline is recorded.
	again, err := List(t.Context(), w.app, tenantA, Filter{}, 10, uuid.Nil, beforeBaseline)
	if err != nil || baselineOf(t, again, idOne).Result != "fail" {
		t.Errorf("the earlier answer changed: %+v, %v", baselineOf(t, again, idOne), err)
	}
}

// The baseline is read at the time the server stored the upload, so a period that had not started, or had
// ended, reads fail whatever the runner says about its own clock.
func TestTheGrandfatherPeriodIsReadAtTheTimeTheServerStoredTheUpload(t *testing.T) {
	for _, c := range []struct{ name, valid, want string }{
		{"a period that starts later", "[2999-01-01,)", "fail"},
		{"a period that has ended", "[2000-01-01,2001-01-01)", "fail"},
		{"a period that ends later", "[2000-01-01,2999-01-01)", "waived(baseline)"},
		{"a period with no end", "[2000-01-01,)", "waived(baseline)"},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := newWorld(t)
			decision := w.decision(t, tenantA, idOne)
			w.period(t, tenantA, decision, c.valid)
			w.baseline(t, tenantA, decision, "acme/api", digestsFrom(1, 3))
			// The runner states a time that is inside every period here. The server does not read it.
			if _, err := Store(t.Context(), w.app, tenantA, run("acme/api", 1, 1), parsed(t, "plan", func(u, r map[string]any) {
				version2([]any{}, digestsFrom(1, 3))(u, r)
				r["evaluated_at"] = "2000-06-01T00:00:00Z"
			})); err != nil {
				t.Fatal(err)
			}
			items, err := List(t.Context(), w.app, tenantA, Filter{Decision: idOne}, 10, uuid.Nil, w.soon(t))
			if err != nil || len(items) != 1 {
				t.Fatalf("List = %d items, %v", len(items), err)
			}
			if got := items[0].Baseline; got == nil || got.Result != c.want {
				t.Errorf("baseline = %+v, want %s", got, c.want)
			}
		})
	}
}

func TestAVerdictThatNamesNoDecisionOrManyOrAnotherRepositoryReadsFailWithNoneMatched(t *testing.T) {
	cases := map[string]func(w *world) string{
		"no decision holds the id": func(w *world) string { return "acme/api" },
		"two decisions hold the id": func(w *world) string {
			for range 2 {
				d := w.decision(t, tenantA, idOne)
				w.period(t, tenantA, d, "[2000-01-01,)")
				w.baseline(t, tenantA, d, "acme/api", digestsFrom(1, 3))
			}
			return "acme/api"
		},
		"a baseline for another repository": func(w *world) string {
			d := w.decision(t, tenantA, idOne)
			w.period(t, tenantA, d, "[2000-01-01,)")
			w.baseline(t, tenantA, d, "acme/web", digestsFrom(1, 3))
			return "acme/api"
		},
		"a baseline of another tenant": func(w *world) string {
			d := w.decision(t, tenantB, idOne)
			w.period(t, tenantB, d, "[2000-01-01,)")
			w.baseline(t, tenantB, d, "acme/api", digestsFrom(1, 3))
			return "acme/api"
		},
		"a repository the registry cannot name": func(w *world) string {
			d := w.decision(t, tenantA, idOne)
			w.period(t, tenantA, d, "[2000-01-01,)")
			w.baseline(t, tenantA, d, "acme/api", digestsFrom(1, 3))
			// The upload table allows an owner that starts with an underscore, and a baseline does not.
			return "_acme/api"
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			w := newWorld(t)
			repo := setup(w)
			w.upload(t, repo, 1, []any{}, digestsFrom(1, 3))
			items, err := List(t.Context(), w.app, tenantA, Filter{Decision: idOne}, 10, uuid.Nil, w.soon(t))
			if err != nil || len(items) != 1 {
				t.Fatalf("List = %d items, %v", len(items), err)
			}
			if got := items[0].Baseline; got == nil || got.Result != "fail" || got.Fingerprints != 3 || got.Waived != 0 {
				t.Errorf("baseline = %+v, want fail, 3 digests, none in the baseline", got)
			}
		})
	}
}

func TestAReportWithNoDigestHasNoReadingAndAVersion1ReportReadsAsBefore(t *testing.T) {
	w := newWorld(t)
	decision := w.decision(t, tenantA, idOne)
	w.period(t, tenantA, decision, "[2000-01-01,)")
	w.baseline(t, tenantA, decision, "acme/api", digestsFrom(1, 3))
	if _, err := Store(t.Context(), w.app, tenantA, run("acme/api", 1, 1), parsed(t, "plan", nil)); err != nil {
		t.Fatal(err)
	}
	w.upload(t, "acme/api", 2, []any{}, []any{})
	items, err := List(t.Context(), w.app, tenantA, Filter{}, 10, uuid.Nil, w.soon(t))
	if err != nil || len(items) != 4 {
		t.Fatalf("List = %d items, %v", len(items), err)
	}
	for _, it := range items {
		if it.Baseline != nil {
			t.Errorf("verdict %s of run %d has the reading %+v, want none", it.DecisionID, it.RunID, it.Baseline)
		}
	}
	if n := w.count(t, `SELECT count(*) FROM verification.verdict WHERE fingerprints IS NOT NULL`); n != 0 {
		t.Errorf("%d verdicts hold digests, want none", n)
	}
}

func TestStoreKeepsTheDigestsInTheOrderTheRunSentThem(t *testing.T) {
	w := newWorld(t)
	w.upload(t, "acme/api", 1, []any{}, digestsFrom(5, 4))
	rows, err := w.admin.QueryContext(t.Context(), `
		SELECT decision_id, coalesce(string_agg(encode(d, 'hex'), ',' ORDER BY n), '')
		FROM verification.verdict v LEFT JOIN LATERAL unnest(v.fingerprints) WITH ORDINALITY AS t(d, n) ON true
		GROUP BY v.id, v.decision_id`)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	got := map[string]string{}
	for rows.Next() {
		var id, list string
		if err := rows.Scan(&id, &list); err != nil {
			t.Fatal(err)
		}
		got[id] = list
	}
	var want []string
	for _, d := range digestsFrom(5, 4) {
		want = append(want, d.(string))
	}
	if got[idOne] != strings.Join(want, ",") || got[idTwo] != "" {
		t.Errorf("stored digests = %v", got)
	}
	if n := w.count(t, `SELECT count(*) FROM verification.verdict WHERE fingerprints IS NULL`); n != 1 {
		t.Errorf("%d verdicts hold no digest, want the pass only", n)
	}
}

// The rules of the table hold when the parser is bypassed, and the constraints hold when the triggers are off.
func TestTheTableRefusesDigestsThatBreakItsRules(t *testing.T) {
	w := newWorld(t)
	w.upload(t, "acme/api", 1, []any{}, []any{})
	conn, err := w.admin.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	index := 8
	insert := func(result string, violations int, digests string) error {
		index++
		_, err := conn.ExecContext(t.Context(), `
			INSERT INTO verification.verdict (tenant_id, upload_id, decision_id, slug, check_index, mode, result, violations, fingerprints)
			SELECT tenant_id, id, $1, 'extra', $2, 'block', $3, $4, `+digests+` FROM verification.upload`, idOne, index, result, violations)
		return err
	}
	two := `ARRAY[sha256('a'), sha256('b')]`
	type attempt struct {
		result     string
		violations int
		digests    string
	}
	for name, c := range map[string]attempt{
		"a short digest":                  {"fail", 1, `ARRAY[decode('ab', 'hex')]`},
		"a repeated digest":               {"fail", 1, `ARRAY[sha256('a'), sha256('a')]`},
		"a null digest":                   {"fail", 1, `ARRAY[sha256('a'), NULL::bytea]`},
		"an empty list":                   {"fail", 1, `'{}'::bytea[]`},
		"a pass with digests":             {"pass", 0, two},
		"an error with digests":           {"error", 0, two},
		"a waived with a different count": {"waived", 3, two},
		"a fail with fewer than counted":  {"fail", 3, two},
	} {
		if err := insert(c.result, c.violations, c.digests); err == nil {
			t.Errorf("%s: the table accepted it", name)
		}
	}
	if err := insert("fail", 2, two); err != nil {
		t.Errorf("a fail with a digest for each violation: %v", err)
	}
	if err := insert("waived", 2, two); err != nil {
		t.Errorf("a waived with a digest for each violation: %v", err)
	}

	// With triggers off, the constraints alone refuse what they can.
	if _, err := conn.ExecContext(t.Context(), `SET session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]attempt{
		"an empty list, triggers off":                   {"fail", 1, `'{}'::bytea[]`},
		"a null digest, triggers off":                   {"fail", 1, `ARRAY[sha256('a'), NULL::bytea]`},
		"a pass with digests, triggers off":             {"pass", 0, two},
		"a waived with a different count, triggers off": {"waived", 3, two},
	} {
		if err := insert(c.result, c.violations, c.digests); err == nil {
			t.Errorf("%s: the table accepted it", name)
		}
	}
}
