//go:build integration

package registry

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
)

var premiseDecision = uuid.MustParse("00000000-0000-4000-8000-0000000000d1")

const (
	inForce = "[2000-01-01,)"

	// pgMajor is recordable: a name, https, a pointer, one comparison.
	pgMajor = `{"id":"postgres-major","statement":"s","every":7,"probe":{"url":"https://status.example.com/platform.json","pointer":"/major","equals":16}}`
	nodeLTS = `{"id":"node-lts","statement":"s","every":30,"probe":{"url":"https://status.example.com/node.json","pointer":"/lts","semver":">=20.0.0"}}`
)

func premiseBody(premises ...string) string {
	return `{"premises":[` + strings.Join(premises, ",") + `]}`
}

// premiseOn inserts the first version of a decision with a body, as the application role.
func (r registryDB) premiseOn(t *testing.T, tenant, id uuid.UUID, valid, body string) {
	t.Helper()
	scope := r.scope(t, tenant, uuid.Nil, "org", "acme-"+id.String())
	_, err := pgtest.Exec(t.Context(), r.app, tenant.String(), `
		INSERT INTO registry.decision_version (decision_id, version, tenant_id, body, scope_refs, valid_period)
		VALUES ($1, 1, $2, $3::jsonb, ARRAY[$4::uuid], $5::text::tstzrange)`, id, tenant, body, scope, valid)
	if err != nil {
		t.Fatalf("insert decision: %v", err)
	}
}

// age moves every evaluation of the tenant back in transaction time. The application role cannot do this,
// which is the point of the trigger that sets sys_period, so the superuser does.
func (r registryDB) age(t *testing.T, tenant uuid.UUID, days int) {
	t.Helper()
	_, err := r.admin.ExecContext(t.Context(), `
		UPDATE registry.premise_evaluation
		SET sys_period = tstzrange(clock_timestamp() - make_interval(days => $2), NULL)
		WHERE tenant_id = $1`, tenant, days)
	if err != nil {
		t.Fatalf("age the evaluations: %v", err)
	}
}

func (r registryDB) count(t *testing.T, tenant uuid.UUID, query string, args ...any) int {
	t.Helper()
	var n int
	if err := pgtest.Scan(t.Context(), r.app, tenant.String(), query, args, &n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

func (r registryDB) allow(t *testing.T, tenant uuid.UUID, host string, allowed bool) {
	t.Helper()
	if _, err := pgtest.Exec(t.Context(), r.app, tenant.String(),
		`INSERT INTO registry.premise_host_allow (tenant_id, host, allowed) VALUES ($1, $2, $3)`, tenant, host, allowed); err != nil {
		t.Fatalf("allow %s: %v", host, err)
	}
}

func evaluation(result string) Evaluation {
	ev := Evaluation{
		Ref:      PremiseRef{Decision: premiseDecision, ID: "postgres-major"},
		Result:   result,
		URL:      "https://status.example.com/platform.json",
		Pointer:  "/major",
		Expected: []byte("16"),
	}
	if result != "error" {
		ev.Observed = []byte("15")
		ev.BodySHA256 = bytes.Repeat([]byte{0xab}, 32)
	}
	return ev
}

func due(t *testing.T, r registryDB, tenant uuid.UUID) ([]PremiseRef, int) {
	t.Helper()
	refs, skipped, err := DuePremises(t.Context(), r.app, tenant)
	if err != nil {
		t.Fatalf("DuePremises: %v", err)
	}
	return refs, skipped
}

func TestAPremiseWithNoEvaluationIsDue(t *testing.T) {
	r := newRegistryDB(t)
	r.premiseOn(t, tenantA, premiseDecision, inForce, premiseBody(pgMajor, nodeLTS))

	refs, skipped := due(t, r, tenantA)
	want := []PremiseRef{{premiseDecision, "node-lts"}, {premiseDecision, "postgres-major"}}
	if len(refs) != 2 || refs[0] != want[0] || refs[1] != want[1] || skipped != 0 {
		t.Fatalf("due = %v, skipped %d, want %v", refs, skipped, want)
	}
	got, found, err := DuePremise(t.Context(), r.app, tenantA, want[1])
	if err != nil || !found {
		t.Fatalf("DuePremise = %v, %v", found, err)
	}
	if got.URL != "https://status.example.com/platform.json" || got.Pointer != "/major" || string(got.Expected) != "16" || !got.HasEquals {
		t.Errorf("premise = %+v", got)
	}
	semver, found, err := DuePremise(t.Context(), r.app, tenantA, want[0])
	if err != nil || !found || semver.HasEquals || string(semver.Expected) != `">=20.0.0"` {
		t.Errorf("semver premise = %+v, %v, %v", semver, found, err)
	}
}

// The interval is read from the latest evaluation, in fixed 24 hour days, and there is no next_run column.
func TestAPremiseIsDueOnceItsLatestEvaluationIsOlderThanItsInterval(t *testing.T) {
	r := newRegistryDB(t)
	r.premiseOn(t, tenantA, premiseDecision, inForce, premiseBody(pgMajor)) // every 7 days
	if _, err := RecordEvaluation(t.Context(), r.app, tenantA, evaluation("pass")); err != nil {
		t.Fatal(err)
	}
	if refs, _ := due(t, r, tenantA); len(refs) != 0 {
		t.Fatalf("a premise evaluated just now is due: %v", refs)
	}
	r.age(t, tenantA, 6)
	if refs, _ := due(t, r, tenantA); len(refs) != 0 {
		t.Fatalf("a premise evaluated 6 days ago with an interval of 7 is due: %v", refs)
	}
	if _, found, err := DuePremise(t.Context(), r.app, tenantA, PremiseRef{premiseDecision, "postgres-major"}); err != nil || found {
		t.Fatalf("DuePremise found a premise that is not due: %v, %v", found, err)
	}
	r.age(t, tenantA, 8)
	if refs, _ := due(t, r, tenantA); len(refs) != 1 {
		t.Fatalf("a premise evaluated 8 days ago with an interval of 7 is not due: %v", refs)
	}
	if _, found, err := DuePremise(t.Context(), r.app, tenantA, PremiseRef{premiseDecision, "postgres-major"}); err != nil || !found {
		t.Fatalf("DuePremise = %v, %v", found, err)
	}
}

func TestOnlyTheLatestEvaluationDecidesWhetherAPremiseIsDue(t *testing.T) {
	r := newRegistryDB(t)
	r.premiseOn(t, tenantA, premiseDecision, inForce, premiseBody(pgMajor))
	if _, err := RecordEvaluation(t.Context(), r.app, tenantA, evaluation("pass")); err != nil {
		t.Fatal(err)
	}
	r.age(t, tenantA, 60)
	if refs, _ := due(t, r, tenantA); len(refs) != 1 {
		t.Fatalf("an old evaluation leaves the premise due: %v", refs)
	}
	if _, err := RecordEvaluation(t.Context(), r.app, tenantA, evaluation("error")); err != nil {
		t.Fatal(err)
	}
	if refs, _ := due(t, r, tenantA); len(refs) != 0 {
		t.Fatalf("a new evaluation, an error included, leaves the premise due: %v", refs)
	}
}

func TestAFailOpensOneReasonAndLeavesTheDecisionAsItWas(t *testing.T) {
	r := newRegistryDB(t)
	r.premiseOn(t, tenantA, premiseDecision, inForce, premiseBody(pgMajor))
	snapshot := func() string {
		var s string
		if err := r.admin.QueryRowContext(t.Context(), `
			SELECT version || '|' || body::text || '|' || valid_period::text || '|' || sys_period::text || '|' ||
			       (SELECT count(*) FROM registry.decision_version_history)
			FROM registry.decision_version WHERE decision_id = $1`, premiseDecision).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}
	before := snapshot()

	opened, err := RecordEvaluation(t.Context(), r.app, tenantA, evaluation("fail"))
	if err != nil || !opened {
		t.Fatalf("a fail opened = %v, %v", opened, err)
	}
	opened, err = RecordEvaluation(t.Context(), r.app, tenantA, evaluation("fail"))
	if err != nil || opened {
		t.Fatalf("a second fail opened = %v, %v, want no second reason", opened, err)
	}
	if n := r.count(t, tenantA, `SELECT count(*) FROM registry.premise_reason`); n != 1 {
		t.Errorf("reasons = %d, want 1", n)
	}
	if n := r.count(t, tenantA, `SELECT count(*) FROM registry.premise_evaluation WHERE result = 'fail'`); n != 2 {
		t.Errorf("fail evaluations = %d, want 2", n)
	}
	if after := snapshot(); after != before {
		t.Errorf("the decision changed:\n before %s\n after  %s", before, after)
	}
}

func TestAPassOrAnErrorNeitherOpensNorClearsAReason(t *testing.T) {
	r := newRegistryDB(t)
	r.premiseOn(t, tenantA, premiseDecision, inForce, premiseBody(pgMajor))
	if opened, err := RecordEvaluation(t.Context(), r.app, tenantA, evaluation("fail")); err != nil || !opened {
		t.Fatalf("fail: %v, %v", opened, err)
	}
	for _, result := range []string{"pass", "error"} {
		if opened, err := RecordEvaluation(t.Context(), r.app, tenantA, evaluation(result)); err != nil || opened {
			t.Fatalf("%s opened = %v, %v", result, opened, err)
		}
	}
	if n := r.count(t, tenantA, `SELECT count(*) FROM registry.premise_reason`); n != 1 {
		t.Errorf("reasons = %d, want the one the fail opened", n)
	}
	if n := r.count(t, tenantA, `SELECT count(*) FROM registry.premise_clearance`); n != 0 {
		t.Errorf("clearances = %d, want none: only a person clears a reason", n)
	}
}

func TestAFailOpensAnotherReasonOnceAPersonHasClearedTheFirst(t *testing.T) {
	r := newRegistryDB(t)
	r.premiseOn(t, tenantA, premiseDecision, inForce, premiseBody(pgMajor))
	if _, err := RecordEvaluation(t.Context(), r.app, tenantA, evaluation("fail")); err != nil {
		t.Fatal(err)
	}
	if _, err := pgtest.Exec(t.Context(), r.app, tenantA.String(), `
		INSERT INTO registry.premise_clearance (tenant_id, reason_id, kind)
		SELECT tenant_id, id, 'human' FROM registry.premise_reason`); err != nil {
		t.Fatal(err)
	}
	if opened, err := RecordEvaluation(t.Context(), r.app, tenantA, evaluation("fail")); err != nil || !opened {
		t.Fatalf("a fail after a clearance opened = %v, %v", opened, err)
	}
	if n := r.count(t, tenantA, `SELECT count(*) FROM registry.premise_reason`); n != 2 {
		t.Errorf("reasons = %d, want 2", n)
	}
}

func TestAnEvaluationKeepsTheObservedValueAndTheDigestAndNoBody(t *testing.T) {
	r := newRegistryDB(t)
	r.premiseOn(t, tenantA, premiseDecision, inForce, premiseBody(pgMajor))
	ev := evaluation("pass")
	ev.Observed = []byte("16")
	if _, err := RecordEvaluation(t.Context(), r.app, tenantA, ev); err != nil {
		t.Fatal(err)
	}
	var result, expected, observed, digest string
	if err := pgtest.Scan(t.Context(), r.app, tenantA.String(), `
		SELECT result, expected::text, observed::text, encode(body_sha256, 'hex') FROM registry.premise_evaluation`,
		nil, &result, &expected, &observed, &digest); err != nil {
		t.Fatal(err)
	}
	if result != "pass" || expected != "16" || observed != "16" || digest != hex.EncodeToString(ev.BodySHA256) {
		t.Errorf("stored %s %s %s %s", result, expected, observed, digest)
	}
}

func TestAPremiseThatCannotBeRecordedIsLeftOutAndCounted(t *testing.T) {
	r := newRegistryDB(t)
	long := strings.Repeat("x", 1100)
	bad := []string{
		`{"id":"Upper_Case","every":7,"probe":{"url":"https://status.example.com/a","pointer":"/a","equals":1}}`,
		`{"id":"` + strings.Repeat("a", 129) + `","every":7,"probe":{"url":"https://status.example.com/a","pointer":"/a","equals":1}}`,
		`{"id":"zero-days","every":0,"probe":{"url":"https://status.example.com/a","pointer":"/a","equals":1}}`,
		`{"id":"a-year-and-a-day","every":366,"probe":{"url":"https://status.example.com/a","pointer":"/a","equals":1}}`,
		`{"id":"fractional","every":7.5,"probe":{"url":"https://status.example.com/a","pointer":"/a","equals":1}}`,
		`{"id":"http","every":7,"probe":{"url":"http://status.example.com/a","pointer":"/a","equals":1}}`,
		`{"id":"an-address","every":7,"probe":{"url":"https://10.0.0.1/a","pointer":"/a","equals":1}}`,
		`{"id":"userinfo","every":7,"probe":{"url":"https://user@status.example.com/a","pointer":"/a","equals":1}}`,
		`{"id":"fragment","every":7,"probe":{"url":"https://status.example.com/a#x","pointer":"/a","equals":1}}`,
		`{"id":"bad-pointer","every":7,"probe":{"url":"https://status.example.com/a","pointer":"a/b","equals":1}}`,
		`{"id":"both","every":7,"probe":{"url":"https://status.example.com/a","pointer":"/a","equals":1,"semver":">=1.0.0"}}`,
		`{"id":"neither","every":7,"probe":{"url":"https://status.example.com/a","pointer":"/a"}}`,
		`{"id":"semver-number","every":7,"probe":{"url":"https://status.example.com/a","pointer":"/a","semver":3}}`,
		`{"id":"too-big","every":7,"probe":{"url":"https://status.example.com/a","pointer":"/a","equals":"` + long + `"}}`,
		`{"id":"no-probe","every":7}`,
		`{"every":7,"probe":{"url":"https://status.example.com/a","pointer":"/a","equals":1}}`,
		`5`,
	}
	r.premiseOn(t, tenantA, premiseDecision, inForce, premiseBody(append([]string{pgMajor}, bad...)...))
	// A body whose premises is not an array holds nothing to sweep and nothing to count.
	r.premiseOn(t, tenantA, uuid.MustParse("00000000-0000-4000-8000-0000000000d2"), inForce, `{"premises":"none"}`)

	refs, skipped := due(t, r, tenantA)
	if len(refs) != 1 || refs[0].ID != "postgres-major" {
		t.Errorf("due = %v, want only the premise that can be recorded", refs)
	}
	if skipped != len(bad) {
		t.Errorf("skipped = %d, want %d", skipped, len(bad))
	}
	if _, found, err := DuePremise(t.Context(), r.app, tenantA, PremiseRef{premiseDecision, "zero-days"}); err != nil || found {
		t.Errorf("DuePremise returned a premise that cannot be recorded: %v, %v", found, err)
	}
}

func TestAPremiseIdListedTwiceOnADecisionIsSweptOnce(t *testing.T) {
	r := newRegistryDB(t)
	r.premiseOn(t, tenantA, premiseDecision, inForce, premiseBody(pgMajor, pgMajor))
	if refs, skipped := due(t, r, tenantA); len(refs) != 1 || skipped != 0 {
		t.Errorf("due = %v, skipped %d, want the premise once", refs, skipped)
	}
}

// The probe limits the compact observed value, and the table limits its jsonb text, where 1e2000 is 2001
// bytes. Such a response is stored once as an error, so the premise is not probed every hour for ever.
func TestAnObservedValueTooLargeAsJSONBIsStoredAsAnErrorAndOpensNoReason(t *testing.T) {
	r := newRegistryDB(t)
	r.premiseOn(t, tenantA, premiseDecision, inForce, premiseBody(pgMajor))
	ev := evaluation("fail")
	ev.Observed = []byte("1e2000")
	opened, err := RecordEvaluation(t.Context(), r.app, tenantA, ev)
	if err != nil || opened {
		t.Fatalf("opened = %v, %v, want an evaluation and no reason", opened, err)
	}
	var result string
	var observed sql.NullString
	if err := pgtest.Scan(t.Context(), r.app, tenantA.String(),
		`SELECT result, observed::text FROM registry.premise_evaluation`, nil, &result, &observed); err != nil {
		t.Fatal(err)
	}
	if result != "error" || observed.Valid {
		t.Errorf("stored %q with observed %v, want an error with no observed value", result, observed)
	}
	if n := r.count(t, tenantA, `SELECT count(*) FROM registry.premise_reason`); n != 0 {
		t.Errorf("reasons = %d, want none", n)
	}
	if refs, _ := due(t, r, tenantA); len(refs) != 0 {
		t.Errorf("the premise is still due after its evaluation: %v", refs)
	}
}

func TestAnEqualsOfNullIsAComparisonLikeAnyOther(t *testing.T) {
	r := newRegistryDB(t)
	r.premiseOn(t, tenantA, premiseDecision, inForce, premiseBody(
		`{"id":"is-null","every":1,"probe":{"url":"https://status.example.com/a","pointer":"/a","equals":null}}`))
	got, found, err := DuePremise(t.Context(), r.app, tenantA, PremiseRef{premiseDecision, "is-null"})
	if err != nil || !found || !got.HasEquals || string(got.Expected) != "null" {
		t.Fatalf("premise = %+v, %v, %v", got, found, err)
	}
}

func TestOnlyDecisionsInForceNowOfTheTenantAreSwept(t *testing.T) {
	r := newRegistryDB(t)
	r.premiseOn(t, tenantA, premiseDecision, "[2000-01-01,2001-01-01)", premiseBody(pgMajor))
	r.premiseOn(t, tenantA, uuid.MustParse("00000000-0000-4000-8000-0000000000d3"), "[2999-01-01,)", premiseBody(pgMajor))
	other := uuid.MustParse("00000000-0000-4000-8000-0000000000d4")
	r.premiseOn(t, tenantB, other, inForce, premiseBody(pgMajor))

	if refs, skipped := due(t, r, tenantA); len(refs) != 0 || skipped != 0 {
		t.Errorf("a decision that ended or has not begun, or one of another tenant, was swept: %v, %d", refs, skipped)
	}
	if _, found, err := DuePremise(t.Context(), r.app, tenantA, PremiseRef{other, "postgres-major"}); err != nil || found {
		t.Errorf("DuePremise read a premise of another tenant: %v, %v", found, err)
	}
	if refs, _ := due(t, r, tenantB); len(refs) != 1 || refs[0].Decision != other {
		t.Errorf("the other tenant's due premises = %v", refs)
	}
}

func TestAnEmptyAllowlistAllowsNoHostAndTheLatestRowDecides(t *testing.T) {
	r := newRegistryDB(t)
	allowed := func(host string) bool {
		t.Helper()
		got, err := HostAllowed(t.Context(), r.app, tenantA, host)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	if allowed("status.example.com") {
		t.Fatal("an empty allowlist allowed a host")
	}
	r.allow(t, tenantA, "status.example.com", true)
	if !allowed("status.example.com") {
		t.Error("an allowed host was refused")
	}
	if allowed("example.com") || allowed("evil.status.example.com") || allowed("status.example.com.") {
		t.Error("a host matched an allowlist row it does not equal")
	}
	r.allow(t, tenantA, "STATUS.example.com", false) // stored in lowercase
	if allowed("status.example.com") {
		t.Error("a revoked host was allowed")
	}
	r.allow(t, tenantA, "status.example.com", true)
	if !allowed("status.example.com") {
		t.Error("a host allowed again was refused")
	}
	if got, err := HostAllowed(t.Context(), r.app, tenantB, "status.example.com"); err != nil || got {
		t.Errorf("another tenant's allowlist applies: %v, %v", got, err)
	}
}

func TestRecordEvaluationRefusesAPremiseThatIsNotOnTheDecision(t *testing.T) {
	r := newRegistryDB(t)
	r.premiseOn(t, tenantA, premiseDecision, inForce, premiseBody(pgMajor))
	ev := evaluation("pass")
	ev.Ref.ID = "not-on-the-decision"
	if _, err := RecordEvaluation(t.Context(), r.app, tenantA, ev); err == nil {
		t.Fatal("an evaluation of a premise the decision does not carry was recorded")
	}
	if n := r.count(t, tenantA, `SELECT count(*) FROM registry.premise_evaluation`); n != 0 {
		t.Errorf("evaluations = %d, want none", n)
	}
}

func TestTheFunctionsRefuseWhatTheyCannotTrust(t *testing.T) {
	r := newRegistryDB(t)
	ctx := context.Background()
	ref := PremiseRef{premiseDecision, "postgres-major"}
	if _, _, err := DuePremises(ctx, r.app, uuid.Nil); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("DuePremises with no tenant: %v", err)
	}
	if _, _, err := DuePremise(ctx, r.app, uuid.Nil, ref); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("DuePremise with no tenant: %v", err)
	}
	if _, _, err := DuePremise(ctx, r.app, tenantA, PremiseRef{}); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("DuePremise with no premise: %v", err)
	}
	if _, err := HostAllowed(ctx, r.app, tenantA, ""); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("HostAllowed with no host: %v", err)
	}
	if _, err := RecordEvaluation(ctx, r.app, uuid.Nil, evaluation("pass")); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("RecordEvaluation with no tenant: %v", err)
	}
	if _, err := RecordEvaluation(ctx, r.app, tenantA, Evaluation{Ref: ref, Result: "waived"}); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("RecordEvaluation with an unknown result: %v", err)
	}
}
