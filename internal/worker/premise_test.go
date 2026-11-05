package worker

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/ipsofacto-io/ipso-server/internal/registry"
	"github.com/ipsofacto-io/ipso/pkg/premisecheck"
)

var decisionA = uuid.MustParse("00000000-0000-4000-8000-0000000000d1")

const (
	// A canary in the places where a database message or a fetched value could end up.
	canary = "TICKET-SECRET"
	digest = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
)

func sweepJobFor(tenant uuid.UUID) *river.Job[PremiseSweepArgs] {
	return &river.Job[PremiseSweepArgs]{JobRow: &rivertype.JobRow{ID: 8}, Args: PremiseSweepArgs{Tenant: tenant}}
}

func probeJobFor(tenant uuid.UUID) *river.Job[PremiseProbeArgs] {
	return &river.Job[PremiseProbeArgs]{
		JobRow: &rivertype.JobRow{ID: 9},
		Args:   PremiseProbeArgs{Tenant: tenant, Decision: decisionA, Premise: "postgres-major"},
	}
}

func TestTheSweepCancelsAJobForAnotherTenantBeforeTheDatabaseIsTouched(t *testing.T) {
	w := &premiseSweep{
		tenant: tenantA, log: slog.New(slog.DiscardHandler),
		due: func(context.Context, *sql.DB, uuid.UUID) ([]registry.PremiseRef, int, error) {
			t.Error("the sweep read premises for a job that names another tenant")
			return nil, 0, nil
		},
		insert: func(context.Context, []PremiseProbeArgs) (int, error) {
			t.Error("the sweep queued probes for a job that names another tenant")
			return 0, nil
		},
	}
	err := w.Work(t.Context(), sweepJobFor(tenantB))
	var cancelled *river.JobCancelError
	if !errors.As(err, &cancelled) || strings.Contains(err.Error(), tenantA.String()) || strings.Contains(err.Error(), tenantB.String()) {
		t.Fatalf("err = %v, want a cancellation that names no tenant", err)
	}
}

func TestTheSweepQueuesOneProbeForEachDuePremiseOfItsTenant(t *testing.T) {
	refs := []registry.PremiseRef{{Decision: decisionA, ID: "postgres-major"}, {Decision: decisionA, ID: "node-lts"}}
	var queued []PremiseProbeArgs
	w := &premiseSweep{
		tenant: tenantA, log: slog.New(slog.DiscardHandler),
		due: func(_ context.Context, _ *sql.DB, tenant uuid.UUID) ([]registry.PremiseRef, int, error) {
			if tenant != tenantA {
				t.Errorf("due premises read for %s", tenant)
			}
			return refs, 1, nil
		},
		insert: func(_ context.Context, jobs []PremiseProbeArgs) (int, error) {
			queued = jobs
			return len(jobs), nil
		},
	}
	if err := w.Work(t.Context(), sweepJobFor(tenantA)); err != nil {
		t.Fatal(err)
	}
	want := []PremiseProbeArgs{
		{Tenant: tenantA, Decision: decisionA, Premise: "postgres-major"},
		{Tenant: tenantA, Decision: decisionA, Premise: "node-lts"},
	}
	if !reflect.DeepEqual(queued, want) {
		t.Errorf("queued %+v, want %+v", queued, want)
	}
}

func TestTheSweepStoresAFailureAsItsOperationAndClassOnly(t *testing.T) {
	pgErr := &pgconn.PgError{Code: "23514", Message: "violates check constraint", Detail: "Failing row contains (" + canary + ")"}
	tests := []struct {
		name   string
		due    error
		insert error
		want   string
	}{
		{"a database error while reading", fmt.Errorf("read due premises: %w", pgErr), nil, "read due premises: SQLSTATE 23514"},
		{"a deadline while reading", fmt.Errorf("%s: %w", canary, context.DeadlineExceeded), nil, "read due premises: timed out"},
		{"an insert error", nil, errors.New("insert probe jobs: " + canary), "queue premise probes: failed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &premiseSweep{
				tenant: tenantA, log: slog.New(slog.DiscardHandler),
				due: func(context.Context, *sql.DB, uuid.UUID) ([]registry.PremiseRef, int, error) {
					return []registry.PremiseRef{{Decision: decisionA, ID: "postgres-major"}}, 0, tt.due
				},
				insert: func(context.Context, []PremiseProbeArgs) (int, error) { return 0, tt.insert },
			}
			err := w.Work(t.Context(), sweepJobFor(tenantA))
			if err == nil || err.Error() != tt.want || strings.Contains(err.Error(), canary) {
				t.Errorf("err = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestEachJobIsInItsOwnQueueAndUniqueWhileItWaitsOrRuns(t *testing.T) {
	jobs := []struct {
		name     string
		opts     river.InsertOpts
		queue    string
		attempts int
	}{
		{"premise_sweep", PremiseSweepArgs{Tenant: tenantA}.InsertOpts(), premiseSweepQueue, premiseSweepAttempts},
		{"premise_probe", PremiseProbeArgs{Tenant: tenantA, Decision: decisionA, Premise: "x"}.InsertOpts(), premiseProbeQueue, premiseProbeAttempts},
	}
	for _, job := range jobs {
		t.Run(job.name, func(t *testing.T) {
			if job.opts.Queue != job.queue || job.opts.MaxAttempts != job.attempts || !job.opts.UniqueOpts.ByArgs {
				t.Errorf("queue %q, attempts %d, by args %v", job.opts.Queue, job.opts.MaxAttempts, job.opts.UniqueOpts.ByArgs)
			}
			for _, required := range []rivertype.JobState{
				rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRunning,
				rivertype.JobStateScheduled, rivertype.JobStateRetryable,
			} {
				if !slices.Contains(job.opts.UniqueOpts.ByState, required) {
					t.Errorf("state %q is not unique", required)
				}
			}
			if slices.Contains(job.opts.UniqueOpts.ByState, rivertype.JobStateCompleted) {
				t.Error("a completed job holds the next one back")
			}
		})
	}
	if (PremiseSweepArgs{}).Kind() != "premise_sweep" || (PremiseProbeArgs{}).Kind() != "premise_probe" {
		t.Error("a kind changed, and River matches stored jobs by it")
	}
}

// A field added to the arguments is a field River stores in river_job.args, outside row-level security.
func TestTheArgumentsHoldIdsAndNothingElse(t *testing.T) {
	sweep := reflect.TypeFor[PremiseSweepArgs]()
	if sweep.NumField() != 1 || sweep.Field(0).Name != "Tenant" {
		t.Errorf("the sweep has %d fields, want the tenant id only", sweep.NumField())
	}
	probe := reflect.TypeFor[PremiseProbeArgs]()
	var names []string
	for i := range probe.NumField() {
		names = append(names, probe.Field(i).Name)
	}
	if !slices.Equal(names, []string{"Tenant", "Decision", "Premise"}) {
		t.Errorf("the probe carries %v, want the tenant, the decision, and the premise id", names)
	}
	raw, err := json.Marshal(PremiseProbeArgs{Tenant: tenantA, Decision: decisionA, Premise: "postgres-major"})
	if err != nil || !strings.Contains(string(raw), `"premise":"postgres-major"`) {
		t.Errorf("args = %s, %v", raw, err)
	}
}

type probeFake struct {
	calls   int
	spec    premisecheck.Spec
	result  premisecheck.Result
	onCheck func()
}

func (p *probeFake) Check(_ context.Context, spec premisecheck.Spec) premisecheck.Result {
	p.calls++
	p.spec = spec
	if p.onCheck != nil {
		p.onCheck()
	}
	return p.result
}

// probeRig is a probe worker whose registry calls and probe are fakes that record what they were asked.
type probeRig struct {
	w         *premiseProbe
	probe     *probeFake
	premise   registry.Premise
	due       bool
	allowed   bool
	dueErr    error
	hostErr   error
	recordErr error
	hosts     []string
	recorded  []registry.Evaluation
}

func newProbeRig() *probeRig {
	r := &probeRig{
		probe: &probeFake{},
		due:   true,
		premise: registry.Premise{
			Ref:       registry.PremiseRef{Decision: decisionA, ID: "postgres-major"},
			URL:       "https://Status.Example.com/platform.json",
			Pointer:   "/major",
			Expected:  json.RawMessage("16"),
			HasEquals: true,
		},
	}
	r.w = &premiseProbe{
		tenant: tenantA, log: slog.New(slog.DiscardHandler), probe: r.probe,
		due: func(context.Context, *sql.DB, uuid.UUID, registry.PremiseRef) (registry.Premise, bool, error) {
			return r.premise, r.due, r.dueErr
		},
		allowed: func(_ context.Context, _ *sql.DB, _ uuid.UUID, host string) (bool, error) {
			r.hosts = append(r.hosts, host)
			return r.allowed, r.hostErr
		},
		record: func(_ context.Context, _ *sql.DB, _ uuid.UUID, ev registry.Evaluation) (bool, error) {
			r.recorded = append(r.recorded, ev)
			return ev.Result == premisecheck.ResultFail, r.recordErr
		},
	}
	return r
}

func TestTheProbeCancelsAJobForAnotherTenantBeforeTheDatabaseIsTouched(t *testing.T) {
	r := newProbeRig()
	r.w.due = func(context.Context, *sql.DB, uuid.UUID, registry.PremiseRef) (registry.Premise, bool, error) {
		t.Error("the probe read a premise for a job that names another tenant")
		return registry.Premise{}, false, nil
	}
	err := r.w.Work(t.Context(), probeJobFor(tenantB))
	var cancelled *river.JobCancelError
	if !errors.As(err, &cancelled) || r.probe.calls != 0 || len(r.recorded) != 0 {
		t.Fatalf("err = %v, probes %d, recorded %d", err, r.probe.calls, len(r.recorded))
	}
}

func TestAPremiseThatIsNotDueIsLeftAlone(t *testing.T) {
	r := newProbeRig()
	r.due, r.allowed = false, true
	if err := r.w.Work(t.Context(), probeJobFor(tenantA)); err != nil {
		t.Fatal(err)
	}
	if len(r.hosts) != 0 || r.probe.calls != 0 || len(r.recorded) != 0 {
		t.Errorf("a premise that is not due was read for its host %v, probed %d times, recorded %d", r.hosts, r.probe.calls, len(r.recorded))
	}
}

// An empty allowlist and a revoked host both read as not allowed. Neither is probed, and neither opens a reason.
func TestAHostThatIsNotAllowedIsRecordedAsAnErrorWithoutALookupOrARequest(t *testing.T) {
	r := newProbeRig()
	r.allowed = false
	if err := r.w.Work(t.Context(), probeJobFor(tenantA)); err != nil {
		t.Fatal(err)
	}
	if r.probe.calls != 0 {
		t.Fatalf("the probe ran %d times for a host that is not allowed", r.probe.calls)
	}
	if !slices.Equal(r.hosts, []string{"status.example.com"}) {
		t.Errorf("the allowlist was asked about %v, want the lowercase host", r.hosts)
	}
	if len(r.recorded) != 1 {
		t.Fatalf("recorded %d evaluations, want one", len(r.recorded))
	}
	ev := r.recorded[0]
	if ev.Result != premisecheck.ResultError || ev.Observed != nil || ev.BodySHA256 != nil ||
		ev.URL != r.premise.URL || ev.Pointer != "/major" || string(ev.Expected) != "16" {
		t.Errorf("evaluation = %+v", ev)
	}
}

func TestAURLTheProbeRefusesIsRecordedAsAnErrorAndNeverReachesTheAllowlist(t *testing.T) {
	for _, url := range []string{
		"http://status.example.com/platform.json",
		"https://status.exampleK.com/platform.json",
		"https://user@status.example.com/platform.json",
	} {
		t.Run(url, func(t *testing.T) {
			r := newProbeRig()
			r.premise.URL = url
			r.allowed = true
			if err := r.w.Work(t.Context(), probeJobFor(tenantA)); err != nil {
				t.Fatal(err)
			}
			if len(r.hosts) != 0 || r.probe.calls != 0 || len(r.recorded) != 1 || r.recorded[0].Result != premisecheck.ResultError {
				t.Errorf("allowlist asked %v, probed %d, recorded %+v", r.hosts, r.probe.calls, r.recorded)
			}
		})
	}
}

func TestAnAllowedHostIsProbedAndEachResultIsRecorded(t *testing.T) {
	wantDigest, _ := hex.DecodeString(digest)
	tests := []struct {
		name       string
		result     premisecheck.Result
		want       string
		observed   string
		hasDigest  bool
		reasonOpen bool
	}{
		{"a pass", premisecheck.Result{Result: premisecheck.ResultPass, Observed: []byte("16"), BodySHA256: digest}, "pass", "16", true, false},
		{"a fail", premisecheck.Result{Result: premisecheck.ResultFail, Observed: []byte("15"), BodySHA256: digest}, "fail", "15", true, true},
		{"an error that read a body", premisecheck.Result{Result: premisecheck.ResultError, BodySHA256: digest, Reason: "status"}, "error", "", true, false},
		{"an error that read nothing", premisecheck.Result{Result: premisecheck.ResultError, Reason: "redirect"}, "error", "", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newProbeRig()
			r.allowed = true
			r.probe.result = tt.result
			if err := r.w.Work(t.Context(), probeJobFor(tenantA)); err != nil {
				t.Fatal(err)
			}
			if r.probe.calls != 1 || len(r.recorded) != 1 {
				t.Fatalf("probed %d times, recorded %d", r.probe.calls, len(r.recorded))
			}
			if r.probe.spec.URL != r.premise.URL || r.probe.spec.Pointer != "/major" || !r.probe.spec.HasEquals || r.probe.spec.Equals != json.Number("16") {
				t.Errorf("spec = %+v", r.probe.spec)
			}
			ev := r.recorded[0]
			if ev.Result != tt.want || string(ev.Observed) != tt.observed || (ev.BodySHA256 != nil) != tt.hasDigest {
				t.Errorf("evaluation = %+v", ev)
			}
			if tt.hasDigest && !slices.Equal(ev.BodySHA256, wantDigest) {
				t.Errorf("digest = %x", ev.BodySHA256)
			}
		})
	}
}

// The table refuses a pass or a fail with no observed value or no 32 byte digest. The probe does not make
// one, and a worker that met one would otherwise fail on the constraint and retry forever.
func TestAPassOrFailThatLacksAnObservedValueOrDigestIsRecordedAsAnErrorHoldingNothing(t *testing.T) {
	for _, result := range []premisecheck.Result{
		{Result: premisecheck.ResultPass, BodySHA256: digest},
		{Result: premisecheck.ResultFail, Observed: []byte("15")},
		{Result: premisecheck.ResultFail, Observed: []byte("15"), BodySHA256: "abcd"},
	} {
		r := newProbeRig()
		r.allowed = true
		r.probe.result = result
		if err := r.w.Work(t.Context(), probeJobFor(tenantA)); err != nil {
			t.Fatal(err)
		}
		ev := r.recorded[0]
		if ev.Result != premisecheck.ResultError || ev.Observed != nil || ev.BodySHA256 != nil {
			t.Errorf("%+v was recorded as %+v", result, ev)
		}
	}
}

func TestAProbeCutShortByTheProcessStoppingRecordsNothingAndIsTriedAgain(t *testing.T) {
	r := newProbeRig()
	r.allowed = true
	ctx, cancel := context.WithCancel(t.Context())
	r.probe.onCheck = cancel
	r.probe.result = premisecheck.Result{Result: premisecheck.ResultError, Reason: "network"}
	err := r.w.Work(ctx, probeJobFor(tenantA))
	if err == nil || err.Error() != "probe a premise: canceled" || len(r.recorded) != 0 {
		t.Errorf("err = %v, recorded %d, want a canceled attempt that wrote nothing", err, len(r.recorded))
	}
}

func TestTheProbeStoresAFailureAsItsOperationAndClassOnly(t *testing.T) {
	pgErr := &pgconn.PgError{Code: "23514", Message: "violates check constraint", Detail: "Failing row contains (" + canary + ")"}
	tests := []struct {
		name   string
		mutate func(*probeRig)
		want   string
	}{
		{"reading the premise", func(r *probeRig) { r.dueErr = fmt.Errorf("%w", pgErr) }, "read a premise: SQLSTATE 23514"},
		{"reading the allowlist", func(r *probeRig) { r.allowed, r.hostErr = true, errors.New("dial tcp "+canary) }, "read the allowlist: failed"},
		{"recording", func(r *probeRig) { r.recordErr = fmt.Errorf("record an evaluation: %w", pgErr) }, "record a premise evaluation: SQLSTATE 23514"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newProbeRig()
			tt.mutate(r)
			err := r.w.Work(t.Context(), probeJobFor(tenantA))
			if err == nil || err.Error() != tt.want || strings.Contains(err.Error(), canary) {
				t.Errorf("err = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestTheProbeLogsIdsAndOutcomesNeverAURLOrAHost(t *testing.T) {
	var out strings.Builder
	r := newProbeRig()
	r.w.log = slog.New(slog.NewTextHandler(&out, nil))
	r.allowed = true
	r.probe.result = premisecheck.Result{Result: premisecheck.ResultFail, Observed: []byte(`"` + canary + `"`), BodySHA256: digest}
	if err := r.w.Work(t.Context(), probeJobFor(tenantA)); err != nil {
		t.Fatal(err)
	}
	for _, leaked := range []string{"example.com", "platform.json", canary, "postgres-major"} {
		if strings.Contains(out.String(), leaked) {
			t.Errorf("the log line holds %q: %s", leaked, out.String())
		}
	}
	if !strings.Contains(out.String(), "result=fail") || !strings.Contains(out.String(), "reason_opened=true") {
		t.Errorf("log = %s", out.String())
	}
}

func TestSpecOfDecodesTheStoredComparison(t *testing.T) {
	big, ok := specOf(registry.Premise{URL: "u", Pointer: "/p", Expected: json.RawMessage("9007199254740993"), HasEquals: true})
	if !ok || big.Equals != json.Number("9007199254740993") {
		t.Errorf("an integer past a float: %+v", big)
	}
	null, ok := specOf(registry.Premise{Expected: json.RawMessage("null"), HasEquals: true})
	if !ok || !null.HasEquals || null.Equals != nil {
		t.Errorf("null: %+v", null)
	}
	semver, ok := specOf(registry.Premise{Expected: json.RawMessage(`">=16.0.0"`)})
	if !ok || semver.HasEquals || semver.Semver != ">=16.0.0" {
		t.Errorf("semver: %+v", semver)
	}
	if _, ok := specOf(registry.Premise{Expected: json.RawMessage("16")}); ok {
		t.Error("a semver constraint that is a number was accepted")
	}
	if _, ok := specOf(registry.Premise{Expected: json.RawMessage("{")}); ok {
		t.Error("broken JSON was accepted")
	}
}
