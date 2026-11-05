package worker

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/riverqueue/river"

	"github.com/ipsofacto-io/ipso-server/internal/registry"
	"github.com/ipsofacto-io/ipso/pkg/premisecheck"
)

const (
	premiseProbeKind  = "premise_probe"
	premiseProbeQueue = "premise_probe"
	// premiseProbeWorkers bounds the outbound requests of one process. Probes take up to ten seconds, so
	// four workers make at least 1,440 probes an hour.
	premiseProbeWorkers = 4
	// The probe itself stops after ten seconds, including name resolution. The rest is the database.
	premiseProbeTimeout = 30 * time.Second
	// A probe that did not finish is tried three times. A probe that finished, an error included, wrote
	// its evaluation and is not tried again.
	premiseProbeAttempts = 3
)

// dueOneFunc is registry.DuePremise, hostAllowedFunc is registry.HostAllowed, and recordFunc is
// registry.RecordEvaluation. Tests replace them.
type (
	dueOneFunc      func(ctx context.Context, db *sql.DB, tenant uuid.UUID, ref registry.PremiseRef) (registry.Premise, bool, error)
	hostAllowedFunc func(ctx context.Context, db *sql.DB, tenant uuid.UUID, host string) (bool, error)
	recordFunc      func(ctx context.Context, db *sql.DB, tenant uuid.UUID, ev registry.Evaluation) (bool, error)
)

// prober is premisecheck.Client. Tests replace it.
type prober interface {
	Check(ctx context.Context, spec premisecheck.Spec) premisecheck.Result
}

// PremiseProbeArgs is what the job carries: the tenant id and the key of the premise, the decision id
// and the premise id. It holds no URL, statement, or value (ADR-0096).
type PremiseProbeArgs struct {
	Tenant   uuid.UUID `json:"tenant"`
	Decision uuid.UUID `json:"decision"`
	Premise  string    `json:"premise"`
}

// Kind is the kind of the job.
func (PremiseProbeArgs) Kind() string { return premiseProbeKind }

// InsertOpts puts the job in its own queue and makes it unique for its arguments while it waits, runs,
// or is due a retry, so one premise is probed at a time.
func (PremiseProbeArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		MaxAttempts: premiseProbeAttempts,
		Queue:       premiseProbeQueue,
		UniqueOpts:  river.UniqueOpts{ByArgs: true, ByState: activeStates()},
	}
}

// premiseProbe re-checks one premise of the tenant this process serves.
type premiseProbe struct {
	river.WorkerDefaults[PremiseProbeArgs]
	db      *sql.DB
	tenant  uuid.UUID
	log     *slog.Logger
	due     dueOneFunc
	allowed hostAllowedFunc
	probe   prober
	record  recordFunc
}

func (*premiseProbe) Timeout(*river.Job[PremiseProbeArgs]) time.Duration {
	return premiseProbeTimeout
}

// Work refuses a job for another tenant before it touches the database. It reads the premise again, so a
// job that is no longer due, or whose decision is no longer in force, finishes and writes nothing. A host
// the tenant has not allowed is recorded as an error without a lookup or a request. Every other outcome of
// the probe, an error included, is one evaluation, and only a fail opens a reason. A probe cut short by
// the process stopping records nothing and is tried again. Failures and the log line follow the rules of
// the notice sweep: an operation and a class of cause, and ids only.
func (w *premiseProbe) Work(ctx context.Context, job *river.Job[PremiseProbeArgs]) error {
	if job.Args.Tenant != w.tenant {
		w.log.Warn("a job names another tenant, so it was cancelled", "job", job.ID, "tenant", w.tenant)
		return river.JobCancel(errOtherTenant)
	}
	ref := registry.PremiseRef{Decision: job.Args.Decision, ID: job.Args.Premise}
	premise, due, err := w.due(ctx, w.db, w.tenant, ref)
	if err != nil {
		return reduce("read a premise", err)
	}
	if !due {
		w.log.Info("premise probe skipped", "job", job.ID, "tenant", w.tenant, "decision", ref.Decision, "outcome", "not due")
		return nil
	}

	allowed := false
	if host, ok := premisecheck.Host(premise.URL); ok {
		if allowed, err = w.allowed(ctx, w.db, w.tenant, host); err != nil {
			return reduce("read the allowlist", err)
		}
	}
	ev := evaluationOf(ctx, w.probe, premise, allowed)
	if err := ctx.Err(); err != nil {
		return reduce("probe a premise", err)
	}
	opened, err := w.record(ctx, w.db, w.tenant, ev)
	if err != nil {
		return reduce("record a premise evaluation", err)
	}
	w.log.Info("premise probed", "job", job.ID, "tenant", w.tenant, "decision", ref.Decision,
		"result", ev.Result, "reason_opened", opened)
	return nil
}

// evaluationOf runs the probe, or skips it for a host that is not allowed, and returns the evaluation to
// record. The expected value is the one stored on the decision, in both cases. A result that would break
// a constraint of the table, which the probe does not produce, is recorded as an error that holds nothing
// of the response.
func evaluationOf(ctx context.Context, client prober, premise registry.Premise, allowed bool) registry.Evaluation {
	ev := registry.Evaluation{
		Ref:      premise.Ref,
		Result:   premisecheck.ResultError,
		URL:      premise.URL,
		Pointer:  premise.Pointer,
		Expected: premise.Expected,
	}
	if !allowed {
		return ev
	}
	spec, ok := specOf(premise)
	if !ok {
		return ev
	}
	got := client.Check(ctx, spec)
	digest, digestOK := digestOf(got.BodySHA256)
	switch got.Result {
	case premisecheck.ResultPass, premisecheck.ResultFail:
		if !digestOK || len(got.Observed) == 0 {
			return ev
		}
		ev.Result, ev.Observed, ev.BodySHA256 = got.Result, got.Observed, digest
	default:
		if digestOK {
			ev.BodySHA256 = digest
		}
		if len(got.Observed) > 0 {
			ev.Observed = got.Observed
		}
	}
	return ev
}

// specOf builds the probe from the stored premise. Numbers decode as json.Number, so an integer past what
// a float holds compares exactly.
func specOf(premise registry.Premise) (premisecheck.Spec, bool) {
	spec := premisecheck.Spec{URL: premise.URL, Pointer: premise.Pointer, HasEquals: premise.HasEquals}
	dec := json.NewDecoder(bytes.NewReader(premise.Expected))
	dec.UseNumber()
	var value any
	if err := dec.Decode(&value); err != nil {
		return spec, false
	}
	if premise.HasEquals {
		spec.Equals = value
		return spec, true
	}
	constraint, ok := value.(string)
	spec.Semver = constraint
	return spec, ok
}

func digestOf(text string) ([]byte, bool) {
	digest, err := hex.DecodeString(text)
	return digest, err == nil && len(digest) == 32
}
