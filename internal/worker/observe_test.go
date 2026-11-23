package worker

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/riverqueue/river/rivertype"

	"github.com/ipsofacto-io/ipso-server/internal/telemetry/telemetrytest"
)

func TestTheObserverGivesAJobItsKindItsTenantAndItsWait(t *testing.T) {
	tel, rec := telemetrytest.New(t)
	tenant := uuid.MustParse("3f1d5d4c-6a52-4b0c-9a5e-3d7a2c9a1e10")
	o := &observer{tel: tel, tenant: tenant}
	row := &rivertype.JobRow{Kind: "premise_probe", ScheduledAt: time.Now().Add(-2 * time.Minute)}

	if err := o.Work(context.Background(), row, func(context.Context) error { return nil }); err != nil {
		t.Fatal(err)
	}
	got := telemetrytest.Attrs(rec.Span(t, "job premise_probe").Attributes)
	if got["ipso.job.kind"] != "premise_probe" || got["ipso.job.outcome"] != "ok" || got["ipso.tenant.id"] != tenant.String() {
		t.Errorf("the span: %v", got)
	}
	points := rec.Points(t, "ipso.job.duration")
	if len(points) != 1 || points[0].Sum < 120 {
		t.Errorf("a job scheduled two minutes ago was measured as %+v", points)
	}
	rec.CheckKeys(t)
}

func TestTheObserverPassesTheErrorOnAndRecordsItAsAnOutcomeOnly(t *testing.T) {
	tel, rec := telemetrytest.New(t)
	o := &observer{tel: tel, tenant: uuid.New()}
	failure := errors.New("the database said: password authentication failed for ada@example.org")
	if err := o.Work(context.Background(), &rivertype.JobRow{Kind: "waiver_notices"}, func(context.Context) error { return failure }); !errors.Is(err, failure) {
		t.Fatalf("the error became %v", err)
	}
	span := rec.Span(t, "job waiver_notices")
	if telemetrytest.Attrs(span.Attributes)["ipso.job.outcome"] != "error" || span.Status.Description != "" || len(span.Events) != 0 {
		t.Errorf("span %v status %+v", telemetrytest.Attrs(span.Attributes), span.Status)
	}
}

func TestTheObserverRecordsAPanicAndRaisesItAgain(t *testing.T) {
	tel, rec := telemetrytest.New(t)
	o := &observer{tel: tel, tenant: uuid.New()}
	func() {
		defer func() {
			if recover() != "boom" {
				t.Error("the panic was not raised again")
			}
		}()
		_ = o.Work(context.Background(), &rivertype.JobRow{Kind: "chat_digests"}, func(context.Context) error { panic("boom") })
	}()
	if got := telemetrytest.Attrs(rec.Span(t, "job chat_digests").Attributes)["ipso.job.outcome"]; got != "panic" {
		t.Errorf("outcome %q", got)
	}
}

func TestJobsAreObservedOnlyWhenTelemetryIsOn(t *testing.T) {
	tel, _ := telemetrytest.New(t)
	if got := middleware(Config{Tenant: uuid.New()}); len(got) != 0 {
		t.Errorf("%d middleware with telemetry off", len(got))
	}
	got := middleware(Config{Tenant: uuid.New(), Telemetry: tel})
	if len(got) != 1 {
		t.Fatalf("%d middleware with telemetry on", len(got))
	}
	if _, ok := got[0].(rivertype.WorkerMiddleware); !ok {
		t.Errorf("%T does not wrap the work of a job", got[0])
	}
}
