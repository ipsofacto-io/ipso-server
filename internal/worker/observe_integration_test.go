//go:build integration

package worker

import (
	"testing"

	"github.com/ipsofacto-io/ipso-server/internal/telemetry/telemetrytest"
)

// A real River client runs the jobs of a real database, and each job has a span and a duration with the tenant
// of the worker (ADR-0155). The jobs are the ones the worker starts with, and the tenant is its own.
func TestTheJobsOfARealWorkerAreObservedWithItsTenant(t *testing.T) {
	s := newStack(t)
	tel, rec := telemetrytest.New(t)
	s.telemetry = tel
	s.start(t, tenantA)

	eventually(t, "a sweep completed", func() bool { return s.jobs(t, `kind = 'waiver_notices' AND state = 'completed'`) >= 1 })
	eventually(t, "the span of the sweep ended", func() bool {
		for _, span := range rec.Spans() {
			if span.Name == "job waiver_notices" {
				return true
			}
		}
		return false
	})
	span := rec.Span(t, "job waiver_notices")
	got := telemetrytest.Attrs(span.Attributes)
	if got["ipso.job.kind"] != "waiver_notices" || got["ipso.job.outcome"] != "ok" || got["ipso.tenant.id"] != tenantA.String() {
		t.Errorf("the span: %v", got)
	}
	if len(rec.Points(t, "ipso.job.duration")) == 0 {
		t.Error("no job duration was recorded")
	}
	rec.CheckKeys(t)
}
