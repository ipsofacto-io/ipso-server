package worker

import (
	"context"

	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/ipsofacto-io/ipso-server/internal/telemetry"
)

// observer is the River middleware that gives each job a span and a duration (ADR-0155). The kind is the one
// River keeps for the job, a constant of this package, and the tenant is the one this process serves. The
// duration counts from the time the job was scheduled for, so the wait in a queue is part of it.
type observer struct {
	river.MiddlewareDefaults
	tel    *telemetry.Telemetry
	tenant uuid.UUID
}

func (o *observer) Work(ctx context.Context, job *rivertype.JobRow, doInner func(context.Context) error) (err error) {
	ctx, end := o.tel.StartJob(ctx, job.Kind, o.tenant, job.ScheduledAt)
	defer func() {
		if recovered := recover(); recovered != nil {
			end(telemetry.ErrPanic)
			panic(recovered)
		}
		end(err)
	}()
	return doInner(ctx)
}
