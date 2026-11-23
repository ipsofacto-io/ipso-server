package telemetry

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"

	"github.com/ipsofacto-io/ipso/pkg/mcptools"
)

// ErrPanic is what a job that panicked ends with, for the code that recovers it. Its text is what the logs
// of the webhook service already say.
var ErrPanic = errors.New("the job panicked")

// The outcomes of a job. They are the whole set of ipso.job.outcome.
const (
	outcomeOK       = "ok"
	outcomeError    = "error"
	outcomeTimeout  = "timeout"
	outcomeCanceled = "canceled"
	outcomePanic    = "panic"
)

func outcomeOf(err error) string {
	switch {
	case err == nil:
		return outcomeOK
	case errors.Is(err, ErrPanic):
		return outcomePanic
	case errors.Is(err, context.DeadlineExceeded):
		return outcomeTimeout
	case errors.Is(err, context.Canceled):
		return outcomeCanceled
	}
	return outcomeError
}

// StartJob starts the span of one job and returns the context to run it under, and the function to call with
// the result when it ends. kind is a constant of the code that runs the job, never a name taken from input.
// due is when the job could first have run: a job that waited in a queue counts that wait, which is what the
// objective of section 15 for a check result measures. A zero due counts from the start.
//
// A parent span in ctx is the parent of the job. A job with none starts a trace.
func (t *Telemetry) StartJob(ctx context.Context, kind string, tenant uuid.UUID, due time.Time) (context.Context, func(error)) {
	if !t.on() {
		return ctx, func(error) {}
	}
	start := time.Now()
	if due.IsZero() || due.After(start) {
		due = start
	}
	ctx, span := t.tracer.Start(ctx, "job "+kind)
	return ctx, func(err error) {
		outcome := outcomeOf(err)
		attrs := withTenant([]attribute.KeyValue{KeyJobKind.String(kind), KeyOutcome.String(outcome)}, tenant)
		if outcome != outcomeOK {
			span.SetStatus(codes.Error, "")
		}
		span.SetAttributes(attrs...)
		t.job.Record(ctx, time.Since(due).Seconds(), metric.WithAttributes(attrs...))
		span.End()
	}
}

// Remote makes the span of an earlier request the parent of the work that request queued.
func Remote(ctx context.Context, parent trace.SpanContext) context.Context {
	if !parent.IsValid() {
		return ctx
	}
	return trace.ContextWithRemoteSpanContext(ctx, parent)
}

// SpanContext is the span context in ctx, to keep with work that runs after the request ends.
func SpanContext(ctx context.Context) trace.SpanContext { return trace.SpanContextFromContext(ctx) }

// StartMCP starts the span of one MCP operation and returns the context to run it under, and the function to
// call when it ends, with whether the answer was an error. The method and the tool are kept only when the
// MCP server of this product defines them, so a name a client invents is not an attribute.
func (t *Telemetry) StartMCP(ctx context.Context, tenant uuid.UUID, method, tool string) (context.Context, func(failed bool)) {
	if !t.on() {
		return ctx, func(bool) {}
	}
	start := time.Now()
	method = mcpMethodOf(method)
	attrs := withTenant([]attribute.KeyValue{KeyMCPMethod.String(method)}, tenant)
	name := method
	if method == "tools/call" && knownTool(tool) {
		attrs = append(attrs, KeyTool.String(tool))
		name += " " + tool
	}
	ctx, span := t.tracer.Start(ctx, name)
	return ctx, func(failed bool) {
		if failed {
			attrs = append(attrs, KeyError.String("rpc_error"))
			span.SetStatus(codes.Error, "")
		}
		span.SetAttributes(attrs...)
		t.mcp.Record(ctx, time.Since(start).Seconds(), metric.WithAttributes(attrs...))
		span.End()
	}
}

func mcpMethodOf(method string) string {
	switch method {
	case "initialize", "ping", "server/discover", "tools/list", "tools/call":
		return method
	}
	return "_OTHER"
}

func knownTool(name string) bool {
	switch name {
	case mcptools.ToolApplicable, mcptools.ToolGet, mcptools.ToolEvaluate, mcptools.ToolPropose:
		return true
	}
	return false
}
