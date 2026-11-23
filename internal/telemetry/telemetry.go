// Package telemetry exports OpenTelemetry traces and metrics over OTLP/HTTP (ADR-0155). It is off until the
// operator sets OTEL_EXPORTER_OTLP_ENDPOINT, so a process that is not told where to send telemetry sends
// none (section 15, the CRA statement that the binary does not phone home).
//
// What leaves the process is decided here and nowhere else. The only attributes are the keys in
// AllowedKeys, and every value comes from a bounded set: the route is a registered pattern and never a
// path, a method outside the standard list is _OTHER, a kind is a constant, and the one identifier is the
// tenant id. Two more layers back that up in case a later change records something else: a metric view that
// keeps only the allowed keys, and exporter wrappers that drop every other span attribute, every span
// event and link, every status message, and the attributes an exemplar carries (ADR-0012, ADR-0155).
package telemetry

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/exemplar"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

const (
	// EnvEndpoint turns telemetry on. The rest of the OTEL_EXPORTER_OTLP_* variables (headers, timeout,
	// certificates) and OTEL_RESOURCE_ATTRIBUTES, OTEL_TRACES_SAMPLER, OTEL_BSP_* and
	// OTEL_METRIC_EXPORT_INTERVAL are read by the SDK from the process environment.
	EnvEndpoint = "OTEL_EXPORTER_OTLP_ENDPOINT"
	// EnvDisabled set to true keeps telemetry off even when an endpoint is set.
	EnvDisabled = "OTEL_SDK_DISABLED"

	scopeName = "github.com/ipsofacto-io/ipso-server/internal/telemetry"
	namespace = "ipso"
	// protocol is the only one the exporters here speak.
	protocol = "http/protobuf"
	// errorEvery bounds how often an export failure is logged. A collector that is down fails every batch.
	errorEvery = time.Minute
)

// Options is what Start needs. Getenv reads the gate and the checked variables. The SDK reads the rest of the
// OTEL_* variables from the process environment itself.
type Options struct {
	// Service is the service.name of the process: ipso-api, ipso-worker, ipso-webhooks or ipso-runtasks.
	Service string
	Version string
	Getenv  func(string) string
	// Logger receives one line a minute when an export fails. It never receives the error text, which can
	// hold the endpoint.
	Logger *slog.Logger
}

// Telemetry holds the tracer and the instruments of one process. A nil *Telemetry is the off state: every
// method on it does nothing.
type Telemetry struct {
	tracer trace.Tracer
	http   metric.Float64Histogram
	job    metric.Float64Histogram
	mcp    metric.Float64Histogram
}

// Start returns the telemetry of a process, and the function that flushes and stops it. It returns nil, and
// a function that does nothing, when no endpoint is set or the SDK is disabled. It refuses a protocol or an
// exporter other than OTLP over HTTP with protobuf, because those are the only ones built in.
func Start(ctx context.Context, o Options) (*Telemetry, func(context.Context) error, error) {
	getenv := o.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}
	off := func(context.Context) error { return nil }
	if strings.EqualFold(strings.TrimSpace(getenv(EnvDisabled)), "true") || strings.TrimSpace(getenv(EnvEndpoint)) == "" {
		return nil, off, nil
	}
	if err := checkSettings(getenv); err != nil {
		return nil, off, err
	}
	spans, err := otlptracehttp.New(ctx)
	if err != nil {
		return nil, off, fmt.Errorf("telemetry: the trace exporter: %w", err)
	}
	metrics, err := otlpmetrichttp.New(ctx)
	if err != nil {
		return nil, off, fmt.Errorf("telemetry: the metric exporter: %w", err)
	}
	logger := o.Logger
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	var last atomic.Int64
	otel.SetErrorHandler(otel.ErrorHandlerFunc(func(error) {
		now := time.Now().UnixNano()
		if prev := last.Load(); now-prev < int64(errorEvery) || !last.CompareAndSwap(prev, now) {
			return
		}
		logger.Warn("telemetry export failed, check the collector endpoint and the OTEL_EXPORTER_OTLP_* variables")
	}))
	res, err := resource.Merge(resource.Default(), resource.NewWithAttributes("",
		attribute.String("service.namespace", namespace),
		attribute.String("service.name", o.Service),
		attribute.String("service.version", o.Version),
	))
	if err != nil {
		return nil, off, fmt.Errorf("telemetry: the resource: %w", err)
	}
	t, shutdown, err := New(res, sdktrace.NewBatchSpanProcessor(allowSpans{spans}), sdkmetric.NewPeriodicReader(allowMetrics{metrics}))
	if err != nil {
		return nil, off, err
	}
	return t, shutdown, nil
}

// checkSettings refuses what the build cannot do, so a process does not start and then export nothing.
func checkSettings(getenv func(string) string) error {
	for _, name := range []string{"OTEL_EXPORTER_OTLP_PROTOCOL", "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL", "OTEL_EXPORTER_OTLP_METRICS_PROTOCOL"} {
		if v := strings.TrimSpace(getenv(name)); v != "" && v != protocol {
			return fmt.Errorf("telemetry: %s must be %s or unset", name, protocol)
		}
	}
	for _, name := range []string{"OTEL_TRACES_EXPORTER", "OTEL_METRICS_EXPORTER"} {
		if v := strings.TrimSpace(getenv(name)); v != "" && v != "otlp" {
			return fmt.Errorf("telemetry: %s must be otlp or unset", name)
		}
	}
	return nil
}

// New makes the tracer and the instruments over a span processor and a metric reader, and returns the function
// that stops them. Start gives it the OTLP exporters behind the wrappers of this package, and the tests of
// instrumented code give it memory (telemetrytest).
func New(res *resource.Resource, processor sdktrace.SpanProcessor, reader sdkmetric.Reader) (*Telemetry, func(context.Context) error, error) {
	tp := sdktrace.NewTracerProvider(sdktrace.WithResource(res), sdktrace.WithSpanProcessor(processor))
	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithResource(res),
		sdkmetric.WithReader(reader),
		sdkmetric.WithExemplarFilter(exemplar.TraceBasedFilter),
		sdkmetric.WithView(sdkmetric.NewView(
			sdkmetric.Instrument{Scope: instrumentation.Scope{Name: scopeName}},
			sdkmetric.Stream{AttributeFilter: attribute.NewAllowKeysFilter(AllowedKeys...)},
		)),
	)
	shutdown := func(ctx context.Context) error {
		return errors.Join(tp.Shutdown(ctx), mp.Shutdown(ctx))
	}
	meter := mp.Meter(scopeName)
	t := &Telemetry{tracer: tp.Tracer(scopeName)}
	var err error
	// The bounds hold the section 15 thresholds: 0.4 s and 0.5 s for the MCP and bundle objectives, and 60 s
	// and 300 s for a check result and a notification.
	if t.http, err = meter.Float64Histogram("http.server.request.duration", metric.WithUnit("s"),
		metric.WithDescription("Duration of an HTTP request served by this process."),
		metric.WithExplicitBucketBoundaries(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.4, 0.5, 1, 2.5, 5, 10)); err != nil {
		return nil, nil, err
	}
	if t.job, err = meter.Float64Histogram("ipso.job.duration", metric.WithUnit("s"),
		metric.WithDescription("Time from the moment a job was due to its end, so the wait in a queue counts."),
		metric.WithExplicitBucketBoundaries(0.1, 0.5, 1, 5, 10, 30, 60, 120, 300, 600, 1800)); err != nil {
		return nil, nil, err
	}
	if t.mcp, err = meter.Float64Histogram("mcp.server.operation.duration", metric.WithUnit("s"),
		metric.WithDescription("Duration of an MCP operation."),
		metric.WithExplicitBucketBoundaries(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.4, 0.5, 1, 2.5, 5, 10)); err != nil {
		return nil, nil, err
	}
	return t, shutdown, nil
}

func (t *Telemetry) on() bool { return t != nil && t.tracer != nil }
