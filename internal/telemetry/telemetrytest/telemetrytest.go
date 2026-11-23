// Package telemetrytest gives the tests of instrumented code a Telemetry that keeps what it records. It
// keeps it as the code recorded it, with none of the wrappers that Start puts in front of an exporter, so a
// test sees a key that is not allowed instead of the wrapper hiding it.
package telemetrytest

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"

	"github.com/ipsofacto-io/ipso-server/internal/telemetry"
)

// Recorder holds the spans and the metrics of one Telemetry.
type Recorder struct {
	spans  *tracetest.InMemoryExporter
	reader *sdkmetric.ManualReader
}

// New returns a Telemetry that records into the Recorder, and stops with the test.
func New(t testing.TB) (*telemetry.Telemetry, *Recorder) {
	t.Helper()
	r := &Recorder{spans: tracetest.NewInMemoryExporter(), reader: sdkmetric.NewManualReader()}
	tel, shutdown, err := telemetry.New(resource.Empty(), sdktrace.NewSimpleSpanProcessor(r.spans), r.reader)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = shutdown(context.Background()) })
	return tel, r
}

// Spans are the spans that have ended, oldest first.
func (r *Recorder) Spans() tracetest.SpanStubs { return r.spans.GetSpans() }

// Span returns the one span with the name, and fails the test when there is not exactly one.
func (r *Recorder) Span(t testing.TB, name string) tracetest.SpanStub {
	t.Helper()
	var found []tracetest.SpanStub
	for _, s := range r.Spans() {
		if s.Name == name {
			found = append(found, s)
		}
	}
	if len(found) != 1 {
		t.Fatalf("got %d spans named %q, want 1 (all: %v)", len(found), name, r.names())
	}
	return found[0]
}

func (r *Recorder) names() []string {
	var out []string
	for _, s := range r.Spans() {
		out = append(out, s.Name)
	}
	return out
}

// Points are the data points of the histogram with the name.
func (r *Recorder) Points(t testing.TB, name string) []metricdata.HistogramDataPoint[float64] {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := r.reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			if m.Name == name {
				return m.Data.(metricdata.Histogram[float64]).DataPoints
			}
		}
	}
	return nil
}

// Attrs is a set of attributes as strings.
func Attrs(kvs []attribute.KeyValue) map[string]string {
	out := map[string]string{}
	for _, kv := range kvs {
		out[string(kv.Key)] = kv.Value.String()
	}
	return out
}

// CheckKeys fails the test for a span or a metric point that carries a key outside telemetry.AllowedKeys.
func (r *Recorder) CheckKeys(t testing.TB) {
	t.Helper()
	allowed := map[string]bool{}
	for _, k := range telemetry.AllowedKeys {
		allowed[string(k)] = true
	}
	check := func(where string, kvs []attribute.KeyValue) {
		for _, kv := range kvs {
			if !allowed[string(kv.Key)] {
				t.Errorf("%s carries %q, which is not an allowed key", where, kv.Key)
			}
		}
	}
	for _, s := range r.Spans() {
		check("span "+s.Name, s.Attributes)
	}
	for _, name := range []string{"http.server.request.duration", "ipso.job.duration", "mcp.server.operation.duration"} {
		for _, p := range r.Points(t, name) {
			check("metric "+name, p.Attributes.ToSlice())
			for _, e := range p.Exemplars {
				check("an exemplar of "+name, e.FilteredAttributes)
			}
		}
	}
}
