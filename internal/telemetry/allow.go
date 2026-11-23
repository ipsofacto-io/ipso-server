package telemetry

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// The attribute keys that may leave the process. Nothing names a person, a login, an address, a path, a
// repository or a message (ADR-0012, ADR-0155). The tenant id is the one identifier.
const (
	KeyMethod    = attribute.Key("http.request.method")
	KeyRoute     = attribute.Key("http.route")
	KeyStatus    = attribute.Key("http.response.status_code")
	KeyError     = attribute.Key("error.type")
	KeyTenant    = attribute.Key("ipso.tenant.id")
	KeyJobKind   = attribute.Key("ipso.job.kind")
	KeyOutcome   = attribute.Key("ipso.job.outcome")
	KeyMCPMethod = attribute.Key("mcp.method.name")
	KeyTool      = attribute.Key("gen_ai.tool.name")
)

// AllowedKeys is every attribute key a span or a metric point may carry. The dashboards and their tests read
// it, so a label that is not here cannot be drawn.
var AllowedKeys = []attribute.Key{KeyMethod, KeyRoute, KeyStatus, KeyError, KeyTenant, KeyJobKind, KeyOutcome, KeyMCPMethod, KeyTool}

var allowFilter = attribute.NewAllowKeysFilter(AllowedKeys...)

// allowAttrs keeps the allowed keys of a span.
func allowAttrs(in []attribute.KeyValue) []attribute.KeyValue {
	out := make([]attribute.KeyValue, 0, len(in))
	for _, kv := range in {
		if allowFilter(kv) {
			out = append(out, kv)
		}
	}
	return out
}

// allowSpans passes spans to an exporter with only the allowed attributes. It drops events and links, which
// the code here never records, and the text of a status, which can hold an error message.
type allowSpans struct{ sdktrace.SpanExporter }

func (e allowSpans) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	out := make([]sdktrace.ReadOnlySpan, len(spans))
	for i, s := range spans {
		out[i] = allowedSpan{s}
	}
	return e.SpanExporter.ExportSpans(ctx, out)
}

type allowedSpan struct{ sdktrace.ReadOnlySpan }

func (s allowedSpan) Attributes() []attribute.KeyValue {
	return allowAttrs(s.ReadOnlySpan.Attributes())
}
func (allowedSpan) Events() []sdktrace.Event { return nil }
func (allowedSpan) Links() []sdktrace.Link   { return nil }
func (s allowedSpan) Status() sdktrace.Status {
	return sdktrace.Status{Code: s.ReadOnlySpan.Status().Code}
}

// allowMetrics passes metrics to an exporter with only the allowed attributes on every point, and no
// attribute on an exemplar. A measurement that carried a key the view removed would otherwise reach the
// exemplar as a filtered attribute. Only the histograms of this package leave the process, so any other
// metric is dropped here.
type allowMetrics struct{ sdkmetric.Exporter }

func (e allowMetrics) Export(ctx context.Context, rm *metricdata.ResourceMetrics) error {
	for i := range rm.ScopeMetrics {
		kept := rm.ScopeMetrics[i].Metrics[:0]
		for _, m := range rm.ScopeMetrics[i].Metrics {
			h, ok := m.Data.(metricdata.Histogram[float64])
			if !ok {
				continue
			}
			for j := range h.DataPoints {
				p := &h.DataPoints[j]
				p.Attributes, _ = p.Attributes.Filter(allowFilter)
				for k := range p.Exemplars {
					p.Exemplars[k].FilteredAttributes = nil
				}
			}
			m.Data = h
			kept = append(kept, m)
		}
		rm.ScopeMetrics[i].Metrics = kept
	}
	return e.Exporter.Export(ctx, rm)
}
