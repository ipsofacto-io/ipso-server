package telemetry

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	collectormetrics "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	collectortrace "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	"google.golang.org/protobuf/proto"

	"github.com/ipsofacto-io/ipso/pkg/mcptools"
)

var tenantID = uuid.MustParse("3f1d5d4c-6a52-4b0c-9a5e-3d7a2c9a1e10")

// harness is a Telemetry that keeps what it would export, behind the same wrappers the OTLP exporters get.
type harness struct {
	t       *Telemetry
	spans   *tracetest.InMemoryExporter
	reader  *sdkmetric.ManualReader
	closing func(context.Context) error
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	spans := tracetest.NewInMemoryExporter()
	reader := sdkmetric.NewManualReader()
	tel, shutdown, err := New(resource.Empty(), sdktrace.NewSimpleSpanProcessor(allowSpans{spans}), reader)
	if err != nil {
		t.Fatal(err)
	}
	return &harness{t: tel, spans: spans, reader: reader, closing: shutdown}
}

func (h *harness) metrics(t *testing.T) map[string]metricdata.Histogram[float64] {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := h.reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	out := map[string]metricdata.Histogram[float64]{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			out[m.Name] = m.Data.(metricdata.Histogram[float64])
		}
	}
	return out
}

func keysOf(kvs []attribute.KeyValue) map[string]string {
	out := map[string]string{}
	for _, kv := range kvs {
		out[string(kv.Key)] = kv.Value.String()
	}
	return out
}

func onlyAllowed(t *testing.T, where string, got map[string]string) {
	t.Helper()
	allowed := map[string]bool{}
	for _, k := range AllowedKeys {
		allowed[string(k)] = true
	}
	for k := range got {
		if !allowed[k] {
			t.Errorf("%s carries %q, which is not an allowed key", where, k)
		}
	}
}

func TestStartIsOffWithoutAnEndpointOrWhenDisabled(t *testing.T) {
	for name, env := range map[string]map[string]string{
		"no endpoint": {},
		"blank":       {EnvEndpoint: "  "},
		"disabled":    {EnvEndpoint: "http://collector:4318", EnvDisabled: "TRUE"},
	} {
		tel, shutdown, err := Start(context.Background(), Options{Service: "ipso-api", Getenv: func(k string) string { return env[k] }})
		if err != nil || tel != nil {
			t.Fatalf("%s: got %v, %v, want no telemetry and no error", name, tel, err)
		}
		if err := shutdown(context.Background()); err != nil {
			t.Fatalf("%s: shutdown: %v", name, err)
		}
		// The off state is a nil value and every method accepts it.
		h := tel.Handler(tenantID, http.NotFoundHandler())
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/x", nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s: the handler changed the answer to %d", name, rec.Code)
		}
		ctx, end := tel.StartJob(context.Background(), "k", tenantID, time.Time{})
		end(nil)
		_, endMCP := tel.StartMCP(ctx, tenantID, "tools/list", "")
		endMCP(false)
	}
}

func TestStartRefusesWhatItCannotSpeak(t *testing.T) {
	for _, bad := range []map[string]string{
		{"OTEL_EXPORTER_OTLP_PROTOCOL": "grpc"},
		{"OTEL_EXPORTER_OTLP_TRACES_PROTOCOL": "http/json"},
		{"OTEL_EXPORTER_OTLP_METRICS_PROTOCOL": "grpc"},
		{"OTEL_TRACES_EXPORTER": "console"},
		{"OTEL_METRICS_EXPORTER": "prometheus"},
	} {
		env := map[string]string{EnvEndpoint: "http://collector:4318"}
		for k, v := range bad {
			env[k] = v
		}
		if _, _, err := Start(context.Background(), Options{Getenv: func(k string) string { return env[k] }}); err == nil {
			t.Errorf("%v: started, want a refusal", bad)
		}
	}
	for _, good := range []string{"http/protobuf", ""} {
		env := map[string]string{EnvEndpoint: "http://collector:4318", "OTEL_EXPORTER_OTLP_PROTOCOL": good, "OTEL_TRACES_EXPORTER": "otlp"}
		tel, shutdown, err := Start(context.Background(), Options{Service: "ipso-api", Getenv: func(k string) string { return env[k] }})
		if err != nil || tel == nil {
			t.Fatalf("protocol %q: %v, %v", good, tel, err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		_ = shutdown(ctx)
		cancel()
	}
}

func TestHandlerRecordsTheRouteTheStatusAndTheTenant(t *testing.T) {
	h := newHarness(t)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/decisions/{ref}", func(w http.ResponseWriter, r *http.Request) {
		SetRoute(r.Context(), r.Pattern)
		w.WriteHeader(http.StatusTeapot)
	})
	handler := h.t.Handler(tenantID, mux)

	// The path holds an identifier and the query holds a name: neither may reach the telemetry.
	req := httptest.NewRequest(http.MethodGet, "/v1/decisions/ada.lovelace@example.org?author=ada", nil)
	req.Header.Set("User-Agent", "secret-agent")
	req.RemoteAddr = "203.0.113.9:4000"
	handler.ServeHTTP(httptest.NewRecorder(), req)

	spans := h.spans.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(spans))
	}
	span := spans[0]
	if span.Name != "GET /v1/decisions/{ref}" || span.SpanKind != trace.SpanKindServer {
		t.Errorf("span %q kind %v", span.Name, span.SpanKind)
	}
	got := keysOf(span.Attributes)
	want := map[string]string{
		"http.request.method": "GET", "http.route": "/v1/decisions/{ref}", "http.response.status_code": "418",
		"ipso.tenant.id": tenantID.String(),
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("span %s = %q, want %q", k, got[k], v)
		}
	}
	onlyAllowed(t, "the span", got)
	for k, v := range got {
		for _, secret := range []string{"ada", "secret-agent", "203.0.113.9"} {
			if strings.Contains(v, secret) {
				t.Errorf("span %s = %q holds %q", k, v, secret)
			}
		}
	}

	hist := h.metrics(t)["http.server.request.duration"]
	if len(hist.DataPoints) != 1 {
		t.Fatalf("got %d points, want 1", len(hist.DataPoints))
	}
	point := hist.DataPoints[0]
	if point.Count != 1 {
		t.Errorf("count %d", point.Count)
	}
	pointAttrs := keysOf(point.Attributes.ToSlice())
	for k, v := range want {
		if pointAttrs[k] != v {
			t.Errorf("point %s = %q, want %q", k, pointAttrs[k], v)
		}
	}
	onlyAllowed(t, "the point", pointAttrs)
	if len(point.Exemplars) != 1 || len(point.Exemplars[0].TraceID) == 0 {
		t.Errorf("exemplars %+v, want one that names the trace", point.Exemplars)
	}
}

func TestHandlerFallsBackToTheRootPatternAndKeepsTheInnermostRoute(t *testing.T) {
	h := newHarness(t)
	inner := http.NewServeMux()
	inner.HandleFunc("GET /auth/login/{provider}", func(http.ResponseWriter, *http.Request) {})
	root := http.NewServeMux()
	// The root mux hands the whole subtree to the inner one, behind a handler that copies the request.
	root.Handle("/auth/", http.TimeoutHandler(Routed(inner), time.Second, "slow"))
	root.HandleFunc("/", func(http.ResponseWriter, *http.Request) {})
	handler := h.t.Handler(uuid.Nil, root)

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/auth/login/okta-of-ada", nil))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/some/page/ada", nil))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("BREW", "/", nil))

	var names []string
	for _, s := range h.spans.GetSpans() {
		names = append(names, s.Name)
		if _, has := keysOf(s.Attributes)["ipso.tenant.id"]; has {
			t.Errorf("%s has a tenant, but the process has none", s.Name)
		}
	}
	want := []string{"GET /auth/login/{provider}", "GET /", "_OTHER /"}
	if strings.Join(names, "|") != strings.Join(want, "|") {
		t.Errorf("span names %v, want %v", names, want)
	}
}

func TestHandlerTakesTheTenantALaterStageLearns(t *testing.T) {
	h := newHarness(t)
	handler := h.t.Handler(uuid.Nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		SetTenant(r.Context(), tenantID)
		w.WriteHeader(http.StatusAccepted)
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/webhooks/github", nil))
	if got := keysOf(h.spans.GetSpans()[0].Attributes)["ipso.tenant.id"]; got != tenantID.String() {
		t.Errorf("tenant %q", got)
	}
}

func TestHandlerStartsATraceOfItsOwnAndSkipsHealth(t *testing.T) {
	h := newHarness(t)
	handler := h.t.Handler(tenantID, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Traceparent", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")
	handler.ServeHTTP(httptest.NewRecorder(), req)
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/healthz", nil))

	spans := h.spans.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans, want the one of /x and none for /healthz", len(spans))
	}
	if spans[0].SpanContext.TraceID().String() == "0af7651916cd43dd8448eb211c80319c" || spans[0].Parent.IsValid() {
		t.Error("the span joined the trace of the caller")
	}
}

func TestHandlerMarksAServerErrorAndAPanic(t *testing.T) {
	h := newHarness(t)
	handler := h.t.Handler(tenantID, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/panic" {
			panic(http.ErrAbortHandler)
		}
		http.Error(w, "the database said: password authentication failed for user ada", http.StatusBadGateway)
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/boom", nil))
	func() {
		defer func() {
			if recover() != http.ErrAbortHandler {
				t.Error("the panic was not raised again")
			}
		}()
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/panic", nil))
	}()

	spans := h.spans.GetSpans()
	if len(spans) != 2 {
		t.Fatalf("got %d spans", len(spans))
	}
	for i, wantType := range []string{"502", "panic"} {
		got := keysOf(spans[i].Attributes)
		if got["error.type"] != wantType || spans[i].Status.Code != codes.Error || spans[i].Status.Description != "" {
			t.Errorf("span %d: %v status %+v", i, got, spans[i].Status)
		}
	}
	if got := keysOf(spans[1].Attributes)["http.response.status_code"]; got != "500" {
		t.Errorf("a panic is recorded as %s, want 500", got)
	}
}

func TestStatusWriterStillLetsTheResponseControllerFlush(t *testing.T) {
	h := newHarness(t)
	var flushed error
	handler := h.t.Handler(tenantID, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "part")
		flushed = http.NewResponseController(w).Flush()
	}))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/archive", nil))
	if flushed != nil || !rec.Flushed {
		t.Errorf("flush: %v, flushed %v", flushed, rec.Flushed)
	}
}

func TestAllowSpansDropsWhatIsNotAllowed(t *testing.T) {
	mem := tracetest.NewInMemoryExporter()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sdktrace.NewSimpleSpanProcessor(allowSpans{mem})))
	_, span := tp.Tracer("x").Start(context.Background(), "op")
	span.SetAttributes(KeyRoute.String("/v1/x"), attribute.String("user.email", "ada@example.org"), attribute.String("url.full", "https://x/?token=abc"))
	span.AddEvent("exception", trace.WithAttributes(attribute.String("exception.message", "ada@example.org")))
	span.RecordError(errors.New("ada@example.org"))
	span.SetStatus(codes.Error, "ada@example.org")
	span.End()

	got := mem.GetSpans()[0]
	if len(got.Events) != 0 || got.Status.Description != "" || got.Status.Code != codes.Error {
		t.Errorf("events %v, status %+v", got.Events, got.Status)
	}
	attrs := keysOf(got.Attributes)
	if len(attrs) != 1 || attrs["http.route"] != "/v1/x" {
		t.Errorf("attributes %v, want only the route", attrs)
	}
}

type captureExporter struct {
	sdkmetric.Exporter
	got *metricdata.ResourceMetrics
}

func (c *captureExporter) Export(_ context.Context, rm *metricdata.ResourceMetrics) error {
	c.got = rm
	return nil
}

func TestAllowMetricsDropsWhatIsNotAllowedEvenOnAnExemplar(t *testing.T) {
	set := attribute.NewSet(KeyRoute.String("/v1/x"), attribute.String("user.email", "ada@example.org"))
	rm := &metricdata.ResourceMetrics{ScopeMetrics: []metricdata.ScopeMetrics{{Metrics: []metricdata.Metrics{
		{Name: "ours", Data: metricdata.Histogram[float64]{DataPoints: []metricdata.HistogramDataPoint[float64]{{
			Attributes: set,
			Exemplars:  []metricdata.Exemplar[float64]{{FilteredAttributes: []attribute.KeyValue{attribute.String("user.email", "ada@example.org")}, Value: 1}},
		}}}},
		{Name: "someone else's", Data: metricdata.Sum[int64]{DataPoints: []metricdata.DataPoint[int64]{{Attributes: set, Value: 1}}}},
	}}}}
	capture := &captureExporter{}
	if err := (allowMetrics{capture}).Export(context.Background(), rm); err != nil {
		t.Fatal(err)
	}
	metrics := capture.got.ScopeMetrics[0].Metrics
	if len(metrics) != 1 || metrics[0].Name != "ours" {
		t.Fatalf("metrics %v, want the histogram only", metrics)
	}
	point := metrics[0].Data.(metricdata.Histogram[float64]).DataPoints[0]
	if got := keysOf(point.Attributes.ToSlice()); len(got) != 1 || got["http.route"] != "/v1/x" {
		t.Errorf("point attributes %v", got)
	}
	if len(point.Exemplars[0].FilteredAttributes) != 0 {
		t.Errorf("the exemplar kept %v", point.Exemplars[0].FilteredAttributes)
	}
}

func TestTheViewRemovesAKeyThatIsNotAllowed(t *testing.T) {
	h := newHarness(t)
	h.t.http.Record(context.Background(), 1, metric.WithAttributes(KeyRoute.String("/v1/x"), attribute.String("enduser.id", "ada")))
	point := h.metrics(t)["http.server.request.duration"].DataPoints[0]
	if got := keysOf(point.Attributes.ToSlice()); len(got) != 1 || got["http.route"] != "/v1/x" {
		t.Errorf("point attributes %v", got)
	}
}

func TestStartJobRecordsTheOutcomeAndCountsTheWait(t *testing.T) {
	h := newHarness(t)
	for _, c := range []struct {
		err     error
		outcome string
	}{
		{nil, "ok"}, {errors.New("password for ada"), "error"}, {context.DeadlineExceeded, "timeout"},
		{context.Canceled, "canceled"}, {ErrPanic, "panic"},
	} {
		_, end := h.t.StartJob(context.Background(), "premise_probe", tenantID, time.Now().Add(-90*time.Second))
		end(c.err)
		last := h.spans.GetSpans()[len(h.spans.GetSpans())-1]
		got := keysOf(last.Attributes)
		if got["ipso.job.outcome"] != c.outcome || got["ipso.job.kind"] != "premise_probe" || got["ipso.tenant.id"] != tenantID.String() {
			t.Errorf("%v: %v", c.err, got)
		}
		if (c.outcome == "ok") != (last.Status.Code != codes.Error) || last.Status.Description != "" {
			t.Errorf("%s: status %+v", c.outcome, last.Status)
		}
	}
	hist := h.metrics(t)["ipso.job.duration"]
	var total uint64
	for _, p := range hist.DataPoints {
		total += p.Count
		if p.Sum < 90 {
			t.Errorf("a job due 90 s ago was measured as %.1f s", p.Sum)
		}
		onlyAllowed(t, "a job point", keysOf(p.Attributes.ToSlice()))
	}
	if total != 5 {
		t.Errorf("recorded %d jobs, want 5", total)
	}
}

func TestStartJobIsAChildOfTheRequestThatQueuedIt(t *testing.T) {
	h := newHarness(t)
	var queued trace.SpanContext
	handler := h.t.Handler(uuid.Nil, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		queued = SpanContext(r.Context())
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/webhooks/github", nil))
	ctx, end := h.t.StartJob(Remote(context.Background(), queued), "check", tenantID, time.Time{})
	_ = ctx
	end(nil)
	jobSpan := h.spans.GetSpans()[1]
	if jobSpan.Parent.SpanID() != queued.SpanID() || jobSpan.SpanContext.TraceID() != queued.TraceID() {
		t.Error("the job is not a child of the delivery")
	}
	// A job that has no request starts a trace of its own.
	_, end = h.t.StartJob(Remote(context.Background(), trace.SpanContext{}), "waiver_notices", tenantID, time.Time{})
	end(nil)
	if h.spans.GetSpans()[2].Parent.IsValid() {
		t.Error("a job with no request has a parent")
	}
}

func TestStartMCPKeepsOnlyWhatTheServerDefines(t *testing.T) {
	h := newHarness(t)
	for _, c := range []struct{ method, tool, name, wantTool string }{
		{"tools/call", mcptools.ToolApplicable, "tools/call decisions.applicable", mcptools.ToolApplicable},
		{"tools/call", "ada-lovelace-secret-tool", "tools/call", ""},
		{"tools/list", mcptools.ToolGet, "tools/list", ""},
		{"ada/lovelace", "", "_OTHER", ""},
	} {
		_, end := h.t.StartMCP(context.Background(), tenantID, c.method, c.tool)
		end(false)
		last := h.spans.GetSpans()[len(h.spans.GetSpans())-1]
		if last.Name != c.name {
			t.Errorf("span %q, want %q", last.Name, c.name)
		}
		if got := keysOf(last.Attributes)["gen_ai.tool.name"]; got != c.wantTool {
			t.Errorf("%s %s: tool %q, want %q", c.method, c.tool, got, c.wantTool)
		}
	}
	_, end := h.t.StartMCP(context.Background(), tenantID, "tools/call", mcptools.ToolPropose)
	end(true)
	last := h.spans.GetSpans()[4]
	if keysOf(last.Attributes)["error.type"] != "rpc_error" || last.Status.Code != codes.Error {
		t.Errorf("a failed call: %v %+v", keysOf(last.Attributes), last.Status)
	}
	if n := len(h.metrics(t)["mcp.server.operation.duration"].DataPoints); n != 5 {
		t.Errorf("%d points, want 5", n)
	}
}

func TestLogHandlerAddsTheTraceToALineThatHasOne(t *testing.T) {
	var out strings.Builder
	log := slog.New(LogHandler(slog.NewJSONHandler(&out, nil))).With("tenant", "t")
	log.Info("plain")
	h := newHarness(t)
	ctx, end := h.t.StartJob(context.Background(), "k", uuid.Nil, time.Time{})
	log.InfoContext(ctx, "in a job")
	end(nil)
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if strings.Contains(lines[0], "trace_id") {
		t.Errorf("a line with no span has a trace: %s", lines[0])
	}
	id := h.spans.GetSpans()[0].SpanContext
	if !strings.Contains(lines[1], id.TraceID().String()) || !strings.Contains(lines[1], id.SpanID().String()) || !strings.Contains(lines[1], `"tenant":"t"`) {
		t.Errorf("line %s", lines[1])
	}
}

// TestExportsOverOTLPWithOnlyAllowedKeys runs the real exporters against a collector that records what it is
// sent, and decodes it as a collector would.
func TestExportsOverOTLPWithOnlyAllowedKeys(t *testing.T) {
	var mu sync.Mutex
	var traces []*collectortrace.ExportTraceServiceRequest
	var metrics []*collectormetrics.ExportMetricsServiceRequest
	var auth string
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		defer mu.Unlock()
		auth = r.Header.Get("Authorization")
		switch r.URL.Path {
		case "/v1/traces":
			req := &collectortrace.ExportTraceServiceRequest{}
			if err := proto.Unmarshal(body, req); err != nil {
				t.Errorf("traces: %v", err)
			}
			traces = append(traces, req)
		case "/v1/metrics":
			req := &collectormetrics.ExportMetricsServiceRequest{}
			if err := proto.Unmarshal(body, req); err != nil {
				t.Errorf("metrics: %v", err)
			}
			metrics = append(metrics, req)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/x-protobuf")
	}))
	defer collector.Close()
	t.Setenv(EnvEndpoint, collector.URL)
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "Authorization=Bearer collector-token")
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "deployment.environment.name=test")

	var logged strings.Builder
	tel, shutdown, err := Start(context.Background(), Options{Service: "ipso-api", Version: "v1.2.3", Logger: slog.New(slog.NewJSONHandler(&logged, nil))})
	if err != nil || tel == nil {
		t.Fatalf("start: %v, %v", tel, err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/decisions/{ref}", func(w http.ResponseWriter, r *http.Request) { SetRoute(r.Context(), r.Pattern) })
	req := httptest.NewRequest(http.MethodGet, "/v1/decisions/ada@example.org?author=ada", nil)
	req.Header.Set("Authorization", "Bearer user-token")
	tel.Handler(tenantID, mux).ServeHTTP(httptest.NewRecorder(), req)
	_, end := tel.StartJob(context.Background(), "premise_sweep", tenantID, time.Time{})
	end(nil)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(traces) == 0 || len(metrics) == 0 {
		t.Fatalf("the collector got %d trace and %d metric requests", len(traces), len(metrics))
	}
	if auth != "Bearer collector-token" {
		t.Errorf("the exporter did not send the configured header: %q", auth)
	}
	allowed := map[string]bool{}
	for _, k := range AllowedKeys {
		allowed[string(k)] = true
	}
	check := func(where string, kvs []*commonpb.KeyValue) {
		for _, kv := range kvs {
			if !allowed[kv.Key] {
				t.Errorf("%s carries %q", where, kv.Key)
			}
			if v := kv.GetValue().GetStringValue(); strings.Contains(v, "ada") || strings.Contains(v, "user-token") {
				t.Errorf("%s %s = %q", where, kv.Key, v)
			}
		}
	}
	var spanNames []string
	for _, req := range traces {
		for _, rs := range req.ResourceSpans {
			resource := map[string]string{}
			for _, kv := range rs.Resource.Attributes {
				resource[kv.Key] = kv.Value.GetStringValue()
			}
			if resource["service.name"] != "ipso-api" || resource["service.namespace"] != "ipso" || resource["service.version"] != "v1.2.3" || resource["deployment.environment.name"] != "test" {
				t.Errorf("resource %v", resource)
			}
			for _, k := range []string{"host.name", "process.command_args", "process.owner"} {
				if _, ok := resource[k]; ok {
					t.Errorf("the resource carries %s", k)
				}
			}
			for _, ss := range rs.ScopeSpans {
				for _, s := range ss.Spans {
					spanNames = append(spanNames, s.Name)
					check("span "+s.Name, s.Attributes)
					if len(s.Events) != 0 || len(s.Links) != 0 {
						t.Errorf("span %s has events or links", s.Name)
					}
				}
			}
		}
	}
	if strings.Join(spanNames, "|") != "GET /v1/decisions/{ref}|job premise_sweep" && strings.Join(spanNames, "|") != "job premise_sweep|GET /v1/decisions/{ref}" {
		t.Errorf("spans %v", spanNames)
	}
	var names []string
	for _, req := range metrics {
		for _, rm := range req.ResourceMetrics {
			for _, sm := range rm.ScopeMetrics {
				for _, m := range sm.Metrics {
					names = append(names, m.Name)
					for _, p := range m.GetHistogram().DataPoints {
						check("metric "+m.Name, p.Attributes)
						for _, e := range p.Exemplars {
							if len(e.FilteredAttributes) != 0 {
								t.Errorf("metric %s: an exemplar kept %v", m.Name, e.FilteredAttributes)
							}
						}
					}
				}
			}
		}
	}
	if len(names) == 0 {
		t.Error("no metric reached the collector")
	}
	if strings.Contains(logged.String(), "collector-token") {
		t.Error("the log holds the header")
	}
}

func TestAFailingCollectorIsLoggedOnceAndWithoutItsAddress(t *testing.T) {
	collector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusForbidden) }))
	defer collector.Close()
	t.Setenv(EnvEndpoint, collector.URL)
	var logged strings.Builder
	tel, shutdown, err := Start(context.Background(), Options{Service: "ipso-worker", Logger: slog.New(slog.NewJSONHandler(&logged, nil))})
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		_, end := tel.StartJob(context.Background(), "k", tenantID, time.Time{})
		end(nil)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = shutdown(ctx)
	if n := strings.Count(logged.String(), "telemetry export failed"); n != 1 {
		t.Errorf("logged %d times:\n%s", n, logged.String())
	}
	if strings.Contains(logged.String(), collector.URL) || strings.Contains(logged.String(), "127.0.0.1") {
		t.Errorf("the log names the collector:\n%s", logged.String())
	}
}
