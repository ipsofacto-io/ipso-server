//go:build telemetry

// Package telemetrystack holds the tests of the telemetry stack (deploy/telemetry, ADR-0155). ci / telemetry
// starts the local stack with the overlay and runs them against its published ports: the api and the worker
// of the stack send their own telemetry, and the test sends the telemetry of the two roles the stack does not
// run, the webhooks service and the run task service, through the same package, so the four dashboards are
// run against what the four roles send.
package telemetrystack

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso/pkg/mcptools"

	"github.com/ipsofacto-io/ipso-server/internal/telemetry"
)

const (
	defaultGrafana    = "http://127.0.0.1:3000"
	defaultPrometheus = "http://127.0.0.1:9090"
	defaultTempo      = "http://127.0.0.1:3200"
	defaultOTLP       = "http://127.0.0.1:4318"
	// settleTime is how long a series may take to reach Prometheus after the last flush.
	settleTime = 90 * time.Second
)

// The test sends for this tenant. The stack's own tenant is the one of .env.example.
var emittedTenant = uuid.MustParse("00000000-0000-4000-8000-0000000000e2")

func setting(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

var (
	grafanaURL    = setting("IPSO_TELEMETRY_GRAFANA", defaultGrafana)
	prometheusURL = setting("IPSO_TELEMETRY_PROMETHEUS", defaultPrometheus)
	tempoURL      = setting("IPSO_TELEMETRY_TEMPO", defaultTempo)
	otlpURL       = setting("IPSO_TELEMETRY_OTLP", defaultOTLP)
	// stackRuns says that the api and the worker of the compose stack send their own telemetry, so the test
	// does not send a second api and a second worker.
	stackRuns = os.Getenv("IPSO_TELEMETRY_STACK") != ""
)

func get(t *testing.T, base, path string, query url.Values) []byte {
	t.Helper()
	target := base + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	if base == grafanaURL {
		req.SetBasicAuth("admin", "admin")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET %s: %d %s", target, resp.StatusCode, body)
	}
	return body
}

// sample is one series of an instant query.
type sample struct {
	Labels map[string]string
	Value  string
}

func query(t *testing.T, expr string) []sample {
	t.Helper()
	var out struct {
		Status string `json:"status"`
		Error  string `json:"error"`
		Data   struct {
			Result []struct {
				Metric map[string]string `json:"metric"`
				Value  [2]any            `json:"value"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(get(t, prometheusURL, "/api/v1/query", url.Values{"query": {expr}}), &out); err != nil {
		t.Fatal(err)
	}
	if out.Status != "success" {
		t.Fatalf("query %q: %s", expr, out.Error)
	}
	var samples []sample
	for _, r := range out.Data.Result {
		samples = append(samples, sample{r.Metric, fmt.Sprint(r.Value[1])})
	}
	return samples
}

func eventually(t *testing.T, what string, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(settleTime)
	for !check() {
		if time.Now().After(deadline) {
			t.Fatalf("%s did not happen within %s", what, settleTime)
		}
		time.Sleep(2 * time.Second)
	}
}

// role starts the telemetry of one role the way the command does, over OTLP to the stack.
func role(t *testing.T, service string) (*telemetry.Telemetry, func()) {
	t.Helper()
	t.Setenv(telemetry.EnvEndpoint, otlpURL)
	tel, shutdown, err := telemetry.Start(context.Background(), telemetry.Options{Service: service, Version: "e2e"})
	if err != nil || tel == nil {
		t.Fatalf("start %s: %v, %v", service, tel, err)
	}
	return tel, func() {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if err := shutdown(ctx); err != nil {
			t.Errorf("flush %s: %v", service, err)
		}
	}
}

func serve(handler http.Handler, method, target string, times int) {
	for range times {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(method, target, nil))
	}
}

// emit sends what each role would, shaped like the real thing: the routes are patterns, the tenant is the one
// the role serves, and the jobs have the kinds and the outcomes of the code that runs them.
func emit(t *testing.T) (flush func()) {
	t.Helper()
	var flushes []func()
	add := func(service string, send func(tel *telemetry.Telemetry)) {
		tel, flush := role(t, service)
		send(tel)
		flushes = append(flushes, flush)
	}
	if !stackRuns {
		add("ipso-api", func(tel *telemetry.Telemetry) {
			mux := http.NewServeMux()
			mux.HandleFunc("GET /v1/decisions/{ref}", func(w http.ResponseWriter, r *http.Request) {
				telemetry.SetRoute(r.Context(), r.Pattern)
				// The probe is a request with a bad token, which the guard of the api answers with a 401.
				if strings.Contains(r.URL.Path, "ipso-e2e") {
					w.WriteHeader(http.StatusUnauthorized)
				}
			})
			mux.HandleFunc("POST /v1/waivers", func(w http.ResponseWriter, r *http.Request) {
				telemetry.SetRoute(r.Context(), r.Pattern)
				w.WriteHeader(http.StatusInternalServerError)
			})
			handler := tel.Handler(emittedTenant, mux)
			serve(handler, http.MethodGet, "/v1/decisions/adr-1", 20)
			serve(handler, http.MethodPost, "/v1/waivers", 3)
			for range 12 {
				req := httptest.NewRequest(http.MethodGet, probePath+"?"+probeQuery, nil)
				req.Header.Set("User-Agent", probeAgent)
				req.Header.Set("Authorization", "Bearer "+probeToken)
				req.RemoteAddr = "203.0.113.9:4000"
				handler.ServeHTTP(httptest.NewRecorder(), req)
			}
			for range 5 {
				_, end := tel.StartMCP(context.Background(), emittedTenant, "tools/call", mcptools.ToolApplicable)
				end(false)
			}
		})
		add("ipso-worker", func(tel *telemetry.Telemetry) {
			for _, kind := range []string{"waiver_notices", "premise_sweep", "premise_probe"} {
				_, end := tel.StartJob(context.Background(), kind, emittedTenant, time.Now().Add(-3*time.Second))
				end(nil)
			}
			_, end := tel.StartJob(context.Background(), "premise_probe", emittedTenant, time.Now().Add(-90*time.Second))
			end(context.DeadlineExceeded)
		})
	}
	add("ipso-webhooks", func(tel *telemetry.Telemetry) {
		mux := http.NewServeMux()
		mux.HandleFunc("POST /webhooks/github", func(w http.ResponseWriter, r *http.Request) {
			telemetry.SetTenant(r.Context(), emittedTenant)
			w.WriteHeader(http.StatusAccepted)
		})
		serve(tel.Handler(uuid.Nil, mux), http.MethodPost, "/webhooks/github", 10)
		for _, c := range []struct {
			kind string
			due  time.Duration
			err  error
		}{{"check", 4 * time.Second, nil}, {"check", 70 * time.Second, nil}, {"check", time.Second, context.DeadlineExceeded}, {"merged_pr", 20 * time.Second, nil}} {
			_, end := tel.StartJob(context.Background(), c.kind, emittedTenant, time.Now().Add(-c.due))
			end(c.err)
		}
	})
	add("ipso-runtasks", func(tel *telemetry.Telemetry) {
		mux := http.NewServeMux()
		mux.HandleFunc("POST /runtasks/hcp-terraform", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) })
		serve(tel.Handler(uuid.Nil, mux), http.MethodPost, "/runtasks/hcp-terraform", 6)
		for _, err := range []error{nil, nil, telemetry.ErrPanic} {
			_, end := tel.StartJob(context.Background(), "runtask", uuid.Nil, time.Now().Add(-5*time.Second))
			end(err)
		}
	})
	return func() {
		for _, f := range flushes {
			f()
		}
	}
}

// What a person could put in a request. None of it may reach a series, a trace or an exemplar.
const (
	probePath  = "/v1/decisions/ipso-e2e-person@example.org"
	probeQuery = "author=ipso-e2e-author&token=ipso-e2e-probe-two"
	probeAgent = "ipso-e2e-agent/1.0"
	probeToken = "ipso-e2e-probe-one"
)

var probes = []string{"ipso-e2e", "example.org", "@"}

var (
	tenantPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	// addressPattern is an IPv4 address, which the runner and the containers both have.
	addressPattern = regexp.MustCompile(`\b\d{1,3}(\.\d{1,3}){3}\b`)
	// promLabels are the labels Prometheus adds to a series from the resource of the sender.
	promLabels = map[string]bool{
		"__name__": true, "job": true, "instance": true, "le": true,
		"service_name": true, "service_namespace": true, "service_version": true, "service_instance_id": true,
	}
	// resourceKeys are the attributes of the resource of a span: the identity of the service and the SDK.
	resourceKeys = map[string]bool{
		"service.name": true, "service.namespace": true, "service.version": true,
		"telemetry.sdk.language": true, "telemetry.sdk.name": true, "telemetry.sdk.version": true,
	}
)

func allowedLabels() map[string]bool {
	allowed := map[string]bool{}
	for k := range promLabels {
		allowed[k] = true
	}
	for _, k := range telemetry.AllowedKeys {
		allowed[strings.ReplaceAll(string(k), ".", "_")] = true
	}
	return allowed
}

func noProbe(t *testing.T, where, value string) {
	t.Helper()
	lower := strings.ToLower(value)
	for _, probe := range probes {
		if strings.Contains(lower, probe) {
			t.Errorf("%s holds %q: %q", where, probe, value)
		}
	}
	if addressPattern.MatchString(value) {
		t.Errorf("%s holds an address: %q", where, value)
	}
}

// stackTraffic sends the requests that the api of the stack answers with a 401. They carry what must not be
// recorded, and the route they ask for, which must.
func stackTraffic(t *testing.T) {
	t.Helper()
	api := setting("IPSO_TELEMETRY_API", "http://127.0.0.1:8080")
	for range 12 {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, api+probePath+"?"+probeQuery, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("User-Agent", probeAgent)
		req.Header.Set("Authorization", "Bearer "+probeToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("the api answered %d to a request with a bad token, want 401", resp.StatusCode)
		}
	}
}

// sampleOf is what a person reviews for personal data: every distinct series label set and trace attribute.
type sampleOf struct {
	Series    []map[string]string `json:"series"`
	Exemplars []map[string]string `json:"exemplars"`
	Spans     []spanSample        `json:"spans"`
}

type spanSample struct {
	Name       string            `json:"name"`
	Attributes map[string]string `json:"attributes"`
	Resource   map[string]string `json:"resource"`
	Events     int               `json:"events"`
	Status     string            `json:"status"`
}

func TestTheStackReceivesTheTelemetryOfEveryRole(t *testing.T) {
	if stackRuns {
		stackTraffic(t)
	}
	flush := emit(t)
	flush()

	wantTenant := emittedTenant.String()
	if stackRuns {
		wantTenant = setting("IPSO_TENANT_ID", "")
		if wantTenant == "" {
			t.Fatal("IPSO_TELEMETRY_STACK is set and IPSO_TENANT_ID is not")
		}
	}

	// Every role has sent the metric it has: the three roles that serve requests, and the three that run jobs.
	for service, metrics := range map[string][]string{
		"ipso-api":      {"http_server_request_duration_seconds_count"},
		"ipso-worker":   {"ipso_job_duration_seconds_count"},
		"ipso-webhooks": {"http_server_request_duration_seconds_count", "ipso_job_duration_seconds_count"},
		"ipso-runtasks": {"http_server_request_duration_seconds_count", "ipso_job_duration_seconds_count"},
	} {
		for _, metric := range metrics {
			eventually(t, service+" sending "+metric, func() bool {
				return len(query(t, fmt.Sprintf(`%s{job="ipso/%s"}`, metric, service))) > 0
			})
		}
	}

	var review sampleOf
	allowed := allowedLabels()
	t.Run("series carry only the allowed labels and the tenant", func(t *testing.T) {
		seen := map[string]bool{}
		for _, series := range query(t, `{job=~"ipso/.*", __name__!="target_info"}`) {
			name := series.Labels["__name__"]
			base := strings.TrimSuffix(strings.TrimSuffix(strings.TrimSuffix(name, "_bucket"), "_sum"), "_count")
			switch base {
			case "http_server_request_duration_seconds", "ipso_job_duration_seconds", "mcp_server_operation_duration_seconds":
			default:
				t.Errorf("a metric outside the three histograms was sent: %s", name)
			}
			for k, v := range series.Labels {
				if !allowed[k] {
					t.Errorf("%s carries the label %q", name, k)
				}
				noProbe(t, name+" label "+k, v)
			}
			service := series.Labels["service_name"]
			tenant, has := series.Labels["ipso_tenant_id"]
			switch {
			case service == "ipso-runtasks":
				if has {
					t.Errorf("%s of ipso-runtasks has a tenant, but that role has none", name)
				}
			case has:
				if !tenantPattern.MatchString(tenant) {
					t.Errorf("%s carries a tenant label that is not a UUID: %q", name, tenant)
				}
			case strings.HasSuffix(name, "_count"):
				// The tenant is on a point whenever the role has one. A webhooks delivery refused before the
				// mapping has none, and no such delivery is sent here.
				t.Errorf("%s of %s has no tenant", name, service)
			}
			key := fmt.Sprint(series.Labels)
			if !seen[key] && !strings.HasSuffix(name, "_bucket") {
				seen[key] = true
				review.Series = append(review.Series, series.Labels)
			}
		}
		if len(review.Series) == 0 {
			t.Fatal("no series to review")
		}
		// The tenant of the stack's own api and worker is the tenant they serve.
		if stackRuns {
			for _, service := range []string{"ipso-api", "ipso-worker"} {
				got := query(t, fmt.Sprintf(`count by (ipso_tenant_id) ({job="ipso/%s", __name__=~".*_count"})`, service))
				if len(got) != 1 || got[0].Labels["ipso_tenant_id"] != wantTenant {
					t.Errorf("%s: tenants %v, want only %s", service, got, wantTenant)
				}
			}
		}
	})

	t.Run("the resource says who sent it and nothing about the host", func(t *testing.T) {
		infos := query(t, `target_info{job=~"ipso/.*"}`)
		if len(infos) == 0 {
			t.Fatal("no target_info")
		}
		for _, info := range infos {
			for k, v := range info.Labels {
				if !allowed[k] && !strings.HasPrefix(k, "telemetry_sdk_") {
					t.Errorf("target_info carries the label %q", k)
				}
				noProbe(t, "target_info label "+k, v)
			}
		}
	})

	// The exemplars of every role name traces. A few traces of each metric of each role are read back from Tempo.
	var traceIDs []string
	t.Run("an exemplar names a trace", func(t *testing.T) {
		eventually(t, "an exemplar of each metric", func() bool {
			traceIDs, review.Exemplars = nil, nil
			seen, taken := map[string]bool{}, map[string]int{}
			for _, metric := range []string{"http_server_request_duration_seconds", "ipso_job_duration_seconds", "mcp_server_operation_duration_seconds"} {
				var out struct {
					Data []struct {
						SeriesLabels map[string]string `json:"seriesLabels"`
						Exemplars    []struct {
							Labels map[string]string `json:"labels"`
						} `json:"exemplars"`
					} `json:"data"`
				}
				end := time.Now()
				body := get(t, prometheusURL, "/api/v1/query_exemplars", url.Values{
					"query": {metric + `_bucket{job=~"ipso/.*"}`},
					"start": {fmt.Sprint(end.Add(-time.Hour).Unix())}, "end": {fmt.Sprint(end.Unix())},
				})
				if err := json.Unmarshal(body, &out); err != nil {
					t.Fatal(err)
				}
				for _, series := range out.Data {
					for _, e := range series.Exemplars {
						for k, v := range e.Labels {
							if k != "trace_id" && k != "span_id" {
								t.Errorf("an exemplar carries the label %q", k)
							}
							noProbe(t, "exemplar label "+k, v)
						}
						// Two traces of each metric of each role are read back.
						kind := metric + series.SeriesLabels["job"]
						if id := e.Labels["trace_id"]; id != "" && !seen[id] && taken[kind] < 2 {
							seen[id] = true
							taken[kind]++
							traceIDs = append(traceIDs, id)
						}
						review.Exemplars = append(review.Exemplars, e.Labels)
					}
				}
			}
			// The api and the webhooks service both have exemplars once they have served a request in a trace.
			return len(traceIDs) > 0
		})
	})

	t.Run("a trace carries only the allowed attributes and the tenant", func(t *testing.T) {
		allowedSpan := map[string]bool{}
		for _, k := range telemetry.AllowedKeys {
			allowedSpan[string(k)] = true
		}
		spans := 0
		for _, id := range traceIDs {
			// Tempo answers with the batches of the trace, each with the resource that sent it.
			var trace struct {
				Batches []struct {
					Resource struct {
						Attributes []attr `json:"attributes"`
					} `json:"resource"`
					ScopeSpans []struct {
						Spans []struct {
							Name       string `json:"name"`
							Attributes []attr `json:"attributes"`
							Events     []any  `json:"events"`
							Links      []any  `json:"links"`
							Status     struct {
								Code    string `json:"code"`
								Message string `json:"message"`
							} `json:"status"`
						} `json:"spans"`
					} `json:"scopeSpans"`
				} `json:"batches"`
			}
			eventually(t, "the trace "+id+" in Tempo", func() bool {
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, tempoURL+"/api/traces/"+id, nil)
				if err != nil {
					t.Fatal(err)
				}
				resp, err := http.DefaultClient.Do(req)
				if err != nil {
					return false
				}
				defer func() { _ = resp.Body.Close() }()
				body, _ := io.ReadAll(resp.Body)
				return resp.StatusCode == http.StatusOK && json.Unmarshal(body, &trace) == nil && len(trace.Batches) > 0
			})
			for _, batch := range trace.Batches {
				resource := map[string]string{}
				for _, a := range batch.Resource.Attributes {
					if !resourceKeys[a.Key] {
						t.Errorf("the resource carries %q", a.Key)
					}
					noProbe(t, "resource "+a.Key, a.text())
					resource[a.Key] = a.text()
				}
				for _, scope := range batch.ScopeSpans {
					for _, span := range scope.Spans {
						spans++
						noProbe(t, "span name", span.Name)
						sample := spanSample{Name: span.Name, Attributes: map[string]string{}, Resource: resource, Events: len(span.Events), Status: span.Status.Code}
						for _, a := range span.Attributes {
							if !allowedSpan[a.Key] {
								t.Errorf("span %q carries %q", span.Name, a.Key)
							}
							noProbe(t, "span "+a.Key, a.text())
							sample.Attributes[a.Key] = a.text()
						}
						// Every role but the run task service has a tenant on its spans.
						if tenant := sample.Attributes["ipso.tenant.id"]; resource["service.name"] == "ipso-runtasks" {
							if tenant != "" {
								t.Errorf("span %q of ipso-runtasks has a tenant", span.Name)
							}
						} else if !tenantPattern.MatchString(tenant) {
							t.Errorf("span %q of %s has no tenant: %v", span.Name, resource["service.name"], sample.Attributes)
						}
						if len(span.Events) != 0 || len(span.Links) != 0 || span.Status.Message != "" {
							t.Errorf("span %q has events, links or a status message", span.Name)
						}
						review.Spans = append(review.Spans, sample)
					}
				}
			}
		}
		if spans == 0 {
			t.Fatal("no span was read back")
		}
	})

	t.Run("the dashboards are provisioned and every query of them runs", func(t *testing.T) {
		var list []struct {
			UID string `json:"uid"`
		}
		if err := json.Unmarshal(get(t, grafanaURL, "/api/search", url.Values{"type": {"dash-db"}, "tag": {"ipso"}}), &list); err != nil {
			t.Fatal(err)
		}
		var uids []string
		for _, d := range list {
			uids = append(uids, d.UID)
		}
		sort.Strings(uids)
		if want := []string{"ipso-api", "ipso-runtasks", "ipso-webhooks", "ipso-worker"}; strings.Join(uids, ",") != strings.Join(want, ",") {
			t.Fatalf("dashboards %v, want %v", uids, want)
		}
		queries := 0
		for _, uid := range uids {
			var board struct {
				Dashboard struct {
					Panels []panel `json:"panels"`
				} `json:"dashboard"`
			}
			if err := json.Unmarshal(get(t, grafanaURL, "/api/dashboards/uid/"+uid, nil), &board); err != nil {
				t.Fatal(err)
			}
			for _, p := range board.Dashboard.Panels {
				for _, target := range p.Targets {
					expr := strings.NewReplacer("$tenant", ".*", "$__rate_interval", "1m", "$__range", "1h").Replace(target.Expr)
					if strings.Contains(expr, "$") {
						t.Errorf("%s: %q has a variable the test does not fill", uid, p.Title)
						continue
					}
					query(t, expr)
					queries++
				}
			}
		}
		if queries < 40 {
			t.Errorf("ran %d queries, want every query of four dashboards", queries)
		}
	})

	if path := os.Getenv("IPSO_TELEMETRY_SAMPLE"); path != "" {
		out, err := json.MarshalIndent(review, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(out, '\n'), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

type attr struct {
	Key   string `json:"key"`
	Value struct {
		String string `json:"stringValue"`
		Int    string `json:"intValue"`
		Bool   *bool  `json:"boolValue"`
	} `json:"value"`
}

func (a attr) text() string {
	switch {
	case a.Value.String != "":
		return a.Value.String
	case a.Value.Int != "":
		return a.Value.Int
	case a.Value.Bool != nil:
		return fmt.Sprint(*a.Value.Bool)
	}
	return ""
}

type panel struct {
	Title   string `json:"title"`
	Targets []struct {
		Expr string `json:"expr"`
	} `json:"targets"`
}
