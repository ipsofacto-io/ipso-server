package integrations

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/codes"

	"github.com/ipsofacto-io/ipso-server/internal/telemetry/telemetrytest"
)

// observedService is a service whose telemetry is kept, and the handler that Serve builds for it.
func observedService(t *testing.T, onMerged func(context.Context, MergedPullRequest) error) (*Service, http.Handler, *fakeGitHub, *telemetrytest.Recorder) {
	t.Helper()
	fake, app := newFakeGitHub(t)
	tel, rec := telemetrytest.New(t)
	s := newTestService(t, app, nil, onMerged)
	s.cfg.Telemetry = tel
	mux := http.NewServeMux()
	mux.Handle(webhookPath, s.Handler())
	return s, tel.Handler(uuid.Nil, mux), fake, rec
}

func deliverThrough(t *testing.T, handler http.Handler, event, id string, payload any) int {
	t.Helper()
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, webhookPath, strings.NewReader(string(body)))
	request.Header.Set("X-Hub-Signature-256", sign(body))
	request.Header.Set("X-GitHub-Event", event)
	request.Header.Set("X-GitHub-Delivery", id)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder.Code
}

func TestACheckJobIsObservedUnderItsDeliveryWithTheTenant(t *testing.T) {
	s, handler, fake, rec := observedService(t, nil)
	fake.changed = []changedFile{{Filename: "adr/one.md", Status: "added"}}
	fake.files[configPath] = "decisions:\n  - adr/**/*.md\n"
	fake.files["adr/one.md"] = validDecision

	if code := deliverThrough(t, handler, "pull_request", "d-1", prEvent("synchronize")); code != http.StatusAccepted {
		t.Fatalf("status %d", code)
	}
	drain(s)

	delivery := rec.Span(t, "POST /webhooks/github")
	job := rec.Span(t, "job check")
	if got := telemetrytest.Attrs(delivery.Attributes); got["ipso.tenant.id"] != testTenant.String() || got["http.response.status_code"] != "202" {
		t.Errorf("the delivery span: %v", got)
	}
	got := telemetrytest.Attrs(job.Attributes)
	if got["ipso.job.kind"] != "check" || got["ipso.job.outcome"] != "ok" || got["ipso.tenant.id"] != testTenant.String() {
		t.Errorf("the job span: %v", got)
	}
	if job.Parent.SpanID() != delivery.SpanContext.SpanID() {
		t.Error("the job is not a child of its delivery")
	}
	points := rec.Points(t, "ipso.job.duration")
	if len(points) != 1 || points[0].Count != 1 {
		t.Fatalf("job points %+v", points)
	}
	rec.CheckKeys(t)
}

func TestAMergedJobIsKindMergedAndAFailureKeepsItsTextOffTheSpan(t *testing.T) {
	s, handler, _, rec := observedService(t, func(context.Context, MergedPullRequest) error {
		return errors.New("the database said: password authentication failed for ada@example.org")
	})
	if code := deliverThrough(t, handler, "pull_request", "m-1", prEvent("closed")); code != http.StatusAccepted {
		t.Fatalf("status %d", code)
	}
	drain(s)

	job := rec.Span(t, "job merged_pr")
	if got := telemetrytest.Attrs(job.Attributes); got["ipso.job.outcome"] != "error" || got["ipso.job.kind"] != "merged_pr" {
		t.Errorf("the job span: %v", got)
	}
	if job.Status.Code != codes.Error || job.Status.Description != "" || len(job.Events) != 0 {
		t.Errorf("status %+v events %v", job.Status, job.Events)
	}
	rec.CheckKeys(t)
}

func TestAPanickingJobIsObservedAsOne(t *testing.T) {
	_, app := newFakeGitHub(t)
	tel, rec := telemetrytest.New(t)
	s := newTestService(t, app, nil, nil)
	s.cfg.Telemetry = tel
	s.work(context.Background(), job{delivery: "d-1", name: "boom", kind: "check", run: func(context.Context, uuid.UUID) error { panic("boom") }})
	if got := telemetrytest.Attrs(rec.Span(t, "job check").Attributes); got["ipso.job.outcome"] != "panic" {
		t.Errorf("the job span: %v", got)
	}
}

func TestARefusedDeliveryStillCarriesNoTenantAndNoPerson(t *testing.T) {
	_, handler, _, rec := observedService(t, nil)
	if code := deliverThrough(t, handler, "pull_request", "d-1", map[string]any{"action": "opened"}); code == http.StatusAccepted {
		t.Fatal("an empty payload was accepted")
	}
	span := rec.Span(t, "POST /webhooks/github")
	if _, has := telemetrytest.Attrs(span.Attributes)["ipso.tenant.id"]; has {
		t.Error("a delivery that was refused before the mapping has a tenant")
	}
	rec.CheckKeys(t)
}
