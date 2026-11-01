package integrations

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ipsofacto-io/ipso/pkg/plancheck"
)

const (
	runTaskKey   = "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk"
	testToken    = "tttttttttttttttttttttttt"
	planMarker   = "VALUE-FROM-THE-PLAN"
	messageMark  = "MESSAGE-QUOTING-A-VALUE"
	testPlanBody = `{"format_version":"1.2","resource_changes":[],"marker":"` + planMarker + `"}`
)

// fakeHCP is the API side of HCP Terraform and the download host, over TLS.
type fakeHCP struct {
	t        *testing.T
	api      *httptest.Server
	download *httptest.Server
	mu       sync.Mutex
	// planStatus answers the plan URL in order. 307 redirects to redirectTo. The last one repeats.
	planStatus []int
	redirectTo string
	planAuth   []string
	dlAuth     []string
	dlHits     int
	callbacks  []capturedCallback
	// callbackStatus answers the callback in order. The last one repeats.
	callbackStatus []int
	// planHang keeps the plan URL from answering until the test ends.
	planHang chan struct{}
}

type capturedCallback struct {
	auth        string
	contentType string
	method      string
	path        string
	body        string
}

func newFakeHCP(t *testing.T) *fakeHCP {
	t.Helper()
	f := &fakeHCP{t: t, planStatus: []int{http.StatusTemporaryRedirect}, callbackStatus: []int{http.StatusOK}}
	f.download = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.dlHits++
		f.dlAuth = append(f.dlAuth, r.Header.Get("Authorization"))
		_, _ = io.WriteString(w, testPlanBody)
	}))
	t.Cleanup(f.download.Close)
	f.api = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && f.planHang != nil {
			select {
			case <-f.planHang:
			case <-r.Context().Done():
			}
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Method == http.MethodGet {
			f.planAuth = append(f.planAuth, r.Header.Get("Authorization"))
			status := f.planStatus[0]
			if len(f.planStatus) > 1 {
				f.planStatus = f.planStatus[1:]
			}
			switch status {
			case http.StatusTemporaryRedirect:
				target := f.redirectTo
				if target == "" {
					target = f.download.URL + "/signed-download?token=DOWNLOAD-MARKER"
				}
				w.Header().Set("Location", target)
				w.WriteHeader(status)
			case http.StatusOK:
				_, _ = io.WriteString(w, testPlanBody)
			default:
				w.WriteHeader(status)
			}
			return
		}
		body, _ := io.ReadAll(r.Body)
		f.callbacks = append(f.callbacks, capturedCallback{
			auth:        r.Header.Get("Authorization"),
			contentType: r.Header.Get("Content-Type"),
			method:      r.Method,
			path:        r.URL.Path,
			body:        string(body),
		})
		status := f.callbackStatus[0]
		if len(f.callbackStatus) > 1 {
			f.callbackStatus = f.callbackStatus[1:]
		}
		w.WriteHeader(status)
	}))
	t.Cleanup(f.api.Close)
	return f
}

func (f *fakeHCP) host() string { return strings.TrimPrefix(f.api.URL, "https://") }

func (f *fakeHCP) downloadHost() string { return strings.TrimPrefix(f.download.URL, "https://") }

func (f *fakeHCP) callbackCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.callbacks)
}

func (f *fakeHCP) lastCallback() capturedCallback {
	f.t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.callbacks) == 0 {
		f.t.Fatal("no callback")
	}
	return f.callbacks[len(f.callbacks)-1]
}

// fakeBundle stands in for a verified bundle. It records what it read.
type fakeBundle struct {
	mu     sync.Mutex
	report plancheck.Report
	err    error
	read   string
	env    string
	panics bool
}

func (b *fakeBundle) Evaluate(r io.Reader, env string, _ time.Time) (plancheck.Report, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.panics {
		panic("boom " + planMarker)
	}
	raw, err := io.ReadAll(r)
	if err != nil {
		return plancheck.Report{}, err
	}
	b.read, b.env = string(raw), env
	return b.report, b.err
}

type runTaskHarness struct {
	service *RunTaskService
	hcp     *fakeHCP
	bundle  *fakeBundle
	logs    *syncBuffer
	handler http.Handler
}

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

func newRunTaskHarness(t *testing.T, report plancheck.Report) *runTaskHarness {
	t.Helper()
	hcp := newFakeHCP(t)
	logs := &syncBuffer{}
	bundle := &fakeBundle{report: report}
	service := NewRunTaskService(RunTaskConfig{
		HMACKey:   []byte(runTaskKey),
		Bundle:    bundle,
		Env:       "prod",
		APIHost:   hcp.host(),
		PlanHosts: []string{hcp.downloadHost()},
		Logger:    slog.New(slog.NewJSONHandler(logs, nil)),
	})
	// The fake's two servers share one test CA.
	service.client.Transport = hcp.api.Client().Transport
	service.wait = time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		service.Run(ctx)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return &runTaskHarness{service: service, hcp: hcp, bundle: bundle, logs: logs, handler: service.Handler()}
}

func (h *runTaskHarness) payload(mutate func(map[string]any)) []byte {
	host := h.hcp.host()
	values := map[string]any{
		"payload_version":               1,
		"stage":                         "post_plan",
		"access_token":                  testToken,
		"capabilities":                  map[string]any{"outcomes": true},
		"plan_json_api_url":             "https://" + host + "/api/v2/plans/plan-abc123/json-output",
		"task_result_callback_url":      "https://" + host + "/api/v2/task-results/5ea8d46c-2ceb/callback",
		"task_result_enforcement_level": "mandatory",
		"task_result_id":                "taskrs-abc123",
		"run_id":                        "run-abc123",
		"workspace_name":                "network",
	}
	if mutate != nil {
		mutate(values)
	}
	raw, err := json.Marshal(values)
	if err != nil {
		panic(err)
	}
	return raw
}

func signTask(body []byte) string {
	mac := hmac.New(sha512.New, []byte(runTaskKey))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

func (h *runTaskHarness) post(body []byte, signature string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, runTaskPath, bytes.NewReader(body))
	if signature != "" {
		request.Header.Set(runTaskHeader, signature)
	}
	recorder := httptest.NewRecorder()
	h.handler.ServeHTTP(recorder, request)
	return recorder
}

func (h *runTaskHarness) postSigned(t *testing.T, mutate func(map[string]any)) {
	t.Helper()
	body := h.payload(mutate)
	if got := h.post(body, signTask(body)); got.Code != http.StatusOK {
		t.Fatalf("status %d", got.Code)
	}
}

func (h *runTaskHarness) waitForCallback(t *testing.T, count int) capturedCallback {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if h.hcp.callbackCount() >= count {
			return h.hcp.lastCallback()
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("no callback %d within the deadline\n%s", count, h.logs.String())
	return capturedCallback{}
}

func resultFields(t *testing.T, body string) (status, message string, outcomes []map[string]any) {
	t.Helper()
	var document struct {
		Data struct {
			Type       string `json:"type"`
			Attributes struct {
				Status  string `json:"status"`
				Message string `json:"message"`
			} `json:"attributes"`
			Relationships struct {
				Outcomes struct {
					Data []map[string]any `json:"data"`
				} `json:"outcomes"`
			} `json:"relationships"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &document); err != nil {
		t.Fatal(err)
	}
	if document.Data.Type != "task-results" {
		t.Fatalf("type %q", document.Data.Type)
	}
	return document.Data.Attributes.Status, document.Data.Attributes.Message, document.Data.Relationships.Outcomes.Data
}

func failingReport(mode string) plancheck.Report {
	return plancheck.Report{
		PlanSHA256: strings.Repeat("a", 64),
		Blocked:    mode == "block",
		Verdicts: []plancheck.Verdict{{
			DecisionID: "01M6D5D0T0KW7M1P6R2SY8X9ZE",
			Slug:       "encrypted-volumes",
			Mode:       mode,
			Result:     plancheck.ResultFail,
			Count:      1,
			Violations: []plancheck.Violation{{Address: "aws_ebs_volume.data", Message: messageMark + " " + planMarker}},
		}},
	}
}

func assertNoLeak(t *testing.T, where, text string) {
	t.Helper()
	for _, secret := range []string{testToken, planMarker, messageMark, "DOWNLOAD-MARKER", "aws_ebs_volume"} {
		if strings.Contains(text, secret) {
			t.Fatalf("%s holds %q:\n%s", where, secret, text)
		}
	}
}

func TestRunTaskRefusesAnUnauthenticatedRequest(t *testing.T) {
	h := newRunTaskHarness(t, plancheck.Report{})
	body := h.payload(nil)
	wrong := hmac.New(sha512.New, []byte("wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwww"))
	wrong.Write(body)
	for name, signature := range map[string]string{
		"missing":   "",
		"wrong key": hex.EncodeToString(wrong.Sum(nil)),
		"not hex":   "zz",
		"truncated": signTask(body)[:64],
		"sha256":    "sha256=" + signTask(body),
	} {
		t.Run(name, func(t *testing.T) {
			if got := h.post(body, signature); got.Code != http.StatusUnauthorized {
				t.Fatalf("status %d", got.Code)
			}
		})
	}
	tampered := bytes.Replace(body, []byte("post_plan"), []byte("pre_apply"), 1)
	if got := h.post(tampered, signTask(body)); got.Code != http.StatusUnauthorized {
		t.Fatalf("tampered status %d", got.Code)
	}
	if h.hcp.callbackCount() != 0 || len(h.hcp.planAuth) != 0 {
		t.Fatal("a refused request reached HCP")
	}
}

func TestRunTaskRefusesWithAnEmptyKey(t *testing.T) {
	body := []byte(`{}`)
	mac := hmac.New(sha512.New, nil)
	mac.Write(body)
	if validTaskSignature(nil, body, hex.EncodeToString(mac.Sum(nil))) {
		t.Fatal("an empty key verified")
	}
}

func TestRunTaskRefusesAnOversizedBody(t *testing.T) {
	h := newRunTaskHarness(t, plancheck.Report{})
	body := bytes.Repeat([]byte("x"), maxRunTaskBody+1)
	if got := h.post(body, signTask(body)); got.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d", got.Code)
	}
}

func TestRunTaskBlocksOnABlockingViolation(t *testing.T) {
	h := newRunTaskHarness(t, failingReport("block"))
	h.postSigned(t, nil)
	callback := h.waitForCallback(t, 1)
	if callback.method != http.MethodPatch || callback.auth != "Bearer "+testToken || callback.contentType != jsonAPI {
		t.Fatalf("callback %+v", callback)
	}
	if callback.path != "/api/v2/task-results/5ea8d46c-2ceb/callback" {
		t.Fatalf("path %q", callback.path)
	}
	status, message, outcomes := resultFields(t, callback.body)
	if status != statusFailed || !strings.Contains(message, "1 blocking") {
		t.Fatalf("status %q message %q", status, message)
	}
	if len(outcomes) != 1 || !strings.Contains(callback.body, "aws_ebs_volume.data") || !strings.Contains(callback.body, `"label":"Failed"`) {
		t.Fatalf("body %s", callback.body)
	}
	if strings.Contains(callback.body, messageMark) || strings.Contains(callback.body, planMarker) {
		t.Fatalf("the result quotes the plan: %s", callback.body)
	}
	if h.bundle.read != testPlanBody || h.bundle.env != "prod" {
		t.Fatalf("read %q env %q", h.bundle.read, h.bundle.env)
	}
}

func TestRunTaskWarnsWithoutBlocking(t *testing.T) {
	for mode, label := range map[string]string{"warn": "Warning", "advise": "Advisory"} {
		t.Run(mode, func(t *testing.T) {
			h := newRunTaskHarness(t, failingReport(mode))
			h.postSigned(t, nil)
			callback := h.waitForCallback(t, 1)
			status, message, outcomes := resultFields(t, callback.body)
			if status != statusPassed || !strings.Contains(message, "1 warnings") || len(outcomes) != 1 {
				t.Fatalf("status %q message %q outcomes %v", status, message, outcomes)
			}
			if !strings.Contains(callback.body, `"label":"`+label+`"`) {
				t.Fatalf("body %s", callback.body)
			}
		})
	}
}

func TestRunTaskPassAndWaiver(t *testing.T) {
	h := newRunTaskHarness(t, plancheck.Report{Verdicts: []plancheck.Verdict{
		{DecisionID: "a", Slug: "a", Mode: "block", Result: plancheck.ResultPass},
		{DecisionID: "b", Slug: "b", Mode: "block", Result: plancheck.ResultWaived, Count: 2},
	}})
	h.postSigned(t, nil)
	callback := h.waitForCallback(t, 1)
	status, message, outcomes := resultFields(t, callback.body)
	if status != statusPassed || !strings.Contains(message, "1 waived, 1 passed") || len(outcomes) != 1 {
		t.Fatalf("status %q message %q outcomes %v", status, message, outcomes)
	}
}

func TestRunTaskNoChecksSelected(t *testing.T) {
	h := newRunTaskHarness(t, plancheck.Report{})
	h.postSigned(t, nil)
	callback := h.waitForCallback(t, 1)
	status, message, outcomes := resultFields(t, callback.body)
	if status != statusPassed || message != "ipso: no checks selected." || outcomes != nil {
		t.Fatalf("status %q message %q outcomes %v", status, message, outcomes)
	}
}

func TestRunTaskEvaluationErrorBlocks(t *testing.T) {
	h := newRunTaskHarness(t, plancheck.Report{Blocked: true, Verdicts: []plancheck.Verdict{
		{DecisionID: "a", Slug: "a", Mode: "warn", Result: plancheck.ResultError},
	}})
	h.postSigned(t, nil)
	status, message, _ := resultFields(t, h.waitForCallback(t, 1).body)
	if status != statusFailed || !strings.Contains(message, "1 could not be evaluated") {
		t.Fatalf("status %q message %q", status, message)
	}
}

func TestRunTaskOmitsOutcomesWhenNotAccepted(t *testing.T) {
	h := newRunTaskHarness(t, failingReport("block"))
	h.postSigned(t, func(values map[string]any) { values["capabilities"] = map[string]any{"outcomes": false} })
	body := h.waitForCallback(t, 1).body
	if strings.Contains(body, "relationships") || strings.Contains(body, "aws_ebs_volume") {
		t.Fatalf("body %s", body)
	}
}

func TestRunTaskFailsClosed(t *testing.T) {
	t.Run("the bundle refuses the plan", func(t *testing.T) {
		h := newRunTaskHarness(t, plancheck.Report{})
		h.bundle.err = errors.New("invalid plan near " + planMarker)
		h.postSigned(t, nil)
		body := h.waitForCallback(t, 1).body
		status, message, _ := resultFields(t, body)
		if status != statusFailed || strings.Contains(message, planMarker) {
			t.Fatalf("status %q message %q", status, message)
		}
		time.Sleep(20 * time.Millisecond)
		assertNoLeak(t, "the log", h.logs.String())
	})
	t.Run("the evaluation panics", func(t *testing.T) {
		h := newRunTaskHarness(t, plancheck.Report{})
		h.bundle.panics = true
		h.postSigned(t, nil)
		status, _, _ := resultFields(t, h.waitForCallback(t, 1).body)
		if status != statusFailed {
			t.Fatalf("status %q", status)
		}
		time.Sleep(20 * time.Millisecond)
		assertNoLeak(t, "the log", h.logs.String())
	})
	t.Run("the plan API refuses the token", func(t *testing.T) {
		h := newRunTaskHarness(t, plancheck.Report{})
		h.hcp.planStatus = []int{http.StatusUnauthorized}
		h.postSigned(t, nil)
		status, _, _ := resultFields(t, h.waitForCallback(t, 1).body)
		if status != statusFailed {
			t.Fatalf("status %q", status)
		}
	})
	t.Run("the plan never becomes ready", func(t *testing.T) {
		h := newRunTaskHarness(t, plancheck.Report{})
		h.hcp.planStatus = []int{http.StatusNoContent}
		h.postSigned(t, nil)
		status, _, _ := resultFields(t, h.waitForCallback(t, 1).body)
		if status != statusFailed || len(h.hcp.planAuth) != 6 {
			t.Fatalf("status %q tries %d", status, len(h.hcp.planAuth))
		}
	})
}

func TestRunTaskReportsWhenThePlanNeverArrives(t *testing.T) {
	h := newRunTaskHarness(t, plancheck.Report{})
	h.hcp.planHang = make(chan struct{})
	t.Cleanup(func() { close(h.hcp.planHang) })
	h.service.evaluateLimit = 50 * time.Millisecond
	h.postSigned(t, nil)
	status, _, _ := resultFields(t, h.waitForCallback(t, 1).body)
	if status != statusFailed {
		t.Fatalf("status %q", status)
	}
}

func TestRunTaskStagesWithNoPlanToJudge(t *testing.T) {
	for _, stage := range []string{stagePrePlan, stagePostApply, "test"} {
		t.Run(stage, func(t *testing.T) {
			h := newRunTaskHarness(t, plancheck.Report{})
			h.postSigned(t, func(values map[string]any) { values["stage"] = stage })
			status, message, _ := resultFields(t, h.waitForCallback(t, 1).body)
			if status != statusFailed || !strings.Contains(message, "post-plan") || len(h.hcp.planAuth) != 0 {
				t.Fatalf("status %q message %q fetches %d", status, message, len(h.hcp.planAuth))
			}
		})
	}
	t.Run(stagePreApply, func(t *testing.T) {
		h := newRunTaskHarness(t, plancheck.Report{})
		h.postSigned(t, func(values map[string]any) { values["stage"] = stagePreApply })
		status, _, _ := resultFields(t, h.waitForCallback(t, 1).body)
		if status != statusPassed {
			t.Fatalf("status %q", status)
		}
	})
}

func TestRunTaskPlanDownload(t *testing.T) {
	t.Run("the token stays on the API host", func(t *testing.T) {
		h := newRunTaskHarness(t, plancheck.Report{})
		h.postSigned(t, nil)
		h.waitForCallback(t, 1)
		if len(h.hcp.planAuth) != 1 || h.hcp.planAuth[0] != "Bearer "+testToken {
			t.Fatalf("plan auth %v", h.hcp.planAuth)
		}
		if len(h.hcp.dlAuth) != 1 || h.hcp.dlAuth[0] != "" {
			t.Fatalf("download auth %q", h.hcp.dlAuth)
		}
	})
	t.Run("a plan that is not ready is retried", func(t *testing.T) {
		h := newRunTaskHarness(t, plancheck.Report{})
		h.hcp.planStatus = []int{http.StatusNoContent, http.StatusNoContent, http.StatusTemporaryRedirect}
		h.postSigned(t, nil)
		status, _, _ := resultFields(t, h.waitForCallback(t, 1).body)
		if status != statusPassed || h.bundle.read != testPlanBody {
			t.Fatalf("status %q read %q", status, h.bundle.read)
		}
	})
	t.Run("a direct answer is read", func(t *testing.T) {
		h := newRunTaskHarness(t, plancheck.Report{})
		h.hcp.planStatus = []int{http.StatusOK}
		h.postSigned(t, nil)
		h.waitForCallback(t, 1)
		if h.bundle.read != testPlanBody || h.hcp.dlHits != 0 {
			t.Fatalf("read %q hits %d", h.bundle.read, h.hcp.dlHits)
		}
	})
	for name, target := range map[string]string{
		"a host that is not allowed": "https://attacker.example.test/plan",
		"plain HTTP":                 "http://attacker.example.test/plan",
		"credentials in the URL":     "https://user:pass@attacker.example.test/plan",
	} {
		t.Run(name, func(t *testing.T) {
			h := newRunTaskHarness(t, plancheck.Report{})
			h.hcp.redirectTo = target
			h.postSigned(t, nil)
			status, _, _ := resultFields(t, h.waitForCallback(t, 1).body)
			if status != statusFailed || h.bundle.read != "" {
				t.Fatalf("status %q read %q", status, h.bundle.read)
			}
		})
	}
}

func TestRunTaskNeverSendsTheTokenElsewhere(t *testing.T) {
	var hits int
	var mu sync.Mutex
	elsewhere := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		hits++
	}))
	t.Cleanup(elsewhere.Close)
	h := newRunTaskHarness(t, plancheck.Report{})
	for name, mutate := range map[string]func(map[string]any){
		"another callback host": func(v map[string]any) {
			v["task_result_callback_url"] = elsewhere.URL + "/api/v2/task-results/x/callback"
		},
		"a callback over HTTP": func(v map[string]any) {
			v["task_result_callback_url"] = "http://" + h.hcp.host() + "/api/v2/task-results/x/callback"
		},
		"another callback path": func(v map[string]any) {
			v["task_result_callback_url"] = "https://" + h.hcp.host() + "/api/v2/admin/users"
		},
		"a callback with a query": func(v map[string]any) {
			v["task_result_callback_url"] = "https://" + h.hcp.host() + "/api/v2/task-results/x/callback?a=b"
		},
		"a bad task result id": func(v map[string]any) { v["task_result_id"] = "../../etc" },
		"a bad run id":         func(v map[string]any) { v["run_id"] = "run with space" },
		"another version":      func(v map[string]any) { v["payload_version"] = 2 },
		"no token":             func(v map[string]any) { v["access_token"] = "" },
		"a huge token":         func(v map[string]any) { v["access_token"] = strings.Repeat("x", maxTokenBytes+1) },
		"the test request": func(v map[string]any) {
			delete(v, "task_result_callback_url")
			v["access_token"] = "test-token"
		},
	} {
		t.Run(name, func(t *testing.T) {
			h.postSigned(t, mutate)
		})
	}
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if hits != 0 || h.hcp.callbackCount() != 0 || len(h.hcp.planAuth) != 0 {
		t.Fatalf("elsewhere %d callbacks %d plan %d", hits, h.hcp.callbackCount(), len(h.hcp.planAuth))
	}
}

func TestRunTaskPlanOnAnotherHostIsNotFetched(t *testing.T) {
	h := newRunTaskHarness(t, plancheck.Report{})
	h.postSigned(t, func(v map[string]any) {
		v["plan_json_api_url"] = h.hcp.download.URL + "/api/v2/plans/plan-abc/json-output"
	})
	status, _, _ := resultFields(t, h.waitForCallback(t, 1).body)
	if status != statusFailed || h.hcp.dlHits != 0 {
		t.Fatalf("status %q hits %d", status, h.hcp.dlHits)
	}
}

func TestRunTaskCallbackRetries(t *testing.T) {
	t.Run("a server error is retried", func(t *testing.T) {
		h := newRunTaskHarness(t, plancheck.Report{})
		h.hcp.callbackStatus = []int{http.StatusBadGateway, http.StatusOK}
		h.postSigned(t, nil)
		h.waitForCallback(t, 2)
	})
	t.Run("a refused token is not", func(t *testing.T) {
		h := newRunTaskHarness(t, plancheck.Report{})
		h.hcp.callbackStatus = []int{http.StatusUnauthorized}
		h.postSigned(t, nil)
		h.waitForCallback(t, 1)
		time.Sleep(50 * time.Millisecond)
		if h.hcp.callbackCount() != 1 {
			t.Fatalf("callbacks %d", h.hcp.callbackCount())
		}
	})
	t.Run("it stops after three tries", func(t *testing.T) {
		h := newRunTaskHarness(t, plancheck.Report{})
		h.hcp.callbackStatus = []int{http.StatusBadGateway}
		h.postSigned(t, nil)
		h.waitForCallback(t, 3)
		time.Sleep(50 * time.Millisecond)
		if h.hcp.callbackCount() != 3 {
			t.Fatalf("callbacks %d", h.hcp.callbackCount())
		}
	})
}

func TestRunTaskRepeatAndRetry(t *testing.T) {
	t.Run("a repeated request does no more work", func(t *testing.T) {
		h := newRunTaskHarness(t, plancheck.Report{})
		h.postSigned(t, nil)
		h.waitForCallback(t, 1)
		h.postSigned(t, nil)
		time.Sleep(50 * time.Millisecond)
		if h.hcp.callbackCount() != 1 {
			t.Fatalf("callbacks %d", h.hcp.callbackCount())
		}
	})
	t.Run("a failed job can be triggered again", func(t *testing.T) {
		h := newRunTaskHarness(t, plancheck.Report{})
		h.hcp.callbackStatus = []int{http.StatusUnauthorized, http.StatusOK}
		h.postSigned(t, nil)
		h.waitForCallback(t, 1)
		deadline := time.Now().Add(5 * time.Second)
		for h.service.jobs.seen.add("taskrs-abc123") == false && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		h.service.jobs.seen.forget("taskrs-abc123")
		h.postSigned(t, nil)
		h.waitForCallback(t, 2)
	})
}

func TestRunTaskQueueFullAnswers503(t *testing.T) {
	hcp := newFakeHCP(t)
	service := NewRunTaskService(RunTaskConfig{
		HMACKey: []byte(runTaskKey),
		Bundle:  &fakeBundle{},
		APIHost: hcp.host(),
		Logger:  slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	h := &runTaskHarness{service: service, hcp: hcp, handler: service.Handler()}
	// No worker runs, so the queue fills.
	for i := range queueSize {
		body := h.payload(func(v map[string]any) { v["task_result_id"] = fmt.Sprintf("taskrs-%d", i) })
		if got := h.post(body, signTask(body)); got.Code != http.StatusOK {
			t.Fatalf("request %d status %d", i, got.Code)
		}
	}
	body := h.payload(func(v map[string]any) { v["task_result_id"] = "taskrs-over" })
	if got := h.post(body, signTask(body)); got.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d", got.Code)
	}
	if !service.jobs.seen.add("taskrs-over") {
		t.Fatal("a refused request stayed in the seen set")
	}
}

func TestRunTaskLogsCarryNoPlanData(t *testing.T) {
	h := newRunTaskHarness(t, failingReport("block"))
	h.postSigned(t, nil)
	h.waitForCallback(t, 1)
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(h.logs.String(), "run task evaluated") && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	logs := h.logs.String()
	if !strings.Contains(logs, strings.Repeat("a", 64)) || !strings.Contains(logs, `"failed":1`) {
		t.Fatalf("logs %s", logs)
	}
	assertNoLeak(t, "the log", logs)
}

func TestRunTaskClientErrorsDropTheURL(t *testing.T) {
	err := withoutURL("the plan download failed", fmt.Errorf("wrapped: %w", errors.New("https://x.test/plan?marker=DOWNLOAD-MARKER")))
	if strings.Contains(err.Error(), "DOWNLOAD-MARKER") {
		t.Fatalf("err %v", err)
	}
}

func TestOutcomeLimits(t *testing.T) {
	var violations []plancheck.Violation
	for i := range maxOutcomeAddrs + 5 {
		violations = append(violations, plancheck.Violation{Address: fmt.Sprintf("aws_x.y[%d]", i), Message: messageMark})
	}
	verdicts := make([]plancheck.Verdict, 0, maxRunTaskOutcomes+3)
	for i := range maxRunTaskOutcomes + 3 {
		verdicts = append(verdicts, plancheck.Verdict{DecisionID: "d", CheckIndex: i, Slug: "s", Mode: "block", Result: plancheck.ResultFail, Count: len(violations), Violations: violations})
	}
	result := resultOf(plancheck.Report{Blocked: true, Verdicts: verdicts}, true)
	if len(result.outcomes) != maxRunTaskOutcomes || !strings.Contains(result.message, "3 more checks are not listed") {
		t.Fatalf("outcomes %d message %q", len(result.outcomes), result.message)
	}
	if !strings.Contains(result.outcomes[0].body, "5 more are not listed") || strings.Contains(result.outcomes[0].body, messageMark) {
		t.Fatalf("body %s", result.outcomes[0].body)
	}
	raw, err := json.Marshal(result.document())
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) > 5<<20 {
		t.Fatalf("document is %d bytes", len(raw))
	}
}

func TestOutcomeTextCannotFormatThePage(t *testing.T) {
	verdict := plancheck.Verdict{DecisionID: "d", Slug: "s`lug\n# x", Mode: "block", Result: plancheck.ResultFail, Count: 2, Violations: []plancheck.Violation{
		{Address: "aws_x.y\n```\n# injected", Message: "m"},
		{Message: "no address"},
	}}
	outcome := outcomeOf(verdict)
	if strings.Contains(outcome.description, "`") || strings.Contains(outcome.description, "\n") {
		t.Fatalf("description %q", outcome.description)
	}
	if strings.Count(outcome.body, "```") != 2 || strings.Contains(outcome.body, "\n# injected") {
		t.Fatalf("body %q", outcome.body)
	}
	long := cleanText(strings.Repeat("é", maxAddressBytes))
	if len(long) > maxAddressBytes || !strings.HasPrefix(long, "é") {
		t.Fatalf("len %d", len(long))
	}
}

// A bundle signed by the ipso CLI, with a blocking check on EBS encryption and a warning on public S3
// ACLs. The private key was thrown away after signing. Only the public key is in testdata.
func loadSignedBundle(t *testing.T) *plancheck.Bundle {
	t.Helper()
	digest, err := os.ReadFile(filepath.Join("testdata", "runtask", "digest"))
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := plancheck.Load(filepath.Join("testdata", "runtask", "layout"), strings.TrimSpace(string(digest)), filepath.Join("testdata", "runtask", "public.pub"))
	if err != nil {
		t.Fatal(err)
	}
	return bundle
}

func TestRunTaskWithARealBundle(t *testing.T) {
	const violating = `{"format_version":"1.2","resource_changes":[{"address":"aws_ebs_volume.data","mode":"managed","type":"aws_ebs_volume","change":{"actions":["create"],"after":{"encrypted":false},"after_unknown":{}}}]}`
	const warning = `{"format_version":"1.2","resource_changes":[{"address":"aws_s3_bucket.logs","mode":"managed","type":"aws_s3_bucket","change":{"actions":["create"],"after":{"bucket":"logs","id":"logs"},"after_unknown":{}}},{"address":"aws_s3_bucket_acl.logs","mode":"managed","type":"aws_s3_bucket_acl","change":{"actions":["create"],"after":{"bucket":"logs","acl":"public-read"},"after_unknown":{}}}]}`
	const clean = `{"format_version":"1.2","resource_changes":[{"address":"aws_ebs_volume.data","mode":"managed","type":"aws_ebs_volume","change":{"actions":["create"],"after":{"encrypted":true},"after_unknown":{}}}]}`
	for name, tc := range map[string]struct {
		plan       string
		status     string
		wantInBody string
	}{
		"a blocking violation": {violating, statusFailed, "aws_ebs_volume.data"},
		"only a warning":       {warning, statusPassed, "aws_s3_bucket.logs"},
		"a clean plan":         {clean, statusPassed, "ipso: 0 blocking"},
		"not a plan":           {`{"nope":true}`, statusFailed, "could not finish"},
	} {
		t.Run(name, func(t *testing.T) {
			hcp := newFakeHCP(t)
			hcp.planStatus = []int{http.StatusOK}
			service := NewRunTaskService(RunTaskConfig{
				HMACKey: []byte(runTaskKey),
				Bundle:  &planOverride{plan: tc.plan, bundle: loadSignedBundle(t)},
				APIHost: hcp.host(),
				Logger:  slog.New(slog.NewJSONHandler(io.Discard, nil)),
			})
			service.client.Transport = hcp.api.Client().Transport
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan struct{})
			go func() {
				service.Run(ctx)
				close(done)
			}()
			t.Cleanup(func() {
				cancel()
				<-done
			})
			h := &runTaskHarness{service: service, hcp: hcp, handler: service.Handler(), logs: &syncBuffer{}}
			h.postSigned(t, nil)
			callback := h.waitForCallback(t, 1)
			status, _, _ := resultFields(t, callback.body)
			if status != tc.status || !strings.Contains(callback.body, tc.wantInBody) {
				t.Fatalf("status %q body %s", status, callback.body)
			}
		})
	}
}

// planOverride hands the real bundle a chosen plan in place of what the fake API served.
type planOverride struct {
	plan   string
	bundle *plancheck.Bundle
}

func (o *planOverride) Evaluate(r io.Reader, env string, now time.Time) (plancheck.Report, error) {
	if _, err := io.Copy(io.Discard, r); err != nil {
		return plancheck.Report{}, err
	}
	return o.bundle.Evaluate(strings.NewReader(o.plan), env, now)
}
