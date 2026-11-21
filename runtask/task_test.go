package runtask

import (
	"context"
	"crypto/x509"
	"net/http"
	"strings"
	"testing"
)

func goodTask(host string) Task {
	return Task{
		Stage:       "post_plan",
		AccessToken: testToken,
		Outcomes:    true,
		PlanURL:     "https://" + host + "/api/v2/plans/plan-abc123/json-output",
		CallbackURL: "https://" + host + "/api/v2/task-results/5ea8d46c-2ceb/callback",
		TaskResult:  "taskrs-abc123",
		Run:         "run-abc123",
	}
}

func TestTaskCheckRebuildsTheCallbackFromTheHost(t *testing.T) {
	callback, ok := goodTask("hcp.test").Check("hcp.test")
	if !ok || callback != "https://hcp.test/api/v2/task-results/5ea8d46c-2ceb/callback" {
		t.Fatalf("callback %q ok %v", callback, ok)
	}
}

func TestTaskCheckRefusesWhatCannotBeAnswered(t *testing.T) {
	for name, mutate := range map[string]func(*Task){
		"an unknown stage":        func(k *Task) { k.Stage = "post_apply_later" },
		"no stage":                func(k *Task) { k.Stage = "" },
		"a malformed result id":   func(k *Task) { k.TaskResult = "taskrs-../x" },
		"a malformed run id":      func(k *Task) { k.Run = "plan-abc123" },
		"no token":                func(k *Task) { k.AccessToken = "" },
		"a token over the limit":  func(k *Task) { k.AccessToken = strings.Repeat("t", maxTokenBytes+1) },
		"a callback on a host":    func(k *Task) { k.CallbackURL = "https://evil.test/api/v2/task-results/5ea8d46c-2ceb/callback" },
		"a callback over http":    func(k *Task) { k.CallbackURL = "http://hcp.test/api/v2/task-results/5ea8d46c-2ceb/callback" },
		"a callback with a login": func(k *Task) { k.CallbackURL = "https://user@hcp.test/api/v2/task-results/5ea8d46c-2ceb/callback" },
		"a callback with a query": func(k *Task) { k.CallbackURL = "https://hcp.test/api/v2/task-results/5ea8d46c-2ceb/callback?x=1" },
		"a callback on a path":    func(k *Task) { k.CallbackURL = "https://hcp.test/api/v2/organizations/o/callback" },
	} {
		t.Run(name, func(t *testing.T) {
			task := goodTask("hcp.test")
			mutate(&task)
			if callback, ok := task.Check("hcp.test"); ok {
				t.Fatalf("accepted %q", callback)
			}
		})
	}
	if _, ok := goodTask("hcp.test").Check("other.test"); ok {
		t.Fatal("a task for another API host was accepted")
	}
}

func TestRunnerRefusesATaskForAnotherHostBeforeAnyRequest(t *testing.T) {
	h := newRunTaskHarness(t, failingReport("block"))
	task := goodTask("evil.test")
	if err := h.runner.Run(context.Background(), task); err == nil {
		t.Fatal("a task for another host ran")
	}
	task = goodTask(h.hcp.host())
	task.AccessToken = ""
	if err := h.runner.Run(context.Background(), task); err == nil {
		t.Fatal("a task with no token ran")
	}
	if h.hcp.callbackCount() != 0 || len(h.hcp.planAuth) != 0 || h.hcp.dlHits != 0 {
		t.Fatalf("a refused task reached HCP: callbacks %d, plan %d, downloads %d", h.hcp.callbackCount(), len(h.hcp.planAuth), h.hcp.dlHits)
	}
}

func TestRunnerKeepsTheTokenOnTheAPIHostWhateverTheTaskNames(t *testing.T) {
	h := newRunTaskHarness(t, failingReport("block"))
	task := goodTask(h.hcp.host())
	task.PlanURL = "https://" + h.hcp.downloadHost() + "/api/v2/plans/plan-abc123/json-output"
	if err := h.runner.Run(context.Background(), task); err == nil {
		t.Fatal("a plan on another host was fetched")
	}
	if h.hcp.dlHits != 0 || len(h.hcp.planAuth) != 0 {
		t.Fatalf("the plan host was reached: %d, %d", h.hcp.dlHits, len(h.hcp.planAuth))
	}
	// The run is still reported, as failed, with the token only on the API host.
	if got := h.hcp.lastCallback(); got.auth != "Bearer "+testToken {
		t.Fatalf("callback %+v", got)
	}
}

func TestHandlerHandsTheTaskOnAndAnswersBusy(t *testing.T) {
	var got []Task
	busy := false
	handler := NewHandler(ReceiverConfig{HMACKey: []byte(runTaskKey), APIHost: "hcp.test"}, func(task Task) bool {
		got = append(got, task)
		return !busy
	})
	h := &runTaskHarness{handler: handler}
	body := payloadFor("hcp.test", nil)
	if rec := h.post(body, signTask(body)); rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if len(got) != 1 || got[0].TaskResult != "taskrs-abc123" || got[0].Run != "run-abc123" || !got[0].Outcomes || got[0].AccessToken != testToken {
		t.Fatalf("tasks %+v", got)
	}
	busy = true
	if rec := h.post(body, signTask(body)); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("busy status %d", rec.Code)
	}
	for name, mutate := range map[string]func(map[string]any){
		"another payload version": func(v map[string]any) { v["payload_version"] = 2 },
		"no stage":                func(v map[string]any) { delete(v, "stage") },
		"another callback host": func(v map[string]any) {
			v["task_result_callback_url"] = "https://evil.test/api/v2/task-results/a/callback"
		},
	} {
		t.Run(name, func(t *testing.T) {
			before := len(got)
			body := payloadFor("hcp.test", mutate)
			if rec := h.post(body, signTask(body)); rec.Code != http.StatusOK {
				t.Fatalf("status %d", rec.Code)
			}
			if len(got) != before {
				t.Fatal("a request that needs no work was handed on")
			}
		})
	}
}

func TestRunnerTrustsTheRootsItIsGiven(t *testing.T) {
	hcp := newFakeHCP(t)
	roots := x509.NewCertPool()
	roots.AddCert(hcp.api.Certificate())
	runner := NewRunner(RunnerConfig{
		Bundle:    &fakeBundle{},
		APIHost:   hcp.host(),
		PlanHosts: []string{hcp.downloadHost()},
		RootCAs:   roots,
	})
	runner.wait = 1
	if err := runner.Run(context.Background(), goodTask(hcp.host())); err != nil {
		t.Fatal(err)
	}
	if hcp.callbackCount() != 1 {
		t.Fatalf("callbacks %d", hcp.callbackCount())
	}
	// Without those roots the same server is not trusted, and nothing is reported.
	hcp = newFakeHCP(t)
	runner = NewRunner(RunnerConfig{Bundle: &fakeBundle{}, APIHost: hcp.host(), PlanHosts: []string{hcp.downloadHost()}})
	runner.wait = 1
	if err := runner.Run(context.Background(), goodTask(hcp.host())); err == nil || hcp.callbackCount() != 0 {
		t.Fatalf("an untrusted server was answered: %v, %d", err, hcp.callbackCount())
	}
}
