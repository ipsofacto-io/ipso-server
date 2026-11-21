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
	"sync"
	"testing"
	"time"

	"github.com/ipsofacto-io/ipso-server/runtask"
)

const (
	taskKey  = "kkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkkk"
	taskHost = "hcp.test"
)

// recordingRunner stands in for the runner of package runtask, which has its own tests. It counts the
// tasks it was given and fails the first failures of them.
type recordingRunner struct {
	mu       sync.Mutex
	tasks    []runtask.Task
	failures int
	ran      chan struct{}
}

func (r *recordingRunner) Run(_ context.Context, task runtask.Task) error {
	r.mu.Lock()
	r.tasks = append(r.tasks, task)
	fail := r.failures > 0
	if fail {
		r.failures--
	}
	r.mu.Unlock()
	r.ran <- struct{}{}
	if fail {
		return errors.New("the evaluation did not finish")
	}
	return nil
}

func (r *recordingRunner) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.tasks)
}

func newTaskService(t *testing.T, runner taskRunner) *RunTaskService {
	t.Helper()
	service := NewRunTaskService(RunTaskConfig{
		HMACKey: []byte(taskKey),
		Bundle:  nil,
		APIHost: taskHost,
		Logger:  slog.New(slog.NewJSONHandler(io.Discard, nil)),
	})
	service.runner = runner
	return service
}

func startTaskService(t *testing.T, service *RunTaskService) {
	t.Helper()
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
}

func postTask(t *testing.T, handler http.Handler, id string) int {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"payload_version":          1,
		"stage":                    "post_plan",
		"access_token":             "tttttttttttttttttttttttt",
		"capabilities":             map[string]any{"outcomes": true},
		"plan_json_api_url":        "https://" + taskHost + "/api/v2/plans/plan-abc123/json-output",
		"task_result_callback_url": "https://" + taskHost + "/api/v2/task-results/5ea8d46c-2ceb/callback",
		"task_result_id":           id,
		"run_id":                   "run-abc123",
	})
	if err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha512.New, []byte(taskKey))
	mac.Write(body)
	request := httptest.NewRequest(http.MethodPost, runtask.Path, bytes.NewReader(body))
	request.Header.Set(runtask.Header, hex.EncodeToString(mac.Sum(nil)))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder.Code
}

func waitRan(t *testing.T, runner *recordingRunner) {
	t.Helper()
	select {
	case <-runner.ran:
	case <-time.After(5 * time.Second):
		t.Fatal("the runner never ran")
	}
}

func TestRunTaskServiceHandsTheTaskToTheRunner(t *testing.T) {
	runner := &recordingRunner{ran: make(chan struct{}, queueSize)}
	service := newTaskService(t, runner)
	startTaskService(t, service)
	if code := postTask(t, service.Handler(), "taskrs-abc123"); code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	waitRan(t, runner)
	if runner.count() != 1 || runner.tasks[0].TaskResult != "taskrs-abc123" || runner.tasks[0].Run != "run-abc123" || !runner.tasks[0].Outcomes {
		t.Fatalf("tasks %+v", runner.tasks)
	}
}

func TestRunTaskServiceRepeatAndRetry(t *testing.T) {
	t.Run("a repeated request does no more work", func(t *testing.T) {
		runner := &recordingRunner{ran: make(chan struct{}, queueSize)}
		service := newTaskService(t, runner)
		startTaskService(t, service)
		for range 2 {
			if code := postTask(t, service.Handler(), "taskrs-abc123"); code != http.StatusOK {
				t.Fatalf("status %d", code)
			}
		}
		waitRan(t, runner)
		time.Sleep(50 * time.Millisecond)
		if runner.count() != 1 {
			t.Fatalf("runs %d", runner.count())
		}
	})
	t.Run("a failed job can be triggered again", func(t *testing.T) {
		runner := &recordingRunner{ran: make(chan struct{}, queueSize), failures: 1}
		service := newTaskService(t, runner)
		startTaskService(t, service)
		postTask(t, service.Handler(), "taskrs-abc123")
		waitRan(t, runner)
		deadline := time.Now().Add(5 * time.Second)
		for !service.jobs.seen.add("taskrs-abc123") && time.Now().Before(deadline) {
			time.Sleep(5 * time.Millisecond)
		}
		service.jobs.seen.forget("taskrs-abc123")
		postTask(t, service.Handler(), "taskrs-abc123")
		waitRan(t, runner)
		if runner.count() != 2 {
			t.Fatalf("runs %d", runner.count())
		}
	})
}

func TestRunTaskServiceQueueFullAnswers503(t *testing.T) {
	// No worker runs, so the queue fills.
	service := newTaskService(t, &recordingRunner{ran: make(chan struct{}, 1)})
	handler := service.Handler()
	for i := range queueSize {
		if code := postTask(t, handler, fmt.Sprintf("taskrs-%d", i)); code != http.StatusOK {
			t.Fatalf("request %d status %d", i, code)
		}
	}
	if code := postTask(t, handler, "taskrs-over"); code != http.StatusServiceUnavailable {
		t.Fatalf("status %d", code)
	}
	if !service.jobs.seen.add("taskrs-over") {
		t.Fatal("a refused request stayed in the seen set")
	}
}
