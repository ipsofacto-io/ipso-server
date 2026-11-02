package evals

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/llmgw"
)

var (
	record = flag.Bool("record", false, "send every prompt through the LLM gateway and rewrite the recorded answers")
	update = flag.Bool("update", false, "write this run's scores as the baseline and add a history line")
	report = flag.String("report", "", "write this run's scores to this JSON file")
)

const (
	cassettePath = "testdata/cassette.json"
	baselinePath = "testdata/baseline.json"
	historyPath  = "testdata/history.jsonl"
)

// TestEvals runs every suite. By default it replays the recorded answers and fails on a drop of
// more than three points below the baseline. -record calls the gateway that IPSO_EVALS_GATEWAY
// configures, as the tenant IPSO_EVALS_TENANT. The datasets are synthetic, so a route the gateway
// cannot place in the EU may record them.
func TestEvals(t *testing.T) {
	cassette, err := LoadCassette(cassettePath)
	if err != nil {
		t.Fatal(err)
	}
	if *record {
		cassette.Record(liveGateway(t))
	}

	scores := Scores{}
	threads, err := LoadThreads("testdata/pr-discussions.json")
	if err != nil {
		t.Fatal(err)
	}
	pr, err := PRSuite(t.Context(), cassette.Complete, threads)
	if err != nil {
		t.Fatal(err)
	}
	for name, score := range pr {
		scores[name] = score
	}
	t.Logf("scores:\n%s", Table(scores))

	if *record {
		if err := cassette.Save(cassettePath); err != nil {
			t.Fatal(err)
		}
	}
	if *report != "" {
		if err := writeJSON(*report, scores); err != nil {
			t.Fatal(err)
		}
	}
	baseline, err := LoadBaseline(baselinePath)
	if err != nil {
		t.Fatal(err)
	}
	if *update {
		if err := SaveBaseline(baselinePath, Update(baseline, scores)); err != nil {
			t.Fatal(err)
		}
		if err := AppendHistory(historyPath, time.Now(), scores); err != nil {
			t.Fatal(err)
		}
		return
	}
	for _, failure := range Gate(baseline, scores) {
		t.Error(failure)
	}
}

// liveGateway builds the LLM gateway from the environment, with a budget held in memory.
func liveGateway(t *testing.T) CompleteFunc {
	t.Helper()
	path, tenantID := os.Getenv("IPSO_EVALS_GATEWAY"), os.Getenv("IPSO_EVALS_TENANT")
	if path == "" || tenantID == "" {
		t.Fatal("-record needs IPSO_EVALS_GATEWAY and IPSO_EVALS_TENANT")
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	cfg, err := llmgw.ParseConfig(file)
	if err != nil {
		t.Fatal(err)
	}
	tenant, err := uuid.Parse(tenantID)
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := llmgw.New(cfg, &memoryLedger{}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return gateway.For(tenant)
}

// memoryLedger never refuses: the eval run is bounded by its datasets.
type memoryLedger struct{}

func (memoryLedger) Reserve(context.Context, uuid.UUID, time.Time, int64, int64) error { return nil }
func (memoryLedger) Settle(context.Context, uuid.UUID, time.Time, int64) error         { return nil }

func TestGate(t *testing.T) {
	floor := 0.8
	baseline := Baseline{"a": {Score: 0.90}, "b": {Score: 0.90, Min: &floor}, "c": {Score: 0.5}}
	if got := Gate(baseline, Scores{"a": 0.87, "b": 0.88, "c": 0.9}); len(got) != 0 {
		t.Fatalf("a three-point drop and gains failed: %v", got)
	}
	got := Gate(baseline, Scores{"a": 0.8699, "b": 0.79, "d": 1})
	want := 5 // a drops too far; b drops too far and is below its floor; c is missing; d is new
	if len(got) != want {
		t.Fatalf("failures = %v, want %d", got, want)
	}
}

func TestUpdateKeepsFloorsAndDropsStaleMetrics(t *testing.T) {
	floor := 0.6
	next := Update(Baseline{"a": {Score: 0.7, Min: &floor}, "gone": {Score: 1}}, Scores{"a": 0.75, "new": 0.5})
	if len(next) != 2 || next["a"].Score != 0.75 || next["a"].Min == nil || *next["a"].Min != 0.6 || next["new"].Min != nil {
		t.Fatalf("next = %+v", next)
	}
}

func TestCassetteReplaysAndRecords(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/cassette.json"
	calls := 0
	recorder, err := LoadCassette(path)
	if err != nil {
		t.Fatal(err)
	}
	recorder.Record(func(context.Context, string, string) (llmgw.Completion, error) {
		calls++
		return llmgw.Completion{Text: "answer", Model: "m"}, nil
	})
	first := "DATA-" + "0123456789abcdef0123456789abcdef" + "\n{}"
	second := "DATA-" + "fedcba9876543210fedcba9876543210" + "\n{}"
	if _, err := recorder.Complete(t.Context(), "sys", first); err != nil {
		t.Fatal(err)
	}
	// The same prompt with another nonce is the same key, so it is not sent again.
	if _, err := recorder.Complete(t.Context(), "sys", second); err != nil || calls != 1 {
		t.Fatalf("calls %d err %v", calls, err)
	}
	if err := recorder.Save(path); err != nil {
		t.Fatal(err)
	}

	replay, err := LoadCassette(path)
	if err != nil {
		t.Fatal(err)
	}
	answer, err := replay.Complete(t.Context(), "sys", second)
	if err != nil || answer.Text != "answer" || answer.Model != "m" {
		t.Fatalf("answer %+v err %v", answer, err)
	}
	if _, err := replay.Complete(t.Context(), "another system prompt", first); !errors.Is(err, ErrNotRecorded) {
		t.Fatalf("err = %v, want ErrNotRecorded", err)
	}
	raw, _ := os.ReadFile(path)
	var saved []Recording
	if err := json.Unmarshal(raw, &saved); err != nil || len(saved) != 1 {
		t.Fatalf("saved %s", raw)
	}
}
