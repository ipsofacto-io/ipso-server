package integrations

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// advisoryHooks records what the advisory hooks of a service were asked.
type advisoryHooks struct {
	mu      sync.Mutex
	enabled func(repo string) (bool, error)
	asked   []string
	tenants []uuid.UUID
	runs    []OpenPullRequest
	fail    error
	block   chan struct{}
	started chan struct{}
}

func (h *advisoryHooks) advisoryEnabled(_ context.Context, tenant uuid.UUID, repo string) (bool, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.asked = append(h.asked, repo)
	h.tenants = append(h.tenants, tenant)
	return h.enabled(repo)
}

func (h *advisoryHooks) onPullRequest(ctx context.Context, pr OpenPullRequest) error {
	h.mu.Lock()
	h.runs = append(h.runs, pr)
	fail, block, started := h.fail, h.block, h.started
	h.mu.Unlock()
	if started != nil {
		started <- struct{}{}
	}
	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
		}
	}
	return fail
}

func (h *advisoryHooks) ran() []OpenPullRequest {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]OpenPullRequest(nil), h.runs...)
}

func advisoryService(t *testing.T, app *App, logs io.Writer, hooks *advisoryHooks, onMerged func(context.Context, MergedPullRequest) error) *Service {
	t.Helper()
	if logs == nil {
		logs = io.Discard
	}
	return NewService(Config{
		App:             app,
		WebhookSecret:   []byte(testSecret),
		Logger:          slog.New(slog.NewTextHandler(logs, nil)),
		Tenants:         ownedBy(map[int64]uuid.UUID{42: testTenant}),
		OnMerged:        onMerged,
		AdvisoryEnabled: hooks.advisoryEnabled,
		OnPullRequest:   hooks.onPullRequest,
	})
}

func optedIn(repo string) (bool, error) { return repo == testRepo, nil }

func TestNoAdvisoryHookStartsNoAdvisoryJob(t *testing.T) {
	fake, app := newFakeGitHub(t)
	s := newTestService(t, app, nil, nil)
	if code := deliver(t, s, "pull_request", "d-1", prEvent("opened")); code != http.StatusAccepted {
		t.Fatalf("status %d", code)
	}
	if code := deliver(t, s, "pull_request", "d-2", prEvent("ready_for_review")); code != http.StatusAccepted {
		t.Fatalf("ready: status %d", code)
	}
	if len(s.queue) != 1 || len(s.advisory) != 0 {
		t.Fatalf("queued %d check and %d advisory jobs, want 1 and 0", len(s.queue), len(s.advisory))
	}
	drain(s)
	if len(fake.minted) != 1 {
		t.Fatalf("expected only the 1 check-run token, got %d: %v", len(fake.minted), fake.minted)
	}
}

// The list is the only switch: a repository that is not on it queues nothing and mints nothing (ADR-0174).
func TestARepositoryNotOptedInMintsNothingForTheAdvisoryJob(t *testing.T) {
	fake, app := newFakeGitHub(t)
	hooks := &advisoryHooks{enabled: func(string) (bool, error) { return false, nil }}
	s := advisoryService(t, app, nil, hooks, nil)
	event := prEvent("opened")
	event["repository"].(map[string]any)["full_name"] = "Acme/Payments"
	if code := deliver(t, s, "pull_request", "d-1", event); code != http.StatusAccepted {
		t.Fatalf("status %d", code)
	}
	if len(s.queue) != 1 || len(s.advisory) != 0 {
		t.Fatalf("queued %d check and %d advisory jobs, want 1 and 0", len(s.queue), len(s.advisory))
	}
	// The fake serves the lowercase name only, so the check run is not run here.
	<-s.queue
	drain(s)
	if len(fake.minted) != 0 || len(hooks.ran()) != 0 {
		t.Fatalf("an advisory job ran: mints %v, runs %v", fake.minted, hooks.ran())
	}
	// The opt-in is read for the mapped tenant and the lowercase name.
	if len(hooks.asked) != 1 || hooks.asked[0] != testRepo || hooks.tenants[0] != testTenant {
		t.Fatalf("asked %v for %v", hooks.asked, hooks.tenants)
	}
}

func TestAnOptedInPullRequestRunsTheAdvisoryJobWithScopedChecksToken(t *testing.T) {
	fake, app := newFakeGitHub(t)
	hooks := &advisoryHooks{enabled: optedIn}
	s := advisoryService(t, app, nil, hooks, nil)
	for _, action := range []string{"opened", "synchronize", "reopened"} {
		if code := deliver(t, s, "pull_request", "d-"+action, prEvent(action)); code != http.StatusAccepted {
			t.Fatalf("%s: status %d", action, code)
		}
	}
	if len(s.queue) != 3 || len(s.advisory) != 3 {
		t.Fatalf("queued %d check and %d advisory jobs, want 3 and 3", len(s.queue), len(s.advisory))
	}
	drain(s)
	runs := hooks.ran()
	if len(runs) != 3 || len(fake.created) != 3 {
		t.Fatalf("%d advisory jobs and %d check runs, want 3 and 3", len(runs), len(fake.created))
	}
	pr := runs[0]
	if pr.Tenant != testTenant || pr.InstallationID != 42 || pr.Repo != testRepo || pr.RepositoryID != 9 || pr.Number != 7 || pr.HeadSHA != headSHA || pr.Client == nil {
		t.Fatalf("the hook got %+v", pr)
	}
	// 3 check runs + 3 advisory jobs = 6 single-repo tokens.
	if len(fake.minted) != 6 {
		t.Fatalf("%d total tokens, want 6", len(fake.minted))
	}
	for _, m := range fake.minted {
		if got := fmt.Sprint(m["permissions"]); got != "map[checks:write contents:read metadata:read pull_requests:read]" {
			t.Fatalf("the token asks for %s", got)
		}
		if got := fmt.Sprint(m["repository_ids"]); got != "[9]" {
			t.Fatalf("the token names repositories %s", got)
		}
	}
}

// Marking a draft ready changes no commit, so it starts the advisory job and no check run.
func TestReadyForReviewStartsOnlyTheAdvisoryJob(t *testing.T) {
	fake, app := newFakeGitHub(t)
	hooks := &advisoryHooks{enabled: optedIn}
	s := advisoryService(t, app, nil, hooks, nil)
	if code := deliver(t, s, "pull_request", "d-1", prEvent("ready_for_review")); code != http.StatusAccepted {
		t.Fatalf("status %d", code)
	}
	drain(s)
	if len(fake.created) != 0 || len(hooks.ran()) != 1 {
		t.Fatalf("%d check runs and %d advisory jobs, want 0 and 1", len(fake.created), len(hooks.ran()))
	}
	if len(fake.minted) != 1 {
		t.Fatalf("%d minted tokens, want 1", len(fake.minted))
	}
	if got := fmt.Sprint(fake.minted[0]["permissions"]); got != "map[checks:write contents:read metadata:read pull_requests:read]" {
		t.Fatalf("the advisory token asks for %s", got)
	}
	if got := fmt.Sprint(fake.minted[0]["repository_ids"]); got != "[9]" {
		t.Fatalf("the advisory token names repositories %s", got)
	}
}

// A failed advisory job is retried by a redelivery without a second check run, and a failed check run is
// retried without a second advisory job, because each has its own key in the seen set.
func TestEachJobOfADeliveryIsRetriedAlone(t *testing.T) {
	fake, app := newFakeGitHub(t)
	hooks := &advisoryHooks{enabled: optedIn, fail: errors.New("the model failed")}
	s := advisoryService(t, app, nil, hooks, nil)
	deliver(t, s, "pull_request", "d-1", prEvent("opened"))
	drain(s)
	hooks.mu.Lock()
	hooks.fail = nil
	hooks.mu.Unlock()
	if code := deliver(t, s, "pull_request", "d-1", prEvent("opened")); code != http.StatusAccepted {
		t.Fatalf("redelivery: status %d", code)
	}
	if len(s.queue) != 0 || len(s.advisory) != 1 {
		t.Fatalf("the redelivery queued %d check and %d advisory jobs, want 0 and 1", len(s.queue), len(s.advisory))
	}
	drain(s)
	if len(fake.created) != 1 || len(hooks.ran()) != 2 {
		t.Fatalf("%d check runs and %d advisory jobs, want 1 and 2", len(fake.created), len(hooks.ran()))
	}

	fake.statusFor["/repos/"+testRepo+"/pulls/8/files"] = http.StatusInternalServerError
	event := prEvent("opened")
	event["number"] = 8
	deliver(t, s, "pull_request", "d-2", event)
	drain(s)
	delete(fake.statusFor, "/repos/"+testRepo+"/pulls/8/files")
	deliver(t, s, "pull_request", "d-2", event)
	if len(s.queue) != 1 || len(s.advisory) != 0 {
		t.Fatalf("the redelivery of a failed check run queued %d check and %d advisory jobs, want 1 and 0", len(s.queue), len(s.advisory))
	}
}

// A repository removed from the list while its job waited mints nothing when the job runs.
func TestTheAdvisoryJobReadsTheOptInAgainBeforeItMints(t *testing.T) {
	fake, app := newFakeGitHub(t)
	on := true
	hooks := &advisoryHooks{}
	hooks.enabled = func(string) (bool, error) { return on, nil }
	s := advisoryService(t, app, nil, hooks, nil)
	deliver(t, s, "pull_request", "d-1", prEvent("ready_for_review"))
	if len(s.advisory) != 1 {
		t.Fatal("the advisory job was not queued")
	}
	hooks.mu.Lock()
	on = false
	hooks.mu.Unlock()
	drain(s)
	if len(fake.minted) != 0 || len(hooks.ran()) != 0 {
		t.Fatalf("a job for a repository taken off the list ran: mints %v", fake.minted)
	}
}

// The advisory job is best effort: a full lane or a failed read of the opt-in drops it, and the check run of the
// delivery still runs.
func TestADroppedAdvisoryJobLeavesTheCheckRun(t *testing.T) {
	_, app := newFakeGitHub(t)
	var logs strings.Builder
	hooks := &advisoryHooks{enabled: optedIn}
	s := advisoryService(t, app, &logs, hooks, nil)
	for i := range advisoryQueueSize {
		if code := deliver(t, s, "pull_request", fmt.Sprintf("r-%d", i), prEvent("ready_for_review")); code != http.StatusAccepted {
			t.Fatalf("delivery %d: status %d", i, code)
		}
	}
	if code := deliver(t, s, "pull_request", "over", prEvent("opened")); code != http.StatusAccepted {
		t.Fatalf("a full advisory lane: status %d", code)
	}
	if len(s.queue) != 1 || len(s.advisory) != advisoryQueueSize {
		t.Fatalf("queued %d check and %d advisory jobs", len(s.queue), len(s.advisory))
	}
	if !strings.Contains(logs.String(), "webhook advisory job dropped") || !strings.Contains(logs.String(), "the lane is full") {
		t.Fatalf("the drop was not logged: %s", logs.String())
	}
	// A dropped job is forgotten, so a redelivery once the lane has room queues it.
	<-s.advisory
	if code := deliver(t, s, "pull_request", "over", prEvent("opened")); code != http.StatusAccepted || len(s.advisory) != advisoryQueueSize {
		t.Fatalf("the redelivery: status %d, %d advisory jobs", code, len(s.advisory))
	}

	hooks.mu.Lock()
	hooks.enabled = func(string) (bool, error) { return false, errors.New("the database is down") }
	hooks.mu.Unlock()
	logs.Reset()
	if code := deliver(t, s, "pull_request", "d-lookup", prEvent("opened")); code != http.StatusAccepted {
		t.Fatalf("a failed opt-in read: status %d", code)
	}
	if len(s.queue) != 2 || !strings.Contains(logs.String(), "the opt-in read failed") || strings.Contains(logs.String(), "database is down") {
		t.Fatalf("queued %d check jobs, logs %s", len(s.queue), logs.String())
	}
	if strings.Contains(strings.ToLower(logs.String()), testRepo) {
		t.Fatalf("the log names the repository: %s", logs.String())
	}
}

// A model can take minutes. An advisory job never holds the worker of a merged pull request job or of a check
// run (ADR-0174).
func TestSlowAdvisoryJobsDoNotDelayOtherLanes(t *testing.T) {
	fake, app := newFakeGitHub(t)
	release := make(chan struct{})
	hooks := &advisoryHooks{enabled: optedIn, block: release, started: make(chan struct{}, advisoryQueueSize)}
	merged := make(chan struct{}, 1)
	s := advisoryService(t, app, nil, hooks, func(context.Context, MergedPullRequest) error {
		merged <- struct{}{}
		return nil
	})
	ctx, stop := context.WithCancel(t.Context())
	stopped := make(chan struct{})
	go func() {
		s.Run(ctx)
		close(stopped)
	}()
	defer func() {
		close(release)
		stop()
		<-stopped
	}()
	for i := range 3 {
		deliver(t, s, "pull_request", fmt.Sprintf("r-%d", i), prEvent("ready_for_review"))
	}
	select {
	case <-hooks.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the advisory job did not start")
	}
	deliver(t, s, "pull_request", "m-1", prEvent("closed"))
	deliver(t, s, "pull_request", "c-1", prEvent("synchronize"))
	select {
	case <-merged:
	case <-time.After(5 * time.Second):
		t.Fatal("the merged pull request job waited for the advisory job")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		fake.mu.Lock()
		created := len(fake.created)
		fake.mu.Unlock()
		if created >= 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the check run waited for the advisory job")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if running := len(hooks.started); running != 0 {
		t.Fatalf("%d advisory jobs beyond the %d worker of their lane started", running, advisoryWorkerCount)
	}
}

func TestPublishAdvisoryCheckRunIsAlwaysNeutralAndPlainText(t *testing.T) {
	fake, app := newFakeGitHub(t)
	client, err := app.repoClient(t.Context(), 42, 9, testRepo, map[string]string{"checks": writeAccess})
	if err != nil {
		t.Fatal(err)
	}
	// 55 annotations force one in_progress POST (50) and one completing PATCH (5) with conclusion "neutral".
	anns := make([]AdvisoryAnnotation, 55)
	for i := range anns {
		level := "notice"
		if i == 0 {
			level = "warning"
		} else if i == 1 {
			// A failure level must be clamped to notice.
			level = "failure"
		}
		anns[i] = AdvisoryAnnotation{
			Path:      "db/schema.sql",
			StartLine: i + 1,
			EndLine:   i + 1,
			Level:     level,
			Title:     "Deviates: [click](https://evil.example) <script> @octocat",
			Message:   SanitizeAdvisoryText("Adds [MySQL](https://evil.example) <b>table</b> @alice") + "\n\nAI-generated (mistral-medium, prompt pr-advisory-v2). Advisory only; does not block a merge.",
		}
	}
	err = client.PublishAdvisoryCheckRun(t.Context(), headSHA, AdvisoryCheckRun{
		Title:       "Advisory check: 1 deviation noted",
		Summary:     "AI-generated advisory verdicts from llm-advisory checks.",
		Annotations: anns,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(fake.created) != 1 || len(fake.patches) != 1 {
		t.Fatalf("created %d, patches %d, want 1 and 1", len(fake.created), len(fake.patches))
	}
	post := fake.created[0]
	if post["name"] != AdvisoryCheckName || post["status"] != "in_progress" || post["conclusion"] != nil {
		t.Fatalf("unexpected POST check run for multi-batch publish: %v", post)
	}
	output := post["output"].(map[string]any)
	firstBatch := output["annotations"].([]any)
	if len(firstBatch) != 50 {
		t.Fatalf("first batch has %d annotations, want 50", len(firstBatch))
	}
	first := firstBatch[0].(map[string]any)
	if first["annotation_level"] != "warning" {
		t.Fatalf("first level = %v, want warning", first["annotation_level"])
	}
	second := firstBatch[1].(map[string]any)
	if second["annotation_level"] != "notice" {
		t.Fatalf("clamped level = %v, want notice", second["annotation_level"])
	}
	title := first["title"].(string)
	msg := first["message"].(string)
	for _, forbidden := range []string{"https://", "<script>", "<b>", "@octocat", "@alice", "[click]", "[MySQL]"} {
		if strings.Contains(title, forbidden) || strings.Contains(msg, forbidden) {
			t.Fatalf("forbidden token %q survived sanitization: title=%q msg=%q", forbidden, title, msg)
		}
	}
	if !strings.Contains(msg, "AI-generated (mistral-medium, prompt pr-advisory-v2)") {
		t.Fatalf("missing AI-generated label in message: %q", msg)
	}
	patch := fake.patches[0]
	if patch["status"] != "completed" || patch["conclusion"] != "neutral" {
		t.Fatalf("unexpected PATCH check run: %v", patch)
	}
	secondBatch := patch["output"].(map[string]any)["annotations"].([]any)
	if len(secondBatch) != 5 {
		t.Fatalf("second batch has %d annotations, want 5", len(secondBatch))
	}

	exists, err := client.HasAdvisoryCheckRun(t.Context(), headSHA)
	if err != nil || !exists {
		t.Fatalf("HasAdvisoryCheckRun after publish = %v, %v; want true, nil", exists, err)
	}
	otherSHA := "fedcba9876543210fedcba9876543210fedcba98"
	exists, err = client.HasAdvisoryCheckRun(t.Context(), otherSHA)
	if err != nil || exists {
		t.Fatalf("HasAdvisoryCheckRun for unseen head = %v, %v; want false, nil", exists, err)
	}

	// Over maxRunAnnotations (500) caps annotations at 500 and notes the omitted count in summary.
	many := make([]AdvisoryAnnotation, maxRunAnnotations+3)
	for i := range many {
		many[i] = AdvisoryAnnotation{Path: "db/schema.sql", StartLine: i + 1, EndLine: i + 1, Level: "notice", Title: "Complies", Message: "ok"}
	}
	if err := client.PublishAdvisoryCheckRun(t.Context(), otherSHA, AdvisoryCheckRun{
		Title:       "Advisory check",
		Summary:     "AI-generated advisory verdicts.",
		Annotations: many,
	}); err != nil {
		t.Fatal(err)
	}
	cappedPost := fake.created[len(fake.created)-1]
	cappedSummary := cappedPost["output"].(map[string]any)["summary"].(string)
	if !strings.Contains(cappedSummary, "3 more advisory citations are not annotated.") {
		t.Fatalf("summary missing omitted citation note: %q", cappedSummary)
	}

	// Single-batch publish (<= 50 annotations) completes atomically on POST with conclusion "neutral".
	singleSHA := "1111222233334444555566667777888899990000"
	patchesBefore := len(fake.patches)
	if err := client.PublishAdvisoryCheckRun(t.Context(), singleSHA, AdvisoryCheckRun{
		Title:       "Advisory check: 1 check complied",
		Summary:     "AI-generated advisory verdicts.",
		Annotations: []AdvisoryAnnotation{{Path: "db/schema.sql", StartLine: 1, EndLine: 1, Level: "notice", Title: "Complies", Message: "ok"}},
	}); err != nil {
		t.Fatal(err)
	}
	singlePost := fake.created[len(fake.created)-1]
	if singlePost["status"] != "completed" || singlePost["conclusion"] != "neutral" || len(fake.patches) != patchesBefore {
		t.Fatalf("single-batch publish did not complete atomically: post=%v patches=%d->%d", singlePost, patchesBefore, len(fake.patches))
	}

	// If a multi-batch PATCH fails, the check run stays in_progress so HasAdvisoryCheckRun returns false for retry.
	failFake, failApp := newFakeGitHub(t)
	failFake.statusFor["/repos/"+testRepo+"/check-runs/77"] = http.StatusInternalServerError
	failClient, err := failApp.repoClient(t.Context(), 42, 9, testRepo, map[string]string{"checks": writeAccess})
	if err != nil {
		t.Fatal(err)
	}
	if err := failClient.PublishAdvisoryCheckRun(t.Context(), headSHA, AdvisoryCheckRun{
		Title:       "Advisory check",
		Summary:     "AI-generated advisory verdicts.",
		Annotations: anns,
	}); err == nil {
		t.Fatal("expected PATCH failure error")
	}
	exists, err = failClient.HasAdvisoryCheckRun(t.Context(), headSHA)
	if err != nil || exists {
		t.Fatalf("HasAdvisoryCheckRun after failed PATCH = %v, %v; want false, nil", exists, err)
	}
}
