package integrations

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testRepo    = "acme/payments"
	headSHA     = "1111111111111111111111111111111111111111"
	baseSHA     = "2222222222222222222222222222222222222222"
	mintedValue = "minted-value"
)

// Repeated, so that it is long enough and reads as no credential.
var testSecret = strings.Repeat("s3", 16)

const validDecision = `---
edr: 1
id: 01M6C7Q3Y8R5T2V9W4X6Z0A1B3
slug: tls-on-ingress
title: "Ingress terminates TLS"
status: accepted
owner: team:platform
scope:
  - org: acme
valid_from: 2026-01-01
valid_to: null
review_by: 2027-01-01
supersedes: []
criticality: warning
checks: []
waivers: []
sources:
  - type: pr
    url: https://github.com/acme/platform/pull/1
tags: []
---

# Ingress terminates TLS

## Context

Context.

## Decision

Decision.

## Alternatives considered

- None.

## Consequences

Consequences.

## Verification

Verification.
`

var testKey = func() *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return key
}()

func testPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(testKey)})
}

// fakeGitHub is the part of the REST API the service calls. It records what it was sent.
type fakeGitHub struct {
	t *testing.T

	mu          sync.Mutex
	files       map[string]string
	changed     []changedFile
	permissions map[string]string
	events      []string
	tokenGrant  map[string]string
	minted      []map[string]any
	created     []map[string]any
	patches     []map[string]any
	statusFor   map[string]int
	requests    []string
}

func newFakeGitHub(t *testing.T) (*fakeGitHub, *App) {
	t.Helper()
	fake := &fakeGitHub{
		t:           t,
		files:       map[string]string{},
		permissions: maps.Clone(appPermissions),
		events:      []string{"pull_request", "push"},
		statusFor:   map[string]int{},
	}
	server := httptest.NewServer(fake)
	t.Cleanup(server.Close)
	app, err := NewApp("12345", testPEM())
	if err != nil {
		t.Fatal(err)
	}
	app.base = server.URL
	return fake, app
}

func (f *fakeGitHub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := r.URL.Path
	f.requests = append(f.requests, r.Method+" "+r.URL.RequestURI())
	if status, ok := f.statusFor[path]; ok {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"message":"marker-api-error"}`))
		return
	}
	body, _ := io.ReadAll(r.Body)
	var decoded map[string]any
	_ = json.Unmarshal(body, &decoded)

	switch {
	case path == "/app":
		f.requireAppToken(r)
		_ = json.NewEncoder(w).Encode(map[string]any{"permissions": f.permissions, "events": f.events})
	case strings.HasSuffix(path, "/access_tokens"):
		f.requireAppToken(r)
		f.minted = append(f.minted, decoded)
		grant := f.tokenGrant
		if grant == nil {
			grant = map[string]string{}
			for name, level := range decoded["permissions"].(map[string]any) {
				grant[name] = level.(string)
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"token": mintedValue, "permissions": grant})
	case r.Method == http.MethodPost && path == "/repos/"+testRepo+"/check-runs":
		f.requireRepoToken(r)
		f.created = append(f.created, decoded)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": 77})
	case r.Method == http.MethodPatch && path == "/repos/"+testRepo+"/check-runs/77":
		f.requireRepoToken(r)
		f.patches = append(f.patches, decoded)
		_, _ = w.Write([]byte(`{}`))
	case strings.HasPrefix(path, "/repos/"+testRepo+"/pulls/") && strings.HasSuffix(path, "/files"):
		f.requireRepoToken(r)
		page := r.URL.Query().Get("page")
		_ = json.NewEncoder(w).Encode(f.page(page))
	case strings.HasPrefix(path, "/repos/"+testRepo+"/compare/"):
		f.requireRepoToken(r)
		_ = json.NewEncoder(w).Encode(map[string]any{"files": f.page(r.URL.Query().Get("page"))})
	case strings.HasPrefix(path, "/repos/"+testRepo+"/contents/"):
		f.requireRepoToken(r)
		name := strings.TrimPrefix(path, "/repos/"+testRepo+"/contents/")
		content, ok := f.files[name]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(content))
	default:
		f.t.Errorf("unexpected request %s %s", r.Method, path)
		w.WriteHeader(http.StatusTeapot)
	}
}

func (f *fakeGitHub) page(page string) []changedFile {
	var number int
	_, _ = fmt.Sscanf(page, "%d", &number)
	start := (number - 1) * changedFilesPerGet
	if number < 1 || start >= len(f.changed) {
		return []changedFile{}
	}
	return f.changed[start:min(start+changedFilesPerGet, len(f.changed))]
}

// requireAppToken checks the JWT signature and claims with the public key.
func (f *fakeGitHub) requireAppToken(r *http.Request) {
	token, _ := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		f.t.Errorf("not a JWT: %d parts", len(parts))
		return
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		f.t.Error(err)
		return
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(&testKey.PublicKey, crypto.SHA256, digest[:], signature); err != nil {
		f.t.Errorf("JWT signature: %v", err)
	}
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var claims struct {
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		f.t.Error(err)
	}
	if claims.Iss != "12345" || claims.Exp-claims.Iat > 600 {
		f.t.Errorf("claims %+v", claims)
	}
}

func (f *fakeGitHub) requireRepoToken(r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+mintedValue {
		f.t.Error("a repository call did not use the minted token")
	}
}

func newTestService(t *testing.T, app *App, logs io.Writer, onMerged func(context.Context, MergedPullRequest) error) *Service {
	t.Helper()
	if logs == nil {
		logs = io.Discard
	}
	return NewService(Config{
		App:           app,
		WebhookSecret: []byte(testSecret),
		Logger:        slog.New(slog.NewTextHandler(logs, nil)),
		OnMerged:      onMerged,
	})
}

func sign(body []byte) string {
	mac := hmac.New(sha256.New, []byte(testSecret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func deliver(t *testing.T, s *Service, event, id string, payload any) int {
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
	s.Handler().ServeHTTP(recorder, request)
	return recorder.Code
}

// drain runs what the handler queued and returns.
func drain(s *Service) {
	for {
		select {
		case next := <-s.queue:
			s.work(context.Background(), next)
		default:
			return
		}
	}
}

func prEvent(action string) map[string]any {
	return map[string]any{
		"action":       action,
		"number":       7,
		"installation": map[string]any{"id": 42},
		"repository":   map[string]any{"id": 9, "full_name": testRepo, "default_branch": "main"},
		"pull_request": map[string]any{"merged": action == "closed", "head": map[string]any{"sha": headSHA}},
	}
}

func pushEvent(ref string) map[string]any {
	return map[string]any{
		"ref":          ref,
		"before":       baseSHA,
		"after":        headSHA,
		"installation": map[string]any{"id": 42},
		"repository":   map[string]any{"id": 9, "full_name": testRepo, "default_branch": "main"},
	}
}

func TestSignatureGuardsEverything(t *testing.T) {
	fake, app := newFakeGitHub(t)
	s := newTestService(t, app, nil, nil)
	body := []byte(`{"action":"opened"}`)
	for name, header := range map[string]string{
		"missing":   "",
		"no prefix": hex.EncodeToString(body),
		"not hex":   "sha256=zz",
		"wrong":     "sha256=" + strings.Repeat("0", 64),
		"sha1":      "sha1=" + strings.Repeat("0", 40),
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, webhookPath, strings.NewReader(string(body)))
			request.Header.Set("X-Hub-Signature-256", header)
			request.Header.Set("X-GitHub-Event", "pull_request")
			request.Header.Set("X-GitHub-Delivery", "d-1")
			recorder := httptest.NewRecorder()
			s.Handler().ServeHTTP(recorder, request)
			if recorder.Code != http.StatusUnauthorized {
				t.Fatalf("status %d", recorder.Code)
			}
		})
	}
	drain(s)
	if len(fake.requests) != 0 {
		t.Fatalf("an unsigned delivery reached GitHub: %v", fake.requests)
	}
}

func TestEmptySecretRefusesEverySignature(t *testing.T) {
	mac := hmac.New(sha256.New, nil)
	mac.Write([]byte("x"))
	if validSignature(nil, []byte("x"), "sha256="+hex.EncodeToString(mac.Sum(nil))) {
		t.Fatal("an empty secret accepted a signature")
	}
}

func TestOversizedBodyIsRefused(t *testing.T) {
	_, app := newFakeGitHub(t)
	s := newTestService(t, app, nil, nil)
	request := httptest.NewRequest(http.MethodPost, webhookPath, strings.NewReader(strings.Repeat("a", maxWebhookBody+1)))
	recorder := httptest.NewRecorder()
	s.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status %d", recorder.Code)
	}
}

func TestOnlyPostIsServed(t *testing.T) {
	_, app := newFakeGitHub(t)
	s := newTestService(t, app, nil, nil)
	recorder := httptest.NewRecorder()
	s.Handler().ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, webhookPath, nil))
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status %d", recorder.Code)
	}
}

func TestInvalidDecisionIsAnnotated(t *testing.T) {
	fake, app := newFakeGitHub(t)
	fake.changed = []changedFile{
		{Filename: "docs/decisions/bad.md", Status: "added"},
		{Filename: "docs/decisions/good.md", Status: "modified"},
		{Filename: "docs/decisions/gone.md", Status: "removed"},
		{Filename: "src/main.go", Status: "modified"},
	}
	fake.files["docs/decisions/bad.md"] = "not a record"
	fake.files["docs/decisions/good.md"] = validDecision
	s := newTestService(t, app, nil, nil)

	if code := deliver(t, s, "pull_request", "d-1", prEvent("opened")); code != http.StatusAccepted {
		t.Fatalf("status %d", code)
	}
	drain(s)

	if len(fake.minted) != 1 {
		t.Fatalf("minted %d tokens", len(fake.minted))
	}
	mint := fake.minted[0]
	if ids := mint["repository_ids"].([]any); len(ids) != 1 || ids[0].(float64) != 9 {
		t.Fatalf("token is not limited to one repository: %v", mint)
	}
	want := map[string]any{"checks": "write", "contents": "read", "metadata": "read", "pull_requests": "read"}
	if !maps.Equal(mint["permissions"].(map[string]any), want) {
		t.Fatalf("token permissions %v", mint["permissions"])
	}
	if len(fake.created) != 1 || fake.created[0]["head_sha"] != headSHA || fake.created[0]["status"] != "in_progress" {
		t.Fatalf("created %v", fake.created)
	}
	if len(fake.patches) != 1 || fake.patches[0]["conclusion"] != "failure" || fake.patches[0]["status"] != "completed" {
		t.Fatalf("patches %v", fake.patches)
	}
	annotations := fake.patches[0]["output"].(map[string]any)["annotations"].([]any)
	if len(annotations) != 1 {
		t.Fatalf("annotations %v", annotations)
	}
	first := annotations[0].(map[string]any)
	if first["path"] != "docs/decisions/bad.md" || first["annotation_level"] != "failure" || first["start_line"].(float64) != 1 {
		t.Fatalf("annotation %v", first)
	}
}

func TestValidDecisionsPass(t *testing.T) {
	fake, app := newFakeGitHub(t)
	fake.changed = []changedFile{{Filename: "adr/one.md", Status: "added"}}
	fake.files[configPath] = "decisions:\n  - adr/**/*.md\n"
	fake.files["adr/one.md"] = validDecision
	s := newTestService(t, app, nil, nil)
	deliver(t, s, "pull_request", "d-1", prEvent("synchronize"))
	drain(s)
	if len(fake.patches) != 1 || fake.patches[0]["conclusion"] != "success" {
		t.Fatalf("patches %v", fake.patches)
	}
}

func TestNoDecisionChanged(t *testing.T) {
	fake, app := newFakeGitHub(t)
	fake.changed = []changedFile{{Filename: "src/main.go", Status: "modified"}}
	s := newTestService(t, app, nil, nil)
	deliver(t, s, "pull_request", "d-1", prEvent("reopened"))
	drain(s)
	if fake.patches[0]["conclusion"] != "success" {
		t.Fatalf("patches %v", fake.patches)
	}
}

func TestInvalidConfigIsAnnotated(t *testing.T) {
	fake, app := newFakeGitHub(t)
	fake.files[configPath] = "decisions: []\n"
	s := newTestService(t, app, nil, nil)
	deliver(t, s, "pull_request", "d-1", prEvent("opened"))
	drain(s)
	output := fake.patches[0]["output"].(map[string]any)
	first := output["annotations"].([]any)[0].(map[string]any)
	if fake.patches[0]["conclusion"] != "failure" || first["path"] != configPath {
		t.Fatalf("patch %v", fake.patches[0])
	}
}

func TestAnnotationsGoInBatches(t *testing.T) {
	fake, app := newFakeGitHub(t)
	for i := range 120 {
		name := fmt.Sprintf("docs/decisions/%03d.md", i)
		fake.changed = append(fake.changed, changedFile{Filename: name, Status: "added"})
		fake.files[name] = "not a record"
	}
	s := newTestService(t, app, nil, nil)
	deliver(t, s, "pull_request", "d-1", prEvent("opened"))
	drain(s)
	if len(fake.patches) != 3 {
		t.Fatalf("%d patches", len(fake.patches))
	}
	total := 0
	for i, patch := range fake.patches {
		batch := patch["output"].(map[string]any)["annotations"].([]any)
		if len(batch) > maxAnnotations {
			t.Fatalf("batch of %d", len(batch))
		}
		total += len(batch)
		if _, closed := patch["conclusion"]; closed != (i == len(fake.patches)-1) {
			t.Fatalf("patch %d conclusion %v", i, patch["conclusion"])
		}
	}
	if total != 120 {
		t.Fatalf("%d annotations", total)
	}
}

func TestTooManyDecisionsFailsClosed(t *testing.T) {
	fake, app := newFakeGitHub(t)
	for i := range maxDecisionFiles + 1 {
		fake.changed = append(fake.changed, changedFile{Filename: fmt.Sprintf("docs/decisions/%d.md", i), Status: "added"})
	}
	s := newTestService(t, app, nil, nil)
	deliver(t, s, "pull_request", "d-1", prEvent("opened"))
	drain(s)
	if fake.patches[0]["conclusion"] != "failure" {
		t.Fatalf("patch %v", fake.patches[0])
	}
}

func TestLargeDecisionIsNotParsed(t *testing.T) {
	fake, app := newFakeGitHub(t)
	fake.changed = []changedFile{{Filename: "docs/decisions/big.md", Status: "added"}}
	fake.files["docs/decisions/big.md"] = strings.Repeat("a", maxDecisionBytes+1)
	s := newTestService(t, app, nil, nil)
	deliver(t, s, "pull_request", "d-1", prEvent("opened"))
	drain(s)
	first := fake.patches[0]["output"].(map[string]any)["annotations"].([]any)[0].(map[string]any)
	if first["message"] != "the file is larger than 1 MiB" {
		t.Fatalf("annotation %v", first)
	}
}

func TestHostileFileNameStaysInOnePathSegment(t *testing.T) {
	fake, app := newFakeGitHub(t)
	name := "docs/decisions/a?ref=evil#x.md"
	fake.changed = []changedFile{{Filename: name, Status: "added"}}
	fake.files[name] = validDecision
	s := newTestService(t, app, nil, nil)
	deliver(t, s, "pull_request", "d-1", prEvent("opened"))
	drain(s)
	if fake.patches[0]["conclusion"] != "success" {
		t.Fatalf("patch %v, requests %v", fake.patches[0], fake.requests)
	}
}

func TestAPIFailureClosesTheRunWithFixedText(t *testing.T) {
	fake, app := newFakeGitHub(t)
	fake.statusFor["/repos/"+testRepo+"/pulls/7/files"] = http.StatusInternalServerError
	var logs strings.Builder
	s := newTestService(t, app, &logs, nil)
	deliver(t, s, "pull_request", "d-1", prEvent("opened"))
	drain(s)
	if len(fake.patches) != 1 || fake.patches[0]["conclusion"] != "failure" {
		t.Fatalf("patches %v", fake.patches)
	}
	encoded, _ := json.Marshal(fake.patches[0])
	if strings.Contains(string(encoded), "marker-api-error") || strings.Contains(string(encoded), "status 500") {
		t.Fatalf("an internal error reached the pull request: %s", encoded)
	}
	if strings.Contains(logs.String(), "marker-api-error") || strings.Contains(logs.String(), mintedValue) {
		t.Fatalf("the log holds an API body or a token: %s", logs.String())
	}
	// A failed job can be retried by a redelivery.
	deliver(t, s, "pull_request", "d-1", prEvent("opened"))
	if len(s.queue) != 1 {
		t.Fatal("the redelivery did not queue a job")
	}
}

func TestRepeatedDeliveryDoesNoWork(t *testing.T) {
	fake, app := newFakeGitHub(t)
	s := newTestService(t, app, nil, nil)
	for range 2 {
		deliver(t, s, "pull_request", "d-1", prEvent("opened"))
	}
	drain(s)
	if len(fake.created) != 1 {
		t.Fatalf("created %d check runs", len(fake.created))
	}
}

func TestFullQueueAsksForRedelivery(t *testing.T) {
	_, app := newFakeGitHub(t)
	s := newTestService(t, app, nil, nil)
	for i := range queueSize {
		if code := deliver(t, s, "pull_request", fmt.Sprintf("d-%d", i), prEvent("opened")); code != http.StatusAccepted {
			t.Fatalf("delivery %d: status %d", i, code)
		}
	}
	if code := deliver(t, s, "pull_request", "over", prEvent("opened")); code != http.StatusServiceUnavailable {
		t.Fatalf("status %d", code)
	}
	for len(s.queue) > 0 {
		<-s.queue
	}
	if code := deliver(t, s, "pull_request", "over", prEvent("opened")); code != http.StatusAccepted {
		t.Fatalf("redelivery: status %d", code)
	}
}

func TestPanicInJobDoesNotStopTheService(t *testing.T) {
	_, app := newFakeGitHub(t)
	s := newTestService(t, app, nil, nil)
	s.work(context.Background(), job{delivery: "d-1", name: "boom", run: func(context.Context) error { panic("boom") }})
}

func TestPushOnDefaultBranch(t *testing.T) {
	fake, app := newFakeGitHub(t)
	fake.changed = []changedFile{{Filename: "docs/decisions/bad.md", Status: "modified"}}
	fake.files["docs/decisions/bad.md"] = "not a record"
	s := newTestService(t, app, nil, nil)
	deliver(t, s, "push", "d-1", pushEvent("refs/heads/main"))
	drain(s)
	if fake.patches[0]["conclusion"] != "failure" || fake.created[0]["head_sha"] != headSHA {
		t.Fatalf("patch %v created %v", fake.patches[0], fake.created)
	}
	if _, asked := fake.minted[0]["permissions"].(map[string]any)["pull_requests"]; asked {
		t.Fatal("a push job asked for pull_requests")
	}
}

func TestIgnoredEventsDoNoWork(t *testing.T) {
	deleted := pushEvent("refs/heads/main")
	deleted["deleted"] = true
	created := pushEvent("refs/heads/main")
	created["before"] = zeroSHA
	unmerged := prEvent("closed")
	unmerged["pull_request"].(map[string]any)["merged"] = false
	for name, delivery := range map[string]struct {
		event   string
		payload any
	}{
		"other branch":   {"push", pushEvent("refs/heads/feature")},
		"tag":            {"push", pushEvent("refs/tags/v1")},
		"deleted branch": {"push", deleted},
		"new branch":     {"push", created},
		"labeled":        {"pull_request", prEvent("labeled")},
		"unmerged close": {"pull_request", unmerged},
		"merged no hook": {"pull_request", prEvent("closed")},
		"ping":           {"ping", map[string]any{"zen": "x"}},
		"installation":   {"installation", map[string]any{"action": "created"}},
	} {
		t.Run(name, func(t *testing.T) {
			fake, app := newFakeGitHub(t)
			s := newTestService(t, app, nil, nil)
			if code := deliver(t, s, delivery.event, "d-1", delivery.payload); code != http.StatusAccepted {
				t.Fatalf("status %d", code)
			}
			drain(s)
			if len(fake.requests) != 0 {
				t.Fatalf("requests %v", fake.requests)
			}
		})
	}
}

func TestMalformedTargetsAreRefused(t *testing.T) {
	badRepo := prEvent("opened")
	badRepo["repository"].(map[string]any)["full_name"] = "acme/../../evil"
	badSHA := prEvent("opened")
	badSHA["pull_request"].(map[string]any)["head"].(map[string]any)["sha"] = "main"
	noInstall := prEvent("opened")
	delete(noInstall, "installation")
	for name, payload := range map[string]any{"repo": badRepo, "sha": badSHA, "install": noInstall} {
		t.Run(name, func(t *testing.T) {
			fake, app := newFakeGitHub(t)
			s := newTestService(t, app, nil, nil)
			if code := deliver(t, s, "pull_request", "d-1", payload); code != http.StatusBadRequest {
				t.Fatalf("status %d", code)
			}
			if len(fake.requests) != 0 {
				t.Fatalf("requests %v", fake.requests)
			}
		})
	}
}

func TestMergedHookGetsAReadOnlyClient(t *testing.T) {
	fake, app := newFakeGitHub(t)
	var got MergedPullRequest
	s := newTestService(t, app, nil, func(_ context.Context, pr MergedPullRequest) error {
		got = pr
		return nil
	})
	deliver(t, s, "pull_request", "d-1", prEvent("closed"))
	drain(s)
	if got.Number != 7 || got.Repo != testRepo || got.Client == nil {
		t.Fatalf("got %+v", got)
	}
	want := map[string]any{"metadata": "read", "pull_requests": "read"}
	if !maps.Equal(fake.minted[0]["permissions"].(map[string]any), want) {
		t.Fatalf("token permissions %v", fake.minted[0]["permissions"])
	}
}

func TestVerifyAcceptsOnlySection31(t *testing.T) {
	ctx := context.Background()
	fake, app := newFakeGitHub(t)
	if err := app.Verify(ctx); err != nil {
		t.Fatalf("the section 3.1 set: %v", err)
	}
	fake.permissions["administration"] = "read"
	if err := app.Verify(ctx); err == nil {
		t.Fatal("an extra permission passed")
	}
	delete(fake.permissions, "administration")
	fake.permissions["contents"] = "write"
	if err := app.Verify(ctx); err == nil {
		t.Fatal("contents:write passed")
	}
	fake.permissions["contents"] = "read"
	delete(fake.permissions, "checks")
	if err := app.Verify(ctx); err == nil {
		t.Fatal("a missing permission passed")
	}
	fake.permissions["checks"] = "write"
	fake.events = append(fake.events, "issue_comment")
	if err := app.Verify(ctx); err == nil {
		t.Fatal("an extra event passed")
	}
}

func TestTokenGrantingMoreIsNotUsed(t *testing.T) {
	fake, app := newFakeGitHub(t)
	fake.tokenGrant = map[string]string{"contents": "write"}
	s := newTestService(t, app, nil, nil)
	deliver(t, s, "pull_request", "d-1", prEvent("opened"))
	drain(s)
	if len(fake.created) != 0 {
		t.Fatal("a token that grants more than the request was used")
	}
}

func TestNoRedirectIsFollowed(t *testing.T) {
	var hit bool
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hit = true }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusMovedPermanently)
	}))
	defer redirect.Close()
	_, app := newFakeGitHub(t)
	app.base = redirect.URL
	if err := app.call(context.Background(), "token", http.MethodGet, "/x", nil, nil); err == nil {
		t.Fatal("a redirect passed")
	}
	if hit {
		t.Fatal("the token followed a redirect")
	}
}

func TestNewAppRefusesBadInput(t *testing.T) {
	if _, err := NewApp("abc", testPEM()); err == nil {
		t.Fatal("a non-numeric id passed")
	}
	if _, err := NewApp("1", []byte("not pem")); err == nil {
		t.Fatal("a non-PEM key passed")
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(testKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewApp("1", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})); err != nil {
		t.Fatalf("a PKCS#8 key: %v", err)
	}
}

func TestPlainText(t *testing.T) {
	if got := plainText("a\nb\x1b[31m\u202e"); strings.ContainsAny(got, "\n\x1b\u202e") {
		t.Fatalf("got %q", got)
	}
	if got := plainText(strings.Repeat("é", maxMessageRunes+5)); len([]rune(got)) != maxMessageRunes {
		t.Fatalf("length %d", len([]rune(got)))
	}
	if plainText("\n") == "" {
		t.Fatal("an empty message")
	}
}

func TestServeRefusesAShortSecretAndAnOverprivilegedApp(t *testing.T) {
	fake, app := newFakeGitHub(t)
	listener, err := (&testListener{}).listen(t)
	if err != nil {
		t.Fatal(err)
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if err := Serve(context.Background(), listener, Config{App: app, WebhookSecret: []byte("short"), Logger: logger}); err == nil {
		t.Fatal("a short secret passed")
	}
	fake.permissions["administration"] = "write"
	if err := Serve(context.Background(), listener, Config{App: app, WebhookSecret: []byte(testSecret), Logger: logger}); err == nil {
		t.Fatal("an overprivileged app passed")
	}
}

func TestServeStopsWithItsContext(t *testing.T) {
	_, app := newFakeGitHub(t)
	listener, err := (&testListener{}).listen(t)
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Serve(ctx, listener, Config{App: app, WebhookSecret: []byte(testSecret), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		response, err := http.Get("http://" + address + "/healthz")
		if err == nil {
			_ = response.Body.Close()
			if response.StatusCode != http.StatusNoContent {
				t.Fatalf("health status %d", response.StatusCode)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Serve did not stop")
	}
}
