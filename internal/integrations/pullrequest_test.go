package integrations

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func pullRequestServer(t *testing.T, handle func(w http.ResponseWriter, r *http.Request)) *RepoClient {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Error("the pull request was not read with the repository token")
		}
		handle(w, r)
	}))
	t.Cleanup(server.Close)
	_, app := newFakeGitHub(t)
	app.base = server.URL
	return &RepoClient{app: app, token: "token", repo: "acme/payments"}
}

func pullAnswer(number int, head, base string) map[string]any {
	return map[string]any{
		"number": number, "state": "open", "draft": true, "changed_files": 3,
		"user": map[string]any{"login": "octocat", "type": "User"},
		"head": map[string]any{"sha": head, "repo": map[string]any{"id": 77}},
		"base": map[string]any{"sha": base, "ref": "main", "repo": map[string]any{"id": 42, "default_branch": "main"}},
	}
}

func TestPullRequestReadsTheCommitsAndTheAuthor(t *testing.T) {
	head, base := strings.Repeat("a", 40), strings.Repeat("b", 40)
	client := pullRequestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/acme/payments/pulls/7" {
			t.Errorf("unexpected request %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(pullAnswer(7, head, base))
	})
	pull, err := client.PullRequest(t.Context(), 7)
	if err != nil {
		t.Fatal(err)
	}
	want := PullRequest{
		Number: 7, State: "open", Draft: true, HeadSHA: head, BaseSHA: base, BaseRef: "main", DefaultBranch: "main",
		HeadRepositoryID: 77, BaseRepositoryID: 42, Author: "octocat", AuthorType: "User", ChangedFiles: 3,
	}
	if pull != want {
		t.Fatalf("%+v, want %+v", pull, want)
	}
}

func TestPullRequestReadsAGoneHeadRepositoryAsZero(t *testing.T) {
	client := pullRequestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		answer := pullAnswer(7, strings.Repeat("a", 40), strings.Repeat("b", 40))
		answer["head"] = map[string]any{"sha": strings.Repeat("a", 40), "repo": nil}
		_ = json.NewEncoder(w).Encode(answer)
	})
	pull, err := client.PullRequest(t.Context(), 7)
	if err != nil || pull.HeadRepositoryID != 0 {
		t.Fatalf("%+v, %v", pull, err)
	}
}

func TestPullRequestRefusesAnAnswerForOtherCommits(t *testing.T) {
	sha := strings.Repeat("a", 40)
	for name, answer := range map[string]map[string]any{
		"another number":   pullAnswer(8, sha, sha),
		"a short head":     pullAnswer(7, "abc", sha),
		"an uppercase sha": pullAnswer(7, strings.ToUpper(sha), sha),
		"no base":          pullAnswer(7, sha, ""),
	} {
		t.Run(name, func(t *testing.T) {
			client := pullRequestServer(t, func(w http.ResponseWriter, _ *http.Request) { _ = json.NewEncoder(w).Encode(answer) })
			if _, err := client.PullRequest(t.Context(), 7); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestPullRequestPatchesReadsPagesOfThirty(t *testing.T) {
	var pages []string
	client := pullRequestServer(t, func(w http.ResponseWriter, r *http.Request) {
		pages = append(pages, r.URL.RawQuery)
		if r.URL.Path != "/repos/acme/payments/pulls/7/files" || r.URL.Query().Get("per_page") != "30" {
			t.Errorf("unexpected request %s", r.URL.RequestURI())
		}
		n := patchesPerGet
		if r.URL.Query().Get("page") == "2" {
			n = 2
		}
		batch := make([]map[string]any, n)
		for i := range batch {
			batch[i] = map[string]any{"filename": fmt.Sprintf("f%d.go", i), "status": "modified", "changes": 1, "patch": "@@ -1 +1 @@\n-a\n+b"}
		}
		if r.URL.Query().Get("page") == "2" {
			// A binary file has no patch and counts no lines, and a rename keeps the old name.
			batch[0] = map[string]any{"filename": "logo.png", "status": "added", "changes": 0}
			batch[1] = map[string]any{"filename": "new.go", "previous_filename": "old.go", "status": "renamed", "changes": 0}
		}
		_ = json.NewEncoder(w).Encode(batch)
	})
	files, err := client.PullRequestPatches(t.Context(), 7)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != patchesPerGet+2 || len(pages) != 2 {
		t.Fatalf("%d files in %d pages", len(files), len(pages))
	}
	if first := files[0]; first.Patch == "" || first.Changes != 1 {
		t.Fatalf("first %+v", first)
	}
	if binary := files[patchesPerGet]; binary.Patch != "" || binary.Changes != 0 {
		t.Fatalf("binary %+v", binary)
	}
	if renamed := files[patchesPerGet+1]; renamed.PreviousFilename != "old.go" || renamed.Status != "renamed" {
		t.Fatalf("renamed %+v", renamed)
	}
}

func TestPullRequestPatchesStopsAtTheBound(t *testing.T) {
	requests := 0
	client := pullRequestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		requests++
		batch := make([]map[string]any, patchesPerGet)
		for i := range batch {
			batch[i] = map[string]any{"filename": "a.go", "changes": 1}
		}
		_ = json.NewEncoder(w).Encode(batch)
	})
	if _, err := client.PullRequestPatches(t.Context(), 7); !errors.Is(err, ErrTooManyFiles) {
		t.Fatalf("err %v", err)
	}
	if want := MaxPatchFiles/patchesPerGet + 1; requests != want {
		t.Fatalf("%d requests, want %d", requests, want)
	}
}

func TestPullRequestPatchesRefusesAMalformedPage(t *testing.T) {
	for name, batch := range map[string][]map[string]any{
		"a page longer than asked for": func() []map[string]any {
			out := make([]map[string]any, patchesPerGet+1)
			for i := range out {
				out[i] = map[string]any{"filename": "a.go"}
			}
			return out
		}(),
		"a file with no name": {{"filename": "", "changes": 1}},
		"a negative count":    {{"filename": "a.go", "changes": -1}},
	} {
		t.Run(name, func(t *testing.T) {
			client := pullRequestServer(t, func(w http.ResponseWriter, _ *http.Request) { _ = json.NewEncoder(w).Encode(batch) })
			if _, err := client.PullRequestPatches(t.Context(), 7); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	client := pullRequestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		// An answer over the bound of every API read fails as a whole.
		_, _ = w.Write([]byte(`[{"filename":"a.go","patch":"`))
		_, _ = w.Write([]byte(strings.Repeat("x", maxAPIBody)))
		_, _ = w.Write([]byte(`"}]`))
	})
	if _, err := client.PullRequestPatches(t.Context(), 7); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("an oversized page: %v", err)
	}
}
