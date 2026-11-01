package integrations

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDiscussionReadsEveryKindUpToTheBound(t *testing.T) {
	item := func(id int) map[string]any {
		return map[string]any{
			"id":                 id,
			"html_url":           fmt.Sprintf("https://github.com/acme/payments/pull/7#x-%d", id),
			"body":               "text",
			"author_association": "MEMBER",
			"user":               map[string]any{"type": "User"},
		}
	}
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.URL.Path)
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Error("the discussion was not read with the repository token")
		}
		switch r.URL.Path {
		case "/repos/acme/payments/pulls/7":
			_ = json.NewEncoder(w).Encode(item(7))
		case "/repos/acme/payments/issues/7/comments":
			// Always a full page, so only the bound stops the reading.
			page := make([]map[string]any, discussionPerGet)
			for i := range page {
				page[i] = item(i)
			}
			_ = json.NewEncoder(w).Encode(page)
		case "/repos/acme/payments/pulls/7/reviews", "/repos/acme/payments/pulls/7/comments":
			_ = json.NewEncoder(w).Encode([]map[string]any{item(1)})
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
		}
	}))
	defer server.Close()
	_, app := newFakeGitHub(t)
	app.base = server.URL

	comments, err := (&RepoClient{app: app, token: "token", repo: "acme/payments"}).Discussion(t.Context(), 7)
	if err != nil {
		t.Fatal(err)
	}
	if want := 1 + discussionPerGet*discussionPages + 2; len(comments) != want {
		t.Fatalf("%d comments, want %d", len(comments), want)
	}
	if first := comments[0]; first.ExternalID != "pull-7" || first.Association != "MEMBER" || first.AuthorType != "User" {
		t.Fatalf("first %+v", first)
	}
	if got := comments[len(comments)-1].ExternalID; got != "discussion-1" {
		t.Fatalf("last %s", got)
	}
}
