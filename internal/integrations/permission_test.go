package integrations

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCanWriteReadsTheRepositoryPermission(t *testing.T) {
	answers := map[string]struct {
		status int
		body   string
	}{
		"owner":   {http.StatusOK, `{"permission":"admin","role_name":"admin"}`},
		"writer":  {http.StatusOK, `{"permission":"write","role_name":"maintain"}`},
		"reader":  {http.StatusOK, `{"permission":"read","role_name":"triage"}`},
		"nobody":  {http.StatusOK, `{"permission":"none","role_name":""}`},
		"unknown": {http.StatusOK, `{"role_name":"admin"}`},
		"ghost":   {http.StatusNotFound, `{"message":"ghost is not a user"}`},
		"limited": {http.StatusForbidden, `{"message":"rate limit"}`},
		"broken":  {http.StatusInternalServerError, `{}`},
		"garbled": {http.StatusOK, `not json`},
	}
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		if r.Header.Get("Authorization") != "Bearer token" {
			t.Error("the permission was not read with the repository token")
		}
		login := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/repos/acme/payments/collaborators/"), "/permission")
		answer, found := answers[login]
		if !found {
			t.Errorf("unexpected request %s", r.URL.Path)
		}
		w.WriteHeader(answer.status)
		_, _ = w.Write([]byte(answer.body))
	}))
	defer server.Close()
	_, app := newFakeGitHub(t)
	app.base = server.URL
	client := &RepoClient{app: app, token: "token", repo: "acme/payments"}

	for login, want := range map[string]bool{"owner": true, "writer": true, "reader": false, "nobody": false, "unknown": false, "ghost": false} {
		got, err := client.CanWrite(t.Context(), login)
		if err != nil || got != want {
			t.Errorf("%s: got %v, %v want %v", login, got, err, want)
		}
	}
	if len(requests) != 6 {
		t.Fatalf("requests %v: one call for each login", requests)
	}
	for _, request := range requests {
		if !strings.HasPrefix(request, "GET /repos/acme/payments/collaborators/") || !strings.HasSuffix(request, "/permission") {
			t.Errorf("request %q", request)
		}
	}
	for _, login := range []string{"limited", "broken", "garbled"} {
		got, err := client.CanWrite(t.Context(), login)
		if err == nil || got {
			t.Errorf("%s: got %v, %v: a failure must be an error, never a yes", login, got, err)
		}
		if err != nil && strings.Contains(err.Error(), login) {
			t.Errorf("the error names the login: %v", err)
		}
	}
}

func TestCanWriteAsksNothingForTextThatIsNotALogin(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("unexpected request %s", r.URL.Path)
	}))
	defer server.Close()
	_, app := newFakeGitHub(t)
	app.base = server.URL
	client := &RepoClient{app: app, token: "token", repo: "acme/payments"}

	for _, login := range []string{"", ".", "..", "a/b", "a b", "-leading", "a.b", "x?y=1", "a%2f..", "dependabot[bot]", strings.Repeat("a", 40)} {
		if got, err := client.CanWrite(t.Context(), login); err != nil || got {
			t.Errorf("%q: got %v, %v", login, got, err)
		}
	}
	// The longest and the most unusual shapes GitHub issues are still logins.
	for _, login := range []string{strings.Repeat("a", 39), "a", "9", "octo-cat", "user_acme"} {
		if !userLogin.MatchString(login) {
			t.Errorf("%q is a login", login)
		}
	}
}
