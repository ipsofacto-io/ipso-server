//go:build githublive

package integrations

import (
	"fmt"
	"os"
	"testing"
)

func TestLiveCheckRun(t *testing.T) {
	app, err := NewApp("1", testPEM())
	if err != nil {
		t.Fatal(err)
	}
	client := &RepoClient{app: app, token: os.Getenv("GH_TOKEN"), repo: os.Getenv("GITHUB_REPOSITORY")}
	id, err := client.createCheckRun(t.Context(), os.Getenv("HEAD_SHA"))
	if err != nil {
		t.Fatal(err)
	}
	var annotations []annotation
	for i := range 120 {
		annotations = append(annotations, failureAt("README.md", fmt.Sprintf("contract check %d", i)))
	}
	if err := client.completeCheckRun(t.Context(), id, outcome{conclusion: "neutral", title: "Contract check", summary: "One-time check of the Checks API payloads.", annotations: annotations}); err != nil {
		t.Fatal(err)
	}
	t.Logf("check run %d", id)
}
