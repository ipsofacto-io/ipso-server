package llmgw

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

func TestNormalizeAdvisoryRepositoriesLowercasesSortsAndRefuses(t *testing.T) {
	got, err := NormalizeAdvisoryRepositories([]string{"acme/web", "Acme/API", "acme/api", "acme/my.repo_1-x"})
	if err != nil || !slices.Equal(got, []string{"acme/api", "acme/my.repo_1-x", "acme/web"}) {
		t.Fatalf("%v, %v", got, err)
	}
	if got, err := NormalizeAdvisoryRepositories(nil); err != nil || got == nil || len(got) != 0 {
		t.Fatalf("no list: %v, %v", got, err)
	}
	for _, bad := range []string{"", "acme", "acme/", "/web", "acme/web/extra", "acme/we b", strings.Repeat("a", 40) + "/web", "acme/" + strings.Repeat("a", 101), "acme/wéb", "acme/web\n"} {
		if _, err := NormalizeAdvisoryRepositories([]string{bad}); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	tooMany := make([]string, MaxAdvisoryRepositories+1)
	for i := range tooMany {
		tooMany[i] = fmt.Sprintf("acme/repo-%d", i)
	}
	if _, err := NormalizeAdvisoryRepositories(tooMany); err == nil {
		t.Error("101 repositories were accepted")
	}
	// A repeat counts once, so 101 entries naming 100 repositories pass.
	if got, err := NormalizeAdvisoryRepositories(append(tooMany[:100:100], "ACME/REPO-0")); err != nil || len(got) != MaxAdvisoryRepositories {
		t.Fatalf("%d, %v", len(got), err)
	}
}
