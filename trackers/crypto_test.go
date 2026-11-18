package trackers

import (
	"testing"

	"github.com/google/uuid"
)

func TestSealRoundTripBindsTheTenantAndConnector(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	tenant := uuid.MustParse("00000000-0000-4000-8000-00000000000a")
	sealed, err := Seal(key, tenant, Jira, "secret-token")
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(key, sealed, tenant, Jira)
	if err != nil || got != "secret-token" {
		t.Fatalf("open = %q %v", got, err)
	}
	if _, err := Open(key, sealed, tenant, Linear); err == nil {
		t.Fatal("opened under another connector")
	}
	other := uuid.MustParse("00000000-0000-4000-8000-00000000000b")
	if _, err := Open(key, sealed, other, Jira); err == nil {
		t.Fatal("opened under another tenant")
	}
	if _, err := ParseKey("aaaa"); err == nil {
		t.Fatal("a short key was accepted")
	}
}

func TestAllowedURLRejectsAHostTheServerDidNotBuild(t *testing.T) {
	if !AllowedURL(Jira, "https://acme.atlassian.net/browse/OPS-1") {
		t.Fatal("jira url rejected")
	}
	if AllowedURL(Jira, "https://jira.example.com/browse/OPS-1") {
		t.Fatal("a self-hosted jira url was accepted")
	}
	if AllowedURL(GitHubIssues, "https://github.com/acme/payments/pull/1") {
		t.Fatal("a pull request url was accepted")
	}
}
