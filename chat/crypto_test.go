package chat

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
	const webhook = "https://hooks.slack.com/services/T000/B000/secret"
	sealed, err := Seal(key, tenant, Slack, webhook)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Open(key, sealed, tenant, Slack)
	if err != nil || got != webhook {
		t.Fatalf("open = %q %v", got, err)
	}
	if _, err := Open(key, sealed, tenant, Teams); err == nil {
		t.Fatal("opened under another connector")
	}
	other := uuid.MustParse("00000000-0000-4000-8000-00000000000b")
	if _, err := Open(key, sealed, other, Slack); err == nil {
		t.Fatal("opened under another tenant")
	}
	if _, err := Seal(key, tenant, Slack, ""); err == nil {
		t.Fatal("an empty url was sealed")
	}
}
