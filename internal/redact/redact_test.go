package redact

import (
	"strings"
	"testing"
)

func TestTextRemovesSecretsAndAddresses(t *testing.T) {
	secrets := []string{
		"AKIAABCDEFGHIJKLMNOP",
		"ghp_abcdefghijklmnopqrstuvwxyz0123",
		"github_pat_abcdefghijklmnopqrstuvwxyz",
		"xoxb-1234567890-abcdef",
		"sk-abcdefghijklmnopqrstuvwxyz",
		"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTYifQ.c2lnbmF0dXJlLXNpZw",
		"Bearer abcdefghijklmnopqrstuvwxyz",
		"api_key=topsecretvalue",
		"postgres://app:hunter2@db.example/ipso",
		"jane.doe@example.com",
		"-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n-----END RSA PRIVATE KEY-----",
	}
	out := Text("keep this " + strings.Join(secrets, " and ") + " keep that")
	for _, secret := range secrets {
		if strings.Contains(out, secret) {
			t.Errorf("%q survived: %s", secret, out)
		}
	}
	if !strings.HasPrefix(out, "keep this ") || !strings.HasSuffix(out, " keep that") || !strings.Contains(out, Marker) {
		t.Errorf("out = %q", out)
	}
}

func TestTextLeavesPlainTextAlone(t *testing.T) {
	text := "We decided to use PostgreSQL 18 for the registry, see section 2.3."
	if got := Text(text); got != text {
		t.Errorf("Text(%q) = %q", text, got)
	}
}
