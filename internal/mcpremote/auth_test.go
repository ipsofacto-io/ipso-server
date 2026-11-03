package mcpremote

import (
	"encoding/base64"
	"testing"

	"github.com/ipsofacto-io/ipso-server/internal/authn"
	"github.com/ipsofacto-io/ipso-server/internal/authn/authntest"
)

// verifierFor discovers auth the way the binary will, with the checks remote MCP adds.
func verifierFor(t *testing.T, auth *authntest.Server, audience string) *authn.JWTVerifier {
	t.Helper()
	verifier, err := Discover(t.Context(), auth.Server.Client(), auth.Server.URL, audience)
	if err != nil {
		t.Fatal(err)
	}
	return verifier
}

func encodeSegment(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
