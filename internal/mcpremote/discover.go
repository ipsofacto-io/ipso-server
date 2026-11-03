package mcpremote

import (
	"context"
	"errors"
	"net/http"
	"slices"

	"github.com/ipsofacto-io/ipso-server/internal/authn"
)

// Discover reads the authorization server's metadata and keys with authn.Discover, and refuses a
// server MCP clients could not use: it must offer PKCE with S256 and Client ID Metadata Documents,
// which are that server's job.
func Discover(ctx context.Context, client *http.Client, issuer, audience string) (*authn.JWTVerifier, error) {
	verifier, meta, err := authn.Discover(ctx, client, issuer, audience)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(meta.CodeChallengeMethods, "S256") {
		return nil, errors.New("the authorization server does not offer PKCE with S256")
	}
	if !meta.ClientIDMetadataDocuments {
		return nil, errors.New("the authorization server does not support Client ID Metadata Documents")
	}
	return verifier, nil
}
