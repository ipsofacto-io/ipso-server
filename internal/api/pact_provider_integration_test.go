//go:build integration && pact

package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/pact-foundation/pact-go/v2/models"
	"github.com/pact-foundation/pact-go/v2/provider"
)

// TestPactProviderIpsoServer verifies the ipso-web pact against the real handler, its guard
// included, on PostgreSQL 18. The fixture seeds stateRegistry and stateVerdicts once, and the request filter swaps
// the pact's example token for a signed one that speaks for a person of tenant A. A request the
// pact sends without a token is left without one.
func TestPactProviderIpsoServer(t *testing.T) {
	f := newFixture(t)
	served := httptest.NewServer(f.handler(t, Limits{}))
	defer served.Close()
	token := f.token(t, personA)
	pact, err := filepath.Abs(pactFile)
	if err != nil {
		t.Fatal(err)
	}
	seeded := func(bool, models.ProviderState) (models.ProviderStateResponse, error) { return nil, nil }
	err = provider.NewVerifier().VerifyProvider(t, provider.VerifyRequest{
		Provider:           "ipso-server",
		ProviderBaseURL:    served.URL,
		PactFiles:          []string{pact},
		FailIfNoPactsFound: true,
		StateHandlers:      models.StateHandlers{stateRegistry: seeded, stateVerdicts: seeded},
		RequestFilter: func(next http.Handler) http.Handler {
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "" {
					r.Header.Set("Authorization", token)
				}
				next.ServeHTTP(w, r)
			})
		},
	})
	if err != nil {
		t.Fatal(err)
	}
}
