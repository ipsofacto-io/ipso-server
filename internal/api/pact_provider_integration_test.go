//go:build integration && pact

package api

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/pact-foundation/pact-go/v2/models"
	"github.com/pact-foundation/pact-go/v2/provider"

	"github.com/ipsofacto-io/ipso-server/internal/authn"
)

// pactFile is the contract of the web app (consumer ipso-web, IPSO-62) with this API. The web app's own
// pact-js tests write it (web/pact), ci / pact fails when the committed file differs from what they write,
// and this test verifies it against the handler on PostgreSQL (ADR-0091).
const pactFile = "../../api/pacts/ipso-web-ipso-server.json"

// stateRegistry is the provider state the pact names for the registry, the review queues and the audit
// answers. Every row it describes is synthetic.
const stateRegistry = "tenant A holds decisions, scopes, a waiver, and proposals"

// stateVerdicts is the provider state of the verdict list: tenant A holds one stored verdict.
const stateVerdicts = "tenant A holds a stored verdict"

// TestPactProviderIpsoServer verifies the ipso-web pact against the real handler, its guard included, on
// PostgreSQL 18. The web app authenticates with the session cookie of ADR-0099, so the fixture opens one
// session for a person of tenant A, and the request filter swaps the pact's example cookie for it. A request
// the pact sends with no cookie is left without one. The fixture seeds both states once.
func TestPactProviderIpsoServer(t *testing.T) {
	f := newFixture(t)
	token, err := authn.NewSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	sessions := &Sessions{
		Origin: "https://ipso.example.test",
		Lookup: func(_ context.Context, got []byte) (Caller, SessionStatus) {
			if !bytes.Equal(got, token) {
				return Caller{}, SessionUnknown
			}
			return f.callers[personA], SessionFound
		},
	}
	served := httptest.NewServer(f.handlerWith(t, Limits{}, sessions))
	defer served.Close()
	cookie := authn.SessionCookieName + "=" + authn.NewSessionCookie(token, time.Now().Add(time.Hour), time.Now()).Value
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
				if r.Header.Get("Cookie") != "" {
					r.Header.Set("Cookie", cookie)
				}
				next.ServeHTTP(w, r)
			})
		},
	})
	if err != nil {
		t.Fatal(err)
	}
}
