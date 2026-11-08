//go:build integration && pact

package api

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pact-foundation/pact-go/v2/models"
	"github.com/pact-foundation/pact-go/v2/provider"

	"github.com/ipsofacto-io/ipso-server/internal/authn"
	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
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

// stateViewer is the provider state of a refusal by the role policy: the session is a viewer's, and a
// viewer may not read the audit routes (ADR-0108).
const stateViewer = "the session belongs to a viewer of tenant A"

// The states of the writes (IPSO-146, ADR-0110). A write changes what the provider holds, and the fixture is
// seeded once, so each of these states seeds its own rows when it is set up and hands their ids back to the
// interaction, which names them with fromProviderState. The session is one of a person who may take the
// action: an approver or a decision owner over the whole tenant (ADR-0108). Rows that no later interaction
// needs are left where they are, and the reads of the pact ask for at least one row and no more.
const (
	stateUnanswered  = "tenant A holds drafts that nobody answered, and the session belongs to an approver"
	stateAnswered    = "tenant A holds a draft that was answered, and the session belongs to an approver"
	stateToWaive     = "tenant A holds a decision in force and a repository scope, and the session belongs to an approver"
	stateToSupersede = "tenant A holds two decisions that nobody superseded, and the session belongs to a decision owner"
)

// seedProposal adds a pending pull request proposal and returns its id. n makes the pull request, and so the
// proposal, unique (the proposal_once constraint of migration 00008).
func (f *fixture) seedProposal(ctx context.Context, n int64) (uuid.UUID, error) {
	var id uuid.UUID
	err := pgtest.Scan(ctx, f.db, tenantA.String(), `
		INSERT INTO proposals.proposal
			(tenant_id, payload, confidence, model_id, prompt_version, repo, pr_number, external_id, source_url, source_sha256, candidate_index)
		VALUES ($1, '{"title":"Use Postgres"}', 0.8, 'm', 'p', 'acme/api', $2, $3, $4, $5, 0)
		RETURNING id`,
		[]any{tenantA, n, "pull-" + strconv.FormatInt(n, 10), "https://github.com/acme/api/pull/" + strconv.FormatInt(n, 10), make([]byte, 32)}, &id)
	if err != nil {
		return uuid.Nil, fmt.Errorf("seed a proposal: %w", err)
	}
	return id, nil
}

// seedDecision adds version 1 of a decision in force from 2026-01-01 at the org scope, and returns its id.
func (f *fixture) seedDecision(ctx context.Context, slug string) (uuid.UUID, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, err
	}
	if _, err := pgtest.Exec(ctx, f.db, tenantA.String(), `
		INSERT INTO registry.decision_version (decision_id, version, tenant_id, body, scope_refs, valid_period)
		VALUES ($1, 1, $2, jsonb_build_object('slug', $3::text, 'title', $3::text), ARRAY[$4::uuid], $5::text::tstzrange)`,
		id, tenantA, slug, f.org, "[2026-01-01,)"); err != nil {
		return uuid.Nil, fmt.Errorf("seed the decision %s: %w", slug, err)
	}
	return id, nil
}

// TestPactProviderIpsoServer verifies the ipso-web pact against the real handler, its guard included, on
// PostgreSQL 18. The web app authenticates with the session cookie of ADR-0099, so the fixture opens one
// session, and the request filter swaps the pact's example cookie for it. A request the pact sends with no
// cookie is left without one. The fixture seeds every state once, and each state names whose session it
// is: the admin of tenant A, or a viewer of tenant A.
func TestPactProviderIpsoServer(t *testing.T) {
	f := newFixture(t)
	token, err := authn.NewSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	var whose atomic.Value
	whose.Store(f.callers[personA])
	sessions := &Sessions{
		Origin: "https://ipso.example.test",
		Lookup: func(_ context.Context, got []byte) (Caller, SessionStatus) {
			if !bytes.Equal(got, token) {
				return Caller{}, SessionUnknown
			}
			return whose.Load().(Caller), SessionFound
		},
	}
	// The pact holds more interactions than the default burst of 20, and they run back to back.
	served := httptest.NewServer(f.handlerWith(t, Limits{Rate: 1000, Burst: 1000}, sessions))
	defer served.Close()
	cookie := authn.SessionCookieName + "=" + authn.NewSessionCookie(token, time.Now().Add(time.Hour), time.Now()).Value
	pact, err := filepath.Abs(pactFile)
	if err != nil {
		t.Fatal(err)
	}
	as := func(subject string) models.StateHandler {
		return func(setup bool, _ models.ProviderState) (models.ProviderStateResponse, error) {
			if setup {
				whose.Store(f.callers[subject])
			}
			return nil, nil
		}
	}
	// seeds is a state of a write: it switches the session to a person who may take the action, seeds what the
	// action needs, and returns the ids the interaction names. Nothing is undone on teardown, because the rows
	// are fresh for each interaction and a later one does not read them.
	var seeded atomic.Int64
	seeds := func(subject string, rows func(ctx context.Context, n int64) (models.ProviderStateResponse, error)) models.StateHandler {
		return func(setup bool, _ models.ProviderState) (models.ProviderStateResponse, error) {
			if !setup {
				return nil, nil
			}
			whose.Store(f.callers[subject])
			return rows(t.Context(), 100+seeded.Add(1))
		}
	}
	unanswered := func(ctx context.Context, n int64) (models.ProviderStateResponse, error) {
		proposal, err := f.seedProposal(ctx, n)
		if err != nil {
			return nil, err
		}
		var agent uuid.UUID
		if err := pgtest.Scan(ctx, f.db, tenantA.String(),
			`INSERT INTO proposals.agent_proposal (tenant_id, principal_id, payload) VALUES ($1, $2, '{"title":"Pin API versions"}') RETURNING id`,
			[]any{tenantA, f.callers[agentA].Principal}, &agent); err != nil {
			return nil, fmt.Errorf("seed an agent proposal: %w", err)
		}
		return models.ProviderStateResponse{"proposalId": proposal.String(), "agentProposalId": agent.String(), "scopeId": f.org.String()}, nil
	}
	answered := func(ctx context.Context, n int64) (models.ProviderStateResponse, error) {
		proposal, err := f.seedProposal(ctx, n)
		if err != nil {
			return nil, err
		}
		if _, err := pgtest.Exec(ctx, f.db, tenantA.String(),
			`INSERT INTO proposals.approval (tenant_id, proposal_id, approver_id, outcome) VALUES ($1, $2, $3, 'rejected')`,
			tenantA, proposal, f.callers[approverA].Principal); err != nil {
			return nil, fmt.Errorf("answer a proposal: %w", err)
		}
		return models.ProviderStateResponse{"proposalId": proposal.String()}, nil
	}
	// The decision use-tls is in force from 2026-01-01, so a waiver inside June 2026 for the repo under its org fits.
	toWaive := func(context.Context, int64) (models.ProviderStateResponse, error) {
		return models.ProviderStateResponse{"decisionId": f.tls.String(), "scopeId": f.repo.String()}, nil
	}
	toSupersede := func(ctx context.Context, n int64) (models.ProviderStateResponse, error) {
		from, err := f.seedDecision(ctx, "synthetic-old-"+strconv.FormatInt(n, 10))
		if err != nil {
			return nil, err
		}
		to, err := f.seedDecision(ctx, "synthetic-new-"+strconv.FormatInt(n, 10))
		if err != nil {
			return nil, err
		}
		return models.ProviderStateResponse{"fromDecisionId": from.String(), "toDecisionId": to.String()}, nil
	}

	err = provider.NewVerifier().VerifyProvider(t, provider.VerifyRequest{
		Provider:           "ipso-server",
		ProviderBaseURL:    served.URL,
		PactFiles:          []string{pact},
		FailIfNoPactsFound: true,
		StateHandlers: models.StateHandlers{
			stateRegistry:    as(personA),
			stateVerdicts:    as(personA),
			stateViewer:      as(viewerA),
			stateUnanswered:  seeds(approverA, unanswered),
			stateAnswered:    seeds(approverA, answered),
			stateToWaive:     seeds(approverA, toWaive),
			stateToSupersede: seeds(ownerA, toSupersede),
		},
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
