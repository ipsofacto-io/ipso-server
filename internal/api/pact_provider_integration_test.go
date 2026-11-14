//go:build integration && pact

package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
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
	"github.com/ipsofacto-io/ipso-server/internal/registry"
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

// The state of a baseline (IPSO-150, ADR-0121). A baseline needs the grandfather terms of its decision first, and it is
// recorded once for a decision and a repository, so the state seeds a decision with its terms and no baseline, and hands
// the id back. The session is a decision owner over the whole tenant, so it covers every scope of the decision.
const stateToBaseline = "tenant A holds a decision with grandfather terms and no baseline, and the session belongs to a decision owner"

// The states of the answer to a drafted check (IPSO-153, ADR-0118). Each seeds a decision and a check drafted for
// it, because a drafted check is decided once and the path names both. The session is an approver over the whole
// tenant, so it covers every scope of the decision.
const (
	stateCheckUnanswered = "tenant A holds a drafted check that nobody answered, and the session belongs to an approver"
	stateCheckAnswered   = "tenant A holds a drafted check that was answered, and the session belongs to an approver"
)

// The states of the export (IPSO-152, ADR-0115). Each one clears the exports of tenant A first, because the
// cooldown and the one-at-a-time rule of the API read them, and then seeds what it names. The session is the
// admin's: only an admin who is a person takes the export routes (ADR-0108, ADR-0111).
const (
	stateNoExport      = "tenant A holds no export, and the session belongs to an admin"
	statePendingExport = "tenant A holds a pending export, and the session belongs to an admin"
	stateReadyExport   = "tenant A holds a ready export, and the session belongs to an admin"
)

// The states of the premises page (IPSO-155, ADR-0119). A reason state seeds a decision and a fail on one of its premises,
// recorded the way the worker records it, and the cleared state clears that reason too. The session is a decision owner
// over the whole tenant, so it covers every scope of the decision. The host state seeds a row of the allowlist, and the
// session is the admin's, because only an admin changes the allowlist (ADR-0108).
const (
	statePremiseOpen    = "tenant A holds an open review reason, and the session belongs to a decision owner"
	statePremiseCleared = "tenant A holds a review reason that was cleared, and the session belongs to a decision owner"
	stateHostAllowed    = "tenant A holds an allowed host, and the session belongs to an admin"
)

// pactPremise is the premise every reason state names, and pactHost the host the allowlist states hold. A reason state
// seeds a fresh decision, so its reason is the only one open for that premise.
const (
	pactPremise = "tls-version"
	pactHost    = "status.example.com"
)

// pactRecipient is the age public key of the age documentation, the one the pact asks for an export with.
const pactRecipient = "age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p"

// resetExports deletes every export of tenant A and its parts, through the admin connection.
func (f *fixture) resetExports(ctx context.Context) error {
	for _, query := range []string{`DELETE FROM tenancy.export_part WHERE tenant_id = $1`, `DELETE FROM tenancy.export WHERE tenant_id = $1`} {
		if _, err := f.admin.ExecContext(ctx, query, tenantA); err != nil {
			return fmt.Errorf("clear the exports of tenant A: %w", err)
		}
	}
	return nil
}

// seedExport clears the exports of tenant A and adds one, pending or ready with one stored part, and returns its id.
func (f *fixture) seedExport(ctx context.Context, ready bool) (uuid.UUID, error) {
	if err := f.resetExports(ctx); err != nil {
		return uuid.Nil, err
	}
	var id uuid.UUID
	if !ready {
		if err := f.admin.QueryRowContext(ctx, `
			INSERT INTO tenancy.export (tenant_id, requested_by, recipient, expires_at)
			VALUES ($1, $2, $3, now() + interval '1 day') RETURNING id`,
			tenantA, f.callers[personA].Principal, pactRecipient).Scan(&id); err != nil {
			return uuid.Nil, fmt.Errorf("seed a pending export: %w", err)
		}
		return id, nil
	}
	part := []byte("a synthetic archive, which no key opens")
	sum := sha256.Sum256(part)
	if err := f.admin.QueryRowContext(ctx, `
		INSERT INTO tenancy.export (tenant_id, requested_by, recipient, state, finished_at, expires_at, bytes, parts, sha256)
		VALUES ($1, $2, $3, 'ready', now(), now() + interval '1 day', $4, 1, $5) RETURNING id`,
		tenantA, f.callers[personA].Principal, pactRecipient, len(part), sum[:]).Scan(&id); err != nil {
		return uuid.Nil, fmt.Errorf("seed a ready export: %w", err)
	}
	if _, err := f.admin.ExecContext(ctx, `INSERT INTO tenancy.export_part (tenant_id, export_id, seq, data) VALUES ($1, $2, 0, $3)`, tenantA, id, part); err != nil {
		return uuid.Nil, fmt.Errorf("seed the part of an export: %w", err)
	}
	return id, nil
}

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

// seedDecision adds version 1 of a decision in force from 2026-01-01 at the org scope, and returns its id. The body
// names the premises given, which a review reason needs, because a fail is recorded only for a premise on a current
// version.
func (f *fixture) seedDecision(ctx context.Context, slug string, premises ...string) (uuid.UUID, error) {
	id, err := uuid.NewV7()
	if err != nil {
		return uuid.Nil, err
	}
	body := map[string]any{"slug": slug, "title": slug}
	if len(premises) > 0 {
		list := make([]map[string]any, 0, len(premises))
		for _, premise := range premises {
			list = append(list, map[string]any{"id": premise})
		}
		body["premises"] = list
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return uuid.Nil, err
	}
	if _, err := pgtest.Exec(ctx, f.db, tenantA.String(), `
		INSERT INTO registry.decision_version (decision_id, version, tenant_id, body, scope_refs, valid_period)
		VALUES ($1, 1, $2, $3::jsonb, ARRAY[$4::uuid], $5::text::tstzrange)`,
		id, tenantA, string(raw), f.org, "[2026-01-01,)"); err != nil {
		return uuid.Nil, fmt.Errorf("seed the decision %s: %w", slug, err)
	}
	return id, nil
}

// seedCheckProposal adds a decision in force and a pending check drafted for it, and returns both ids. n makes the
// rule, and so the check, unique (the check_proposal_once constraint of migration 00012).
func (f *fixture) seedCheckProposal(ctx context.Context, n int64) (decision, check uuid.UUID, err error) {
	decision, err = f.seedDecision(ctx, "synthetic-checked-"+strconv.FormatInt(n, 10))
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}
	err = pgtest.Scan(ctx, f.db, tenantA.String(), `
		INSERT INTO proposals.check_proposal
			(tenant_id, decision_id, decision_version, spec, rego, rego_sha256, fixtures, fixtures_total, fixtures_passed, repaired, model_id, prompt_version)
		VALUES ($1, $2, 1, '{"rules":[]}', $3::text, sha256(convert_to($3::text, 'UTF8')), '[{}, {}]', 2, 2, false, 'm', 'p')
		RETURNING id`,
		[]any{tenantA, decision, "package p" + strconv.FormatInt(n, 10)}, &check)
	if err != nil {
		return uuid.Nil, uuid.Nil, fmt.Errorf("seed a drafted check: %w", err)
	}
	return decision, check, nil
}

// seedPremiseReason adds a decision in force and a fail on its premise tls-version, which opens a review reason as the
// worker does, and clears the reason with a human clearance when cleared is true. It returns the decision. n makes the
// decision, and so the reason, unique.
func (f *fixture) seedPremiseReason(ctx context.Context, n int64, cleared bool) (uuid.UUID, error) {
	decision, err := f.seedDecision(ctx, "synthetic-premised-"+strconv.FormatInt(n, 10), pactPremise)
	if err != nil {
		return uuid.Nil, err
	}
	opened, err := registry.RecordEvaluation(ctx, f.db, tenantA, registry.Evaluation{
		Ref: registry.PremiseRef{Decision: decision, ID: pactPremise}, Result: "fail",
		URL: "https://status.example.com/tls.json", Pointer: "/min", Expected: []byte(`"1.3"`), Observed: []byte(`"1.2"`),
		BodySHA256: bytes.Repeat([]byte{0xab}, 32),
	})
	if err != nil {
		return uuid.Nil, fmt.Errorf("record a fail of a premise: %w", err)
	}
	if !opened {
		return uuid.Nil, fmt.Errorf("a fail of the premise %s opened no reason", pactPremise)
	}
	if cleared {
		if _, err := pgtest.Exec(ctx, f.db, tenantA.String(), `
			INSERT INTO registry.premise_clearance (tenant_id, reason_id, kind)
			SELECT tenant_id, id, 'human' FROM registry.premise_reason
			WHERE tenant_id = $1 AND decision_id = $2 AND premise_id = $3`, tenantA, decision, pactPremise); err != nil {
			return uuid.Nil, fmt.Errorf("clear a review reason: %w", err)
		}
	}
	return decision, nil
}

// seedAllowedHost appends a row that allows pactHost to the allowlist of tenant A.
func (f *fixture) seedAllowedHost(ctx context.Context) error {
	if _, err := pgtest.Exec(ctx, f.db, tenantA.String(),
		`INSERT INTO registry.premise_host_allow (tenant_id, host, allowed) VALUES ($1, $2, true)`, tenantA, pactHost); err != nil {
		return fmt.Errorf("allow a host: %w", err)
	}
	return nil
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

	toBaseline := func(ctx context.Context, n int64) (models.ProviderStateResponse, error) {
		decision, err := f.seedDecision(ctx, "synthetic-baselined-"+strconv.FormatInt(n, 10))
		if err != nil {
			return nil, err
		}
		if _, err := pgtest.Exec(ctx, f.db, tenantA.String(), `
			INSERT INTO registry.grandfather_period (tenant_id, decision_id, valid_period)
			VALUES ($1, $2, tstzrange('2026-03-01T00:00:00Z'::timestamptz, NULL, '[)'))`, tenantA, decision); err != nil {
			return nil, fmt.Errorf("seed the grandfather terms: %w", err)
		}
		return models.ProviderStateResponse{"decisionId": decision.String()}, nil
	}
	unansweredCheck := func(ctx context.Context, n int64) (models.ProviderStateResponse, error) {
		decision, check, err := f.seedCheckProposal(ctx, n)
		if err != nil {
			return nil, err
		}
		return models.ProviderStateResponse{"decisionId": decision.String(), "checkProposalId": check.String()}, nil
	}
	answeredCheck := func(ctx context.Context, n int64) (models.ProviderStateResponse, error) {
		decision, check, err := f.seedCheckProposal(ctx, n)
		if err != nil {
			return nil, err
		}
		if _, err := pgtest.Exec(ctx, f.db, tenantA.String(),
			`INSERT INTO proposals.check_approval (tenant_id, proposal_id, approver_id, outcome) VALUES ($1, $2, $3, 'rejected')`,
			tenantA, check, f.callers[approverA].Principal); err != nil {
			return nil, fmt.Errorf("answer a drafted check: %w", err)
		}
		return models.ProviderStateResponse{"decisionId": decision.String(), "checkProposalId": check.String()}, nil
	}

	premiseReason := func(cleared bool) func(context.Context, int64) (models.ProviderStateResponse, error) {
		return func(ctx context.Context, n int64) (models.ProviderStateResponse, error) {
			decision, err := f.seedPremiseReason(ctx, n, cleared)
			if err != nil {
				return nil, err
			}
			return models.ProviderStateResponse{"decisionId": decision.String(), "premiseId": pactPremise}, nil
		}
	}
	allowedHost := func(ctx context.Context, _ int64) (models.ProviderStateResponse, error) {
		return nil, f.seedAllowedHost(ctx)
	}

	noExport := func(ctx context.Context, _ int64) (models.ProviderStateResponse, error) {
		return nil, f.resetExports(ctx)
	}
	exportOf := func(ready bool) func(context.Context, int64) (models.ProviderStateResponse, error) {
		return func(ctx context.Context, _ int64) (models.ProviderStateResponse, error) {
			id, err := f.seedExport(ctx, ready)
			if err != nil {
				return nil, err
			}
			return models.ProviderStateResponse{"exportId": id.String()}, nil
		}
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
			stateToBaseline:  seeds(ownerA, toBaseline),

			stateCheckUnanswered: seeds(approverA, unansweredCheck),
			stateCheckAnswered:   seeds(approverA, answeredCheck),

			statePremiseOpen:    seeds(ownerA, premiseReason(false)),
			statePremiseCleared: seeds(ownerA, premiseReason(true)),
			stateHostAllowed:    seeds(personA, allowedHost),

			stateNoExport:      seeds(personA, noExport),
			statePendingExport: seeds(personA, exportOf(false)),
			stateReadyExport:   seeds(personA, exportOf(true)),
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
