package proposals

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/integrations"
	"github.com/ipsofacto-io/ipso-server/internal/llmgw"
	"github.com/ipsofacto-io/ipso-server/internal/registry"
	"github.com/ipsofacto-io/ipso/pkg/rulecheck"
)

const (
	defaultPage = 50
	maxPage     = 100
)

// Process runs one merged pull request end to end for one tenant. The tenant must be the one that
// installed the App, because Process trusts it. A comment already turned into a proposal at the
// same bytes is not sent again, so a redelivered webhook spends nothing.
func Process(ctx context.Context, db *sql.DB, complete CompleteFunc, canWrite WriteAccess, tenant uuid.UUID, repo string, number int, comments []integrations.Comment) (int, Stats, error) {
	if tenant == uuid.Nil {
		return 0, Stats{}, errors.New("no tenant")
	}
	known, err := existingSources(ctx, db, tenant, repo, number)
	if err != nil {
		return 0, Stats{}, err
	}
	found, stats, err := Extract(ctx, complete, canWrite, repo, number, comments, func(externalID string, digest [32]byte) bool {
		return known[sourceKey(externalID, digest[:])]
	})
	if err != nil || len(found) == 0 {
		return 0, stats, err
	}
	decided, err := knownDecisions(ctx, db, tenant, repo)
	if err != nil {
		return 0, stats, err
	}
	found, stats.Duplicates = Dedupe(found, decided)
	created, err := insert(ctx, db, tenant, found)
	return created, stats, err
}

// OnMerged returns the hook the webhooks service runs for a merged pull request (ADR-0103). It reads the
// discussion with the client the service limited to that one pull request, then runs Process through the
// gateway for the tenant the installation mapping gave. The same client asks GitHub who can write to the
// repository (ADR-0104). The tenant charged and written is that one and no other, and a hook with no tenant
// reads nothing. The log holds counts, never a comment, an answer, or a person (ADR-0012).
func OnMerged(db *sql.DB, gateway *llmgw.Gateway, log *slog.Logger) func(context.Context, integrations.MergedPullRequest) error {
	return func(ctx context.Context, pr integrations.MergedPullRequest) error {
		if pr.Tenant == uuid.Nil {
			return errors.New("no tenant")
		}
		comments, err := pr.Client.Discussion(ctx, pr.Number)
		if err != nil {
			return err
		}
		created, stats, err := Process(ctx, db, gateway.For(pr.Tenant), pr.Client.CanWrite, pr.Tenant, pr.Repo, pr.Number, comments)
		if err != nil {
			return err
		}
		log.Info("pull request discussion processed", "tenant", pr.Tenant.String(), "repo", pr.Repo, "pull_request", pr.Number,
			"created", created, "comments", stats.Comments, "untrusted", stats.Untrusted, "flagged", stats.Flagged,
			"sent", stats.Sent, "refused", stats.Refused, "duplicates", stats.Duplicates)
		return nil
	}
}

// knownDecisions returns the titles of the decisions in force for the repository, as the registry
// resolves them, and the text of the tenant's latest pending proposals, for Dedupe.
func knownDecisions(ctx context.Context, db *sql.DB, tenant uuid.UUID, repo string) ([]string, error) {
	now := time.Now()
	decisions, err := registry.Resolve(ctx, db, tenant, registry.Subject{Repo: repo}, now, now)
	if err != nil {
		return nil, err
	}
	var texts []string
	for _, decision := range decisions {
		var body struct {
			Title string `json:"title"`
		}
		if json.Unmarshal(decision.Body, &body) == nil && body.Title != "" {
			texts = append(texts, body.Title)
		}
	}
	err = tenantTx(ctx, db, tenant, true, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT concat_ws(' ', payload->>'title', payload->>'statement') FROM proposals.proposal
			WHERE tenant_id = $1 AND status = 'pending'
			ORDER BY id DESC LIMIT $2`, tenant, maxKnownProposals)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var text string
			if err := rows.Scan(&text); err != nil {
				return err
			}
			texts = append(texts, text)
		}
		return rows.Err()
	})
	return texts, err
}

func sourceKey(externalID string, digest []byte) string {
	return externalID + "/" + string(digest)
}

func existingSources(ctx context.Context, db *sql.DB, tenant uuid.UUID, repo string, number int) (map[string]bool, error) {
	known := map[string]bool{}
	err := tenantTx(ctx, db, tenant, true, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT external_id, source_sha256 FROM proposals.proposal
			WHERE tenant_id = $1 AND repo = $2 AND pr_number = $3`, tenant, repo, number)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var externalID string
			var digest []byte
			if err := rows.Scan(&externalID, &digest); err != nil {
				return err
			}
			known[sourceKey(externalID, digest)] = true
		}
		return rows.Err()
	})
	return known, err
}

// insert writes only the fields below. status, kind, origin, and trust_level take their defaults,
// and the table accepts no other value for them.
func insert(ctx context.Context, db *sql.DB, tenant uuid.UUID, found []Proposal) (int, error) {
	if len(found) == 0 {
		return 0, nil
	}
	created := 0
	err := tenantTx(ctx, db, tenant, false, func(tx *sql.Tx) error {
		for _, proposal := range found {
			payload, err := proposal.payload()
			if err != nil {
				return err
			}
			result, err := tx.ExecContext(ctx, `
				INSERT INTO proposals.proposal
					(tenant_id, payload, confidence, model_id, prompt_version, repo, pr_number,
					 external_id, source_url, source_sha256, candidate_index)
				VALUES ($1, $2::jsonb, $3, $4, $5, $6, $7, $8, $9, $10, $11)
				ON CONFLICT ON CONSTRAINT proposal_once DO NOTHING`,
				tenant, string(payload), proposal.Confidence, proposal.Model, proposal.PromptVersion, proposal.Repo,
				proposal.Number, proposal.ExternalID, proposal.SourceURL, proposal.SourceSHA256[:], proposal.CandidateIndex)
			if err != nil {
				return fmt.Errorf("insert a proposal: %w", err)
			}
			rows, err := result.RowsAffected()
			if err != nil {
				return err
			}
			created += int(rows)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return created, nil
}

func tenantTx(ctx context.Context, db *sql.DB, tenant uuid.UUID, readOnly bool, fn func(*sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: readOnly})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('ipso.tenant', $1, true)`, tenant.String()); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// TenantFunc returns the authenticated tenant. Handler reads no tenant from the request.
type TenantFunc func(*http.Request) (uuid.UUID, bool)

// Handler returns the review routes, GET /v1/proposals for decision proposals,
// GET /v1/agent-proposals for what AI coding agents proposed over MCP (ADR-0077), and
// GET /v1/check-proposals for drafted checks. The control plane API mounts them with the tenant from the
// token. A missing tenant is 401 and runs no query. A query
// key tenant or tenant_id is 400 and runs no query. Another tenant's rows are never read.
func Handler(db *sql.DB, tenantFrom TenantFunc) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/proposals", func(w http.ResponseWriter, r *http.Request) {
		tenant, before, limit, ok := readPage(w, r, tenantFrom)
		if !ok {
			return
		}
		items, err := inbox(r.Context(), db, tenant, before, limit)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"proposals": items})
	})
	mux.HandleFunc("GET /v1/agent-proposals", func(w http.ResponseWriter, r *http.Request) {
		tenant, before, limit, ok := readPage(w, r, tenantFrom)
		if !ok {
			return
		}
		items, err := agentInbox(r.Context(), db, tenant, before, limit)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"agent_proposals": items})
	})
	mux.HandleFunc("GET /v1/check-proposals", func(w http.ResponseWriter, r *http.Request) {
		tenant, before, limit, ok := readPage(w, r, tenantFrom)
		if !ok {
			return
		}
		items, err := checkInbox(r.Context(), db, tenant, before, limit)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"check_proposals": items})
	})
	return mux
}

// readPage reads the tenant and the page of a review request. When the request cannot be served,
// it writes the answer and returns false.
func readPage(w http.ResponseWriter, r *http.Request, tenantFrom TenantFunc) (uuid.UUID, any, int, bool) {
	query := r.URL.Query()
	for key := range query {
		if strings.EqualFold(key, "tenant") || strings.EqualFold(key, "tenant_id") {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid query"})
			return uuid.Nil, nil, 0, false
		}
	}
	if tenantFrom == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return uuid.Nil, nil, 0, false
	}
	tenant, ok := tenantFrom(r)
	if !ok || tenant == uuid.Nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return uuid.Nil, nil, 0, false
	}
	limit := defaultPage
	if raw := query.Get("limit"); raw != "" || query.Has("limit") {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed < 1 || parsed > maxPage {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid query"})
			return uuid.Nil, nil, 0, false
		}
		limit = parsed
	}
	var before any
	if raw := query.Get("before"); raw != "" || query.Has("before") {
		parsed, err := uuid.Parse(raw)
		if err != nil || parsed == uuid.Nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid query"})
			return uuid.Nil, nil, 0, false
		}
		before = parsed
	}
	return tenant, before, limit, true
}

type inboxItem struct {
	ID            uuid.UUID       `json:"id"`
	Kind          string          `json:"kind"`
	Origin        string          `json:"origin"`
	Status        string          `json:"status"`
	TrustLevel    string          `json:"trust_level"`
	Payload       json.RawMessage `json:"payload"`
	Confidence    float64         `json:"confidence"`
	ModelID       string          `json:"model_id"`
	PromptVersion string          `json:"prompt_version"`
	Repo          string          `json:"repo"`
	Number        int             `json:"pr_number"`
	SourceURL     string          `json:"source_url"`
	CapturedAt    time.Time       `json:"captured_at"`
}

func inbox(ctx context.Context, db *sql.DB, tenant uuid.UUID, before any, limit int) ([]inboxItem, error) {
	items := []inboxItem{}
	err := tenantTx(ctx, db, tenant, true, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT id, kind, origin, status, trust_level, payload, confidence, model_id, prompt_version,
			       repo, pr_number, source_url, lower(sys_period)
			FROM proposals.proposal p
			WHERE tenant_id = $1 AND ($2::uuid IS NULL OR id < $2::uuid)
			  AND NOT EXISTS (SELECT 1 FROM proposals.approval a WHERE a.tenant_id = p.tenant_id AND a.proposal_id = p.id)
			ORDER BY id DESC
			LIMIT $3`, tenant, before, limit)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var item inboxItem
			var payload []byte
			if err := rows.Scan(&item.ID, &item.Kind, &item.Origin, &item.Status, &item.TrustLevel, &payload, &item.Confidence,
				&item.ModelID, &item.PromptVersion, &item.Repo, &item.Number, &item.SourceURL, &item.CapturedAt); err != nil {
				return err
			}
			item.Payload = payload
			items = append(items, item)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return items, nil
}

type agentInboxItem struct {
	ID          uuid.UUID       `json:"id"`
	PrincipalID uuid.UUID       `json:"principal_id"`
	Status      string          `json:"status"`
	Payload     json.RawMessage `json:"payload"`
	CapturedAt  time.Time       `json:"captured_at"`
}

// agentInbox reads what agents proposed. principal_id names the agent, and its sponsor is in
// identity.principal.
func agentInbox(ctx context.Context, db *sql.DB, tenant uuid.UUID, before any, limit int) ([]agentInboxItem, error) {
	items := []agentInboxItem{}
	err := tenantTx(ctx, db, tenant, true, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT id, principal_id, status, payload, lower(sys_period)
			FROM proposals.agent_proposal p
			WHERE tenant_id = $1 AND ($2::uuid IS NULL OR id < $2::uuid)
			  AND NOT EXISTS (SELECT 1 FROM proposals.agent_approval a WHERE a.tenant_id = p.tenant_id AND a.proposal_id = p.id)
			ORDER BY id DESC
			LIMIT $3`, tenant, before, limit)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var item agentInboxItem
			var payload []byte
			if err := rows.Scan(&item.ID, &item.PrincipalID, &item.Status, &payload, &item.CapturedAt); err != nil {
				return err
			}
			item.Payload = payload
			items = append(items, item)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return items, nil
}

type checkInboxItem struct {
	ID              uuid.UUID       `json:"id"`
	Status          string          `json:"status"`
	DecisionID      uuid.UUID       `json:"decision_id"`
	DecisionVersion int             `json:"decision_version"`
	Engine          string          `json:"engine"`
	Target          string          `json:"target"`
	Spec            json.RawMessage `json:"spec"`
	Rego            string          `json:"rego"`
	Fixtures        json.RawMessage `json:"fixtures"`
	Repaired        bool            `json:"repaired"`
	ModelID         string          `json:"model_id"`
	PromptVersion   string          `json:"prompt_version"`
	CapturedAt      time.Time       `json:"captured_at"`
}

func checkInbox(ctx context.Context, db *sql.DB, tenant uuid.UUID, before any, limit int) ([]checkInboxItem, error) {
	items := []checkInboxItem{}
	err := tenantTx(ctx, db, tenant, true, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT id, status, decision_id, decision_version, engine, target, spec, rego, fixtures, repaired,
			       model_id, prompt_version, lower(sys_period)
			FROM proposals.check_proposal c
			WHERE tenant_id = $1 AND ($2::uuid IS NULL OR id < $2::uuid)
			  AND NOT EXISTS (SELECT 1 FROM proposals.check_approval a WHERE a.tenant_id = c.tenant_id AND a.proposal_id = c.id)
			ORDER BY id DESC
			LIMIT $3`, tenant, before, limit)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var item checkInboxItem
			var spec, fixtures []byte
			if err := rows.Scan(&item.ID, &item.Status, &item.DecisionID, &item.DecisionVersion, &item.Engine, &item.Target, &spec,
				&item.Rego, &fixtures, &item.Repaired, &item.ModelID, &item.PromptVersion, &item.CapturedAt); err != nil {
				return err
			}
			item.Spec, item.Fixtures = spec, fixtures
			items = append(items, item)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return items, nil
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(body)
}

// ProposeCheck stores a drafted check for review and reports whether it added a row. It writes the
// Rego again from the rule, compiles it, and runs every fixture before it writes, so a rule that
// fails one never reaches review, whoever built the Check. The row can only be pending.
func ProposeCheck(ctx context.Context, db *sql.DB, tenant uuid.UUID, check Check) (bool, error) {
	if tenant == uuid.Nil {
		return false, errors.New("no tenant")
	}
	if check.DecisionID == uuid.Nil || check.Version < 1 {
		return false, fmt.Errorf("%w: it names no decision", ErrCheckRequest)
	}
	if err := check.Spec.validate(); err != nil {
		return false, fmt.Errorf("%w: %w", ErrCheckRequest, err)
	}
	if err := validFixtures(check.Fixtures); err != nil {
		return false, err
	}
	rego := check.Rego()
	rule, err := rulecheck.Compile([]byte(rego))
	if err != nil {
		return false, err
	}
	if !Passes(rule, check.Fixtures) {
		return false, ErrCheckFailed
	}
	spec, err := json.Marshal(check.Spec)
	if err != nil {
		return false, err
	}
	fixtures, err := json.Marshal(check.Fixtures)
	if err != nil {
		return false, err
	}
	digest := sha256.Sum256([]byte(rego))
	created := false
	err = tenantTx(ctx, db, tenant, false, func(tx *sql.Tx) error {
		result, err := tx.ExecContext(ctx, `
			INSERT INTO proposals.check_proposal
				(tenant_id, decision_id, decision_version, spec, rego, rego_sha256, fixtures, fixtures_total,
				 fixtures_passed, repaired, model_id, prompt_version)
			VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7::jsonb, $8, $8, $9, $10, $11)
			ON CONFLICT ON CONSTRAINT check_proposal_once DO NOTHING`,
			tenant, check.DecisionID, check.Version, string(spec), rego, digest[:], string(fixtures), len(check.Fixtures),
			check.Repaired, check.Model, check.PromptVersion)
		if err != nil {
			return fmt.Errorf("insert a check proposal: %w", err)
		}
		rows, err := result.RowsAffected()
		created = rows == 1
		return err
	})
	return created && err == nil, err
}
