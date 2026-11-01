package proposals

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/integrations"
)

const (
	defaultPage = 50
	maxPage     = 100
)

// Process runs one merged pull request end to end for one tenant. The tenant must be the one that
// installed the App, because Process trusts it. A comment already turned into a proposal at the
// same bytes is not sent again, so a redelivered webhook spends nothing.
func Process(ctx context.Context, db *sql.DB, complete CompleteFunc, tenant uuid.UUID, repo string, number int, comments []integrations.Comment) (int, Stats, error) {
	if tenant == uuid.Nil {
		return 0, Stats{}, errors.New("no tenant")
	}
	known, err := existingSources(ctx, db, tenant, repo, number)
	if err != nil {
		return 0, Stats{}, err
	}
	found, stats, err := Extract(ctx, complete, repo, number, comments, func(externalID string, digest [32]byte) bool {
		return known[sourceKey(externalID, digest[:])]
	})
	if err != nil {
		return 0, stats, err
	}
	created, err := insert(ctx, db, tenant, found)
	return created, stats, err
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

// Handler returns the inbox route, GET /v1/proposals. The binary does not serve it. The control
// plane mounts it with the tenant from the token. A missing tenant is 401 and runs no query. A
// query key tenant or tenant_id is 400 and runs no query. Another tenant's rows are never read.
func Handler(db *sql.DB, tenantFrom TenantFunc) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /v1/proposals", func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()
		for key := range query {
			if strings.EqualFold(key, "tenant") || strings.EqualFold(key, "tenant_id") {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid query"})
				return
			}
		}
		if tenantFrom == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		tenant, ok := tenantFrom(r)
		if !ok || tenant == uuid.Nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		limit := defaultPage
		if raw := query.Get("limit"); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed < 1 || parsed > maxPage {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid query"})
				return
			}
			limit = parsed
		}
		var before any
		if raw := query.Get("before"); raw != "" {
			parsed, err := uuid.Parse(raw)
			if err != nil {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid query"})
				return
			}
			before = parsed
		}
		items, err := inbox(r.Context(), db, tenant, before, limit)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"proposals": items})
	})
	return mux
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
			FROM proposals.proposal
			WHERE tenant_id = $1 AND ($2::uuid IS NULL OR id < $2::uuid)
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

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	encoder := json.NewEncoder(w)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(body)
}
