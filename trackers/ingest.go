package trackers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/proposals"
)

// Ticket is one tracker event after the adapter has built the URL and mapped the status.
// Body is untrusted and is not stored.
type Ticket struct {
	Connector  string
	ExternalID string
	URL        string
	Title      string
	Body       string
	Status     string
	Labeled    bool
}

// CompleteFunc is one model call. text and model are the answer. A nil function stores no proposal.
type CompleteFunc func(ctx context.Context, system, user string, maxTokens int) (text, model string, err error)

// Ingest writes a pending proposal for a labeled decision ticket and sets the link status.
// A ticket status never approves a proposal. An answer the schema refuses stores nothing.
// Text that is already stored for this external id is not sent again.
func Ingest(ctx context.Context, db *sql.DB, tenant uuid.UUID, ticket Ticket, complete CompleteFunc) error {
	if db == nil || tenant == uuid.Nil || !KnownConnector(ticket.Connector) || !plainText(ticket.ExternalID, 200) || !AllowedURL(ticket.Connector, ticket.URL) {
		return ErrInvalid
	}
	if ticket.Status != "" && !KnownStatus(ticket.Status) {
		return ErrInvalid
	}
	var found []proposals.Proposal
	if ticket.Labeled && complete != nil {
		known, err := knownDigests(ctx, db, tenant, ticket.Connector, ticket.ExternalID)
		if err != nil {
			return err
		}
		extracted, _, err := proposals.ExtractTicket(ctx, func(ctx context.Context, system, user string, maxTokens int) (proposals.Completion, error) {
			text, model, err := complete(ctx, system, user, maxTokens)
			if err != nil {
				return proposals.Completion{}, err
			}
			return proposals.Completion{Text: text, Model: model}, nil
		}, ticket.ExternalID, ticket.URL, ticket.Title, ticket.Body, func(digest [32]byte) bool {
			_, ok := known[digest]
			return ok
		})
		if err != nil && !errors.Is(err, proposals.ErrAnswer) {
			return err
		}
		if err == nil && len(extracted) > 0 {
			texts, err := pendingTexts(ctx, db, tenant)
			if err != nil {
				return err
			}
			found, _ = proposals.Dedupe(extracted, texts)
		}
	}
	status := ticket.Status
	return tenantTx(ctx, db, tenant, false, func(tx *sql.Tx) error {
		kind, err := linkKind(ctx, tx, tenant, ticket.Connector, ticket.ExternalID)
		if err != nil {
			return err
		}
		if kind == "waiver" {
			if status == "" {
				return nil
			}
			return setStatus(ctx, tx, tenant, ticket.Connector, ticket.ExternalID, status)
		}
		// The link names the first stored candidate. The inbox lists every candidate until a person answers it.
		var proposal uuid.UUID
		for _, item := range found {
			id, err := insertProposal(ctx, tx, tenant, ticket.Connector, item)
			if err != nil {
				return err
			}
			if proposal == uuid.Nil {
				proposal = id
			}
		}
		if kind == "" && proposal != uuid.Nil {
			if status == "" {
				status = StatusOpen
			}
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO integrations.tracker_link
					(tenant_id, connector, external_id, url, kind, proposal_id, status)
				VALUES ($1, $2, $3, $4, 'decision', $5, $6)`,
				tenant, ticket.Connector, ticket.ExternalID, ticket.URL, proposal, status); err != nil {
				return err
			}
			return nil
		}
		if kind == "decision" && status != "" {
			return setStatus(ctx, tx, tenant, ticket.Connector, ticket.ExternalID, status)
		}
		return nil
	})
}

func knownDigests(ctx context.Context, db *sql.DB, tenant uuid.UUID, connector, externalID string) (map[[32]byte]struct{}, error) {
	known := map[[32]byte]struct{}{}
	err := tenantTx(ctx, db, tenant, true, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT source_sha256 FROM proposals.tracker_proposal
			WHERE tenant_id = $1 AND connector = $2 AND external_id = $3`, tenant, connector, externalID)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var digest []byte
			if err := rows.Scan(&digest); err != nil {
				return err
			}
			if len(digest) != 32 {
				continue
			}
			var key [32]byte
			copy(key[:], digest)
			known[key] = struct{}{}
		}
		return rows.Err()
	})
	return known, err
}

func pendingTexts(ctx context.Context, db *sql.DB, tenant uuid.UUID) ([]string, error) {
	var texts []string
	err := tenantTx(ctx, db, tenant, true, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT concat_ws(' ', p.payload->>'title', p.payload->>'statement')
			FROM proposals.tracker_proposal p
			WHERE p.tenant_id = $1
			  AND NOT EXISTS (
			    SELECT 1 FROM proposals.tracker_approval a
			    WHERE a.tenant_id = p.tenant_id AND a.proposal_id = p.id)
			ORDER BY p.id DESC
			LIMIT 2000`, tenant)
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

func linkKind(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, connector, externalID string) (string, error) {
	var kind string
	err := tx.QueryRowContext(ctx, `
		SELECT kind FROM integrations.tracker_link
		WHERE tenant_id = $1 AND connector = $2 AND external_id = $3`, tenant, connector, externalID).Scan(&kind)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return kind, err
}

func insertProposal(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, connector string, item proposals.Proposal) (uuid.UUID, error) {
	payload, err := json.Marshal(map[string]string{
		"title": item.Title, "statement": item.Statement, "rationale": item.Rationale,
	})
	if err != nil {
		return uuid.Nil, err
	}
	var id uuid.UUID
	err = tx.QueryRowContext(ctx, `
		INSERT INTO proposals.tracker_proposal
			(tenant_id, connector, payload, confidence, model_id, prompt_version,
			 external_id, source_url, source_sha256, candidate_index)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (tenant_id, connector, external_id, source_sha256, candidate_index) DO NOTHING
		RETURNING id`,
		tenant, connector, payload, item.Confidence, item.Model, item.PromptVersion,
		item.ExternalID, item.SourceURL, item.SourceSHA256[:], item.CandidateIndex).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, nil
	}
	return id, err
}
