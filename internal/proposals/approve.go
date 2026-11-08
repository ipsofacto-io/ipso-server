package proposals

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/registry"
)

// Queue is the review queue a proposal sits in.
type Queue int

const (
	// QueueProposals holds the decisions drafted from pull request discussion (ADR-0062).
	QueueProposals Queue = iota + 1
	// QueueAgentProposals holds the decisions an agent proposed over MCP (ADR-0077).
	QueueAgentProposals
)

// The outcomes of a review.
const (
	OutcomeApproved = "approved"
	OutcomeRejected = "rejected"
)

// Approval is the outcome a person recorded for one proposal. DecisionID is nil for a rejection.
type Approval struct {
	ID         uuid.UUID
	ProposalID uuid.UUID
	Outcome    string
	DecisionID uuid.UUID
}

// Approve records the outcome of a person for one proposal (ADR-0076, ADR-0109). The row of the proposal
// stays pending, as its constraint says it must, and the approval is the outcome. An approval carries the
// decision the person wrote and writes its first version in the same transaction, so a decision version
// exists only through an approval, and a rejection carries none. The approver is the authenticated
// person, and the database refuses an approver that is not one. A proposal is decided once.
//
// The transaction is the caller's, READ COMMITTED with ipso.tenant set, and the tenant must be the
// authenticated one. The proposal must be in the tenant's queue, or the error is registry.ErrNotFound.
func Approve(ctx context.Context, tx *sql.Tx, tenant, approver uuid.UUID, queue Queue, proposal uuid.UUID, outcome string, decision *registry.NewDecision) (Approval, error) {
	if tenant == uuid.Nil || approver == uuid.Nil || proposal == uuid.Nil {
		return Approval{}, fmt.Errorf("%w: a tenant, an approver and a proposal are required", registry.ErrInvalidQuery)
	}
	var exists, insert string
	switch queue {
	case QueueProposals:
		exists = `SELECT true FROM proposals.proposal WHERE tenant_id = $1 AND id = $2`
		insert = `
			INSERT INTO proposals.approval (tenant_id, proposal_id, approver_id, outcome, decision_id)
			VALUES ($1, $2, $3, $4, $5)
			RETURNING id`
	case QueueAgentProposals:
		exists = `SELECT true FROM proposals.agent_proposal WHERE tenant_id = $1 AND id = $2`
		insert = `
			INSERT INTO proposals.agent_approval (tenant_id, proposal_id, approver_id, outcome, decision_id)
			VALUES ($1, $2, $3, $4, $5)
			RETURNING id`
	default:
		return Approval{}, fmt.Errorf("%w: no such queue", registry.ErrInvalidQuery)
	}
	if (outcome == OutcomeApproved) != (decision != nil) || (outcome != OutcomeApproved && outcome != OutcomeRejected) {
		return Approval{}, fmt.Errorf("%w: an approval carries the decision and a rejection carries none", registry.ErrInvalidQuery)
	}
	var found bool
	if err := tx.QueryRowContext(ctx, exists, tenant, proposal).Scan(&found); errors.Is(err, sql.ErrNoRows) {
		return Approval{}, registry.ErrNotFound
	} else if err != nil {
		return Approval{}, fmt.Errorf("read the proposal: %w", err)
	}
	out := Approval{ProposalID: proposal, Outcome: outcome}
	var decisionID any
	if decision != nil {
		id, err := registry.InsertDecision(ctx, tx, tenant, *decision)
		if err != nil {
			return Approval{}, err
		}
		out.DecisionID = id
		decisionID = id
	}
	if err := tx.QueryRowContext(ctx, insert, tenant, proposal, approver, outcome, decisionID).Scan(&out.ID); err != nil {
		return Approval{}, fmt.Errorf("record the approval: %w", err)
	}
	return out, nil
}
