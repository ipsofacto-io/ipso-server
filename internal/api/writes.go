package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/authz"
	"github.com/ipsofacto-io/ipso-server/internal/identity"
	"github.com/ipsofacto-io/ipso-server/internal/proposals"
	"github.com/ipsofacto-io/ipso-server/internal/registry"
)

// The write routes of ADR-0109. Every one is an action only a person takes. The guard has decided the role
// policy, covering every scope the call names, before a handler runs, and the handler reads the tenant and the
// principal from the caller the guard put in the context. A write and its entry in the action log are one
// transaction (identity.WithAction), so a write that cannot be logged does not run. A body names neither a
// tenant nor an approver, and a field the type does not have is a 400.
//
// A premise evaluation and a review reason are not here: the worker writes them (ADR-0053), and so are the
// waiver notices (ADR-0054). A person clears a reason and edits the allowlist.

type writeHandlers struct {
	db  *sql.DB
	log *slog.Logger
}

// writeRoutes are the operations that change the registry, behind the roles of ADR-0108.
func writeRoutes(db *sql.DB, log *slog.Logger) []route {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	h := &writeHandlers{db: db, log: log}
	return []route{
		{"POST /v1/scopes", "create_scope", authz.ScopeWrite, nil, targetsCreateScope, http.HandlerFunc(h.createScope)},
		{"PUT /v1/scopes/{id}/parent", "reparent_scope", authz.ScopeWrite, nil, targetsReparentScope, http.HandlerFunc(h.reparentScope)},
		{"DELETE /v1/scopes/{id}", "retire_scope", authz.ScopeWrite, nil, targetsScopeInPath, http.HandlerFunc(h.retireScope)},
		{"POST /v1/supersessions", "record_supersession", authz.DecisionSupersede, nil, targetsSupersession, http.HandlerFunc(h.recordSupersession)},
		{"POST /v1/decisions/{decisionID}/grandfather-period", "record_grandfather_period", authz.DecisionSupersede, nil, targetsDecisionInPath, http.HandlerFunc(h.recordGrandfatherPeriod)},
		{"POST /v1/decisions/{decisionID}/baselines", "record_baseline", authz.DecisionSupersede, nil, targetsDecisionInPath, http.HandlerFunc(h.recordBaseline)},
		{"POST /v1/waivers", "record_waiver", authz.WaiverRecord, nil, targetsWaiver, http.HandlerFunc(h.recordWaiver)},
		{"POST /v1/decisions/{decisionID}/premises/{premiseID}/clearance", "clear_premise_reason", authz.PremiseWrite, nil, targetsDecisionInPath, http.HandlerFunc(h.clearPremiseReason)},
		{"POST /v1/premise-hosts", "allow_premise_host", authz.AllowlistWrite, nil, nil, http.HandlerFunc(h.allowPremiseHost)},
		{"POST /v1/proposals/{id}/approval", "approve_proposal", authz.DecisionApprove, nil, targetsApproval, http.HandlerFunc(h.approveProposal)},
		{"POST /v1/agent-proposals/{id}/approval", "approve_agent_proposal", authz.DecisionApprove, nil, targetsApproval, http.HandlerFunc(h.approveAgentProposal)},
		{"POST /v1/decisions/{decisionID}/check-proposals/{id}/approval", "approve_check_proposal", authz.DecisionApprove, nil, targetsDecisionInPath, http.HandlerFunc(h.approveCheckProposal)},
	}
}

// write runs fn in one transaction with the entry of the action log, and answers with the status and the
// value fn returns, or with the refusal the store gave. A status of 204 sends no body. The subject fn
// returns names the ids it wrote and never a reason, a ticket or a body.
func (h *writeHandlers) write(w http.ResponseWriter, r *http.Request, op string, status int, fn func(ctx context.Context, tx *sql.Tx, caller Caller) (subject string, answer any, err error)) {
	caller, ok := personOf(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, errUnauthorized)
		return
	}
	var answer any
	ctx := r.Context()
	err := identity.WithAction(ctx, h.db, caller.Tenant, caller.Principal, "api."+op, func(tx *sql.Tx) (string, error) {
		subject, a, err := fn(ctx, tx, caller)
		answer = a
		return subject, err
	})
	if err != nil {
		writeStoreError(w, h.log, op, err)
		return
	}
	if status == http.StatusNoContent {
		setJSONHeaders(w.Header())
		w.WriteHeader(status)
		return
	}
	writeJSON(w, status, answer)
}

// errNoTarget is what a targets function returns for a request it cannot read, which the guard answers 400.
var errNoTarget = errors.New("the request names nothing to act on")

type createScopeRequest struct {
	ParentID *uuid.UUID `json:"parent_id"`
	Kind     string     `json:"kind"`
	Selector string     `json:"selector"`
}

// targetsCreateScope is the parent of the new node, or the tenant as a whole for an org, which has none.
func targetsCreateScope(_ map[string]string, body []byte) (named, error) {
	req, err := decodeBytes[createScopeRequest](body)
	if err != nil {
		return named{}, err
	}
	if req.ParentID == nil {
		return named{root: true}, nil
	}
	return named{scopes: []uuid.UUID{*req.ParentID}}, nil
}

func (h *writeHandlers) createScope(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeBody[createScopeRequest](w, r)
	if !ok {
		return
	}
	h.write(w, r, "create_scope", http.StatusCreated, func(ctx context.Context, tx *sql.Tx, caller Caller) (string, any, error) {
		scope, err := registry.CreateScope(ctx, tx, caller.Tenant, registry.NewScope{ParentID: req.ParentID, Kind: req.Kind, Selector: req.Selector})
		if err != nil {
			return "", nil, err
		}
		return "scope " + scope.ID.String(), scopeJSON{ID: scope.ID, ParentID: scope.ParentID, Kind: scope.Kind, Selector: scope.Selector}, nil
	})
}

type reparentRequest struct {
	ParentID uuid.UUID `json:"parent_id"`
}

// targetsReparentScope is the node and its new parent: a binding that covers the node but not the place it is
// moving to cannot move it there.
func targetsReparentScope(params map[string]string, body []byte) (named, error) {
	id, err := uuid.Parse(params["id"])
	if err != nil {
		return named{}, err
	}
	req, err := decodeBytes[reparentRequest](body)
	if err != nil {
		return named{}, err
	}
	if req.ParentID == uuid.Nil {
		return named{}, errNoTarget
	}
	return named{scopes: []uuid.UUID{id, req.ParentID}}, nil
}

func (h *writeHandlers) reparentScope(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	req, ok := decodeBody[reparentRequest](w, r)
	if !ok {
		return
	}
	h.write(w, r, "reparent_scope", http.StatusOK, func(ctx context.Context, tx *sql.Tx, caller Caller) (string, any, error) {
		scope, err := registry.ReparentScope(ctx, tx, caller.Tenant, id, req.ParentID)
		if err != nil {
			return "", nil, err
		}
		return fmt.Sprintf("scope %s under %s", scope.ID, req.ParentID), scopeJSON{ID: scope.ID, ParentID: scope.ParentID, Kind: scope.Kind, Selector: scope.Selector}, nil
	})
}

// targetsScopeInPath is the node the path names.
func targetsScopeInPath(params map[string]string, _ []byte) (named, error) {
	id, err := uuid.Parse(params["id"])
	if err != nil {
		return named{}, err
	}
	return named{scopes: []uuid.UUID{id}}, nil
}

func (h *writeHandlers) retireScope(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	h.write(w, r, "retire_scope", http.StatusNoContent, func(ctx context.Context, tx *sql.Tx, caller Caller) (string, any, error) {
		if err := registry.RetireScope(ctx, tx, caller.Tenant, id); err != nil {
			return "", nil, err
		}
		return "scope " + id.String(), nil, nil
	})
}

type supersessionRequest struct {
	From        uuid.UUID `json:"from_decision"`
	To          uuid.UUID `json:"to_decision"`
	EffectiveAt time.Time `json:"effective_at"`
}

type supersessionJSON struct {
	ID          uuid.UUID `json:"id"`
	From        uuid.UUID `json:"from_decision"`
	To          uuid.UUID `json:"to_decision"`
	EffectiveAt time.Time `json:"effective_at"`
}

// targetsSupersession is both decisions: replacing one decision with another changes what binds the scopes of
// each, so a binding has to cover every scope of both.
func targetsSupersession(_ map[string]string, body []byte) (named, error) {
	req, err := decodeBytes[supersessionRequest](body)
	if err != nil {
		return named{}, err
	}
	if req.From == uuid.Nil || req.To == uuid.Nil {
		return named{}, errNoTarget
	}
	return named{decisions: []uuid.UUID{req.From, req.To}}, nil
}

func (h *writeHandlers) recordSupersession(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeBody[supersessionRequest](w, r)
	if !ok {
		return
	}
	h.write(w, r, "record_supersession", http.StatusCreated, func(ctx context.Context, tx *sql.Tx, caller Caller) (string, any, error) {
		id, err := registry.RecordSupersession(ctx, tx, caller.Tenant, req.From, req.To, req.EffectiveAt)
		if err != nil {
			return "", nil, err
		}
		return fmt.Sprintf("supersession %s of %s by %s", id, req.From, req.To),
			supersessionJSON{ID: id, From: req.From, To: req.To, EffectiveAt: req.EffectiveAt}, nil
	})
}

// targetsDecisionInPath is the decision the path names, whose scopes the call acts on.
func targetsDecisionInPath(params map[string]string, _ []byte) (named, error) {
	id, err := uuid.Parse(params["decisionID"])
	if err != nil {
		return named{}, err
	}
	return named{decisions: []uuid.UUID{id}}, nil
}

type grandfatherRequest struct {
	ValidFrom  time.Time  `json:"valid_from"`
	ValidUntil *time.Time `json:"valid_until"`
}

type grandfatherJSON struct {
	DecisionID uuid.UUID  `json:"decision_id"`
	ValidFrom  time.Time  `json:"valid_from"`
	ValidUntil *time.Time `json:"valid_until"`
}

func (h *writeHandlers) recordGrandfatherPeriod(w http.ResponseWriter, r *http.Request) {
	decision, ok := pathID(w, r, "decisionID")
	if !ok {
		return
	}
	req, ok := decodeBody[grandfatherRequest](w, r)
	if !ok {
		return
	}
	h.write(w, r, "record_grandfather_period", http.StatusCreated, func(ctx context.Context, tx *sql.Tx, caller Caller) (string, any, error) {
		if err := registry.RecordGrandfatherPeriod(ctx, tx, caller.Tenant, decision, req.ValidFrom, req.ValidUntil); err != nil {
			return "", nil, err
		}
		return "grandfather period of " + decision.String(), grandfatherJSON{DecisionID: decision, ValidFrom: req.ValidFrom, ValidUntil: req.ValidUntil}, nil
	})
}

type baselineRequest struct {
	Repo         string   `json:"repo"`
	Fingerprints []string `json:"fingerprints"`
}

type baselineJSON struct {
	ID               uuid.UUID `json:"id"`
	DecisionID       uuid.UUID `json:"decision_id"`
	Repo             string    `json:"repo"`
	FingerprintCount int       `json:"fingerprint_count"`
}

func (h *writeHandlers) recordBaseline(w http.ResponseWriter, r *http.Request) {
	decision, ok := pathID(w, r, "decisionID")
	if !ok {
		return
	}
	req, ok := decodeBody[baselineRequest](w, r)
	if !ok {
		return
	}
	h.write(w, r, "record_baseline", http.StatusCreated, func(ctx context.Context, tx *sql.Tx, caller Caller) (string, any, error) {
		id, err := registry.RecordBaseline(ctx, tx, caller.Tenant, decision, req.Repo, req.Fingerprints)
		if err != nil {
			return "", nil, err
		}
		return fmt.Sprintf("baseline %s of %s", id, decision), baselineJSON{ID: id, DecisionID: decision, Repo: req.Repo, FingerprintCount: len(req.Fingerprints)}, nil
	})
}

type waiverRequest struct {
	DecisionID uuid.UUID `json:"decision_id"`
	ScopeID    uuid.UUID `json:"scope_id"`
	Reason     string    `json:"reason"`
	TicketRef  string    `json:"ticket_ref"`
	ValidFrom  time.Time `json:"valid_from"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// targetsWaiver is the one scope of the waiver (ADR-0108).
func targetsWaiver(_ map[string]string, body []byte) (named, error) {
	req, err := decodeBytes[waiverRequest](body)
	if err != nil {
		return named{}, err
	}
	if req.ScopeID == uuid.Nil {
		return named{}, errNoTarget
	}
	return named{scopes: []uuid.UUID{req.ScopeID}}, nil
}

func (h *writeHandlers) recordWaiver(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeBody[waiverRequest](w, r)
	if !ok {
		return
	}
	h.write(w, r, "record_waiver", http.StatusCreated, func(ctx context.Context, tx *sql.Tx, caller Caller) (string, any, error) {
		waiver, err := registry.RecordWaiver(ctx, tx, caller.Tenant, caller.Principal, registry.NewWaiver{
			DecisionID: req.DecisionID, ScopeID: req.ScopeID, Reason: req.Reason, TicketRef: req.TicketRef,
			ValidFrom: req.ValidFrom, ExpiresAt: req.ExpiresAt,
		})
		if err != nil {
			return "", nil, err
		}
		// The answer leaves out the reason and the approver, as the read does (ADR-0054).
		return fmt.Sprintf("waiver %s of %s on %s", waiver.ID, waiver.DecisionID, waiver.ScopeID),
			waiverJSON{ID: waiver.ID, DecisionID: waiver.DecisionID, ScopeID: waiver.ScopeID, TicketRef: waiver.TicketRef, ValidFrom: waiver.ValidFrom, ExpiresAt: waiver.ExpiresAt}, nil
	})
}

type clearanceRequest struct{}

type clearanceJSON struct {
	ID         uuid.UUID `json:"id"`
	DecisionID uuid.UUID `json:"decision_id"`
	PremiseID  string    `json:"premise_id"`
}

func (h *writeHandlers) clearPremiseReason(w http.ResponseWriter, r *http.Request) {
	decision, ok := pathID(w, r, "decisionID")
	if !ok {
		return
	}
	premise := r.PathValue("premiseID")
	if _, ok := decodeBody[clearanceRequest](w, r); !ok {
		return
	}
	h.write(w, r, "clear_premise_reason", http.StatusCreated, func(ctx context.Context, tx *sql.Tx, caller Caller) (string, any, error) {
		id, err := registry.ClearPremiseReason(ctx, tx, caller.Tenant, decision, premise)
		if err != nil {
			return "", nil, err
		}
		return fmt.Sprintf("clearance %s of premise %s of %s", id, premise, decision), clearanceJSON{ID: id, DecisionID: decision, PremiseID: premise}, nil
	})
}

type hostRequest struct {
	Host    string `json:"host"`
	Allowed *bool  `json:"allowed"`
}

type hostJSON struct {
	ID      uuid.UUID `json:"id"`
	Host    string    `json:"host"`
	Allowed bool      `json:"allowed"`
}

func (h *writeHandlers) allowPremiseHost(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeBody[hostRequest](w, r)
	if !ok {
		return
	}
	if req.Allowed == nil {
		writeError(w, http.StatusBadRequest, errInvalidQuery)
		return
	}
	allowed := *req.Allowed
	h.write(w, r, "allow_premise_host", http.StatusCreated, func(ctx context.Context, tx *sql.Tx, caller Caller) (string, any, error) {
		id, err := registry.AllowPremiseHost(ctx, tx, caller.Tenant, req.Host, allowed)
		if err != nil {
			return "", nil, err
		}
		return fmt.Sprintf("allowlist row %s", id), hostJSON{ID: id, Host: strings.ToLower(req.Host), Allowed: allowed}, nil
	})
}

type decisionRequest struct {
	Body      json.RawMessage `json:"body"`
	ScopeRefs []uuid.UUID     `json:"scope_refs"`
	ValidFrom time.Time       `json:"valid_from"`
}

type approvalRequest struct {
	Outcome  string           `json:"outcome"`
	Decision *decisionRequest `json:"decision"`
}

type approvalJSON struct {
	ID         uuid.UUID  `json:"id"`
	ProposalID uuid.UUID  `json:"proposal_id"`
	Outcome    string     `json:"outcome"`
	DecisionID *uuid.UUID `json:"decision_id"`
}

// targetsApproval is the scopes of the decision the approver wrote, since approving writes it and a binding
// has to cover every one of them. A rejection writes no decision and names no scope, so it acts on the
// tenant as a whole and only a binding over the whole tenant covers it.
func targetsApproval(_ map[string]string, body []byte) (named, error) {
	req, err := decodeBytes[approvalRequest](body)
	if err != nil {
		return named{}, err
	}
	switch req.Outcome {
	case proposals.OutcomeRejected:
		return named{root: true}, nil
	case proposals.OutcomeApproved:
		if req.Decision == nil || len(req.Decision.ScopeRefs) == 0 || len(req.Decision.ScopeRefs) > 100 {
			return named{}, errNoTarget
		}
		return named{scopes: req.Decision.ScopeRefs}, nil
	}
	return named{}, errNoTarget
}

func (h *writeHandlers) approveProposal(w http.ResponseWriter, r *http.Request) {
	h.approve(w, r, "approve_proposal", proposals.QueueProposals)
}

func (h *writeHandlers) approveAgentProposal(w http.ResponseWriter, r *http.Request) {
	h.approve(w, r, "approve_agent_proposal", proposals.QueueAgentProposals)
}

func (h *writeHandlers) approve(w http.ResponseWriter, r *http.Request, op string, queue proposals.Queue) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	req, ok := decodeBody[approvalRequest](w, r)
	if !ok {
		return
	}
	h.write(w, r, op, http.StatusCreated, func(ctx context.Context, tx *sql.Tx, caller Caller) (string, any, error) {
		var decision *registry.NewDecision
		if req.Decision != nil {
			decision = &registry.NewDecision{Body: req.Decision.Body, ScopeRefs: req.Decision.ScopeRefs, ValidFrom: req.Decision.ValidFrom}
		}
		approval, err := proposals.Approve(ctx, tx, caller.Tenant, caller.Principal, queue, id, req.Outcome, decision)
		if err != nil {
			return "", nil, err
		}
		out := approvalJSON{ID: approval.ID, ProposalID: approval.ProposalID, Outcome: approval.Outcome}
		subject := fmt.Sprintf("%s of proposal %s", approval.Outcome, approval.ProposalID)
		if approval.DecisionID != uuid.Nil {
			out.DecisionID = &approval.DecisionID
			subject += " as decision " + approval.DecisionID.String()
		}
		return subject, out, nil
	})
}

type checkApprovalRequest struct {
	Outcome string `json:"outcome"`
}

type checkApprovalJSON struct {
	ID         uuid.UUID `json:"id"`
	ProposalID uuid.UUID `json:"proposal_id"`
	Outcome    string    `json:"outcome"`
}

// approveCheckProposal answers a check an LLM drafted for a decision (ADR-0116). The path names the decision,
// so the guard covers every scope of the decision the check enforces with targetsDecisionInPath, for an
// approval and for a rejection alike, and the store requires that the drafted check belongs to that decision.
// It writes no decision, and the approver is the authenticated person.
func (h *writeHandlers) approveCheckProposal(w http.ResponseWriter, r *http.Request) {
	decision, ok := pathID(w, r, "decisionID")
	if !ok {
		return
	}
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	req, ok := decodeBody[checkApprovalRequest](w, r)
	if !ok {
		return
	}
	h.write(w, r, "approve_check_proposal", http.StatusCreated, func(ctx context.Context, tx *sql.Tx, caller Caller) (string, any, error) {
		approval, err := proposals.ApproveCheck(ctx, tx, caller.Tenant, caller.Principal, decision, id, req.Outcome)
		if err != nil {
			return "", nil, err
		}
		return fmt.Sprintf("%s of check proposal %s for decision %s", approval.Outcome, approval.ProposalID, decision),
			checkApprovalJSON{ID: approval.ID, ProposalID: approval.ProposalID, Outcome: approval.Outcome}, nil
	})
}
