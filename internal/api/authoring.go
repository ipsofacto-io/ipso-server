package api

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/authz"
	"github.com/ipsofacto-io/ipso-server/internal/identity"
	"github.com/ipsofacto-io/ipso-server/internal/llmgw"
	"github.com/ipsofacto-io/ipso-server/internal/proposals"
	"github.com/ipsofacto-io/ipso-server/internal/registry"
	"github.com/ipsofacto-io/ipso-server/internal/verification"
	"github.com/ipsofacto-io/ipso/pkg/llmcheck"
	"github.com/ipsofacto-io/ipso/pkg/mcptools"
)

type authoringHandlers struct {
	db       *sql.DB
	policy   *authz.Policy
	gateway  *llmgw.Gateway
	log      *slog.Logger
	evictPin func(uuid.UUID)
}

func authoringWriteRoutes(db *sql.DB, policy *authz.Policy, log *slog.Logger, evictPin func(uuid.UUID)) []route {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	h := &authoringHandlers{db: db, policy: policy, log: log, evictPin: evictPin}
	return []route{
		{"POST /v1/human-proposals", "create_human_proposal", authz.HumanPropose, nil, nil, http.HandlerFunc(h.createHumanProposal)},
		{"PUT /v1/llm-policy", "set_llm_policy", authz.AllowlistWrite, nil, nil, http.HandlerFunc(h.setLLMPolicy)},
		{"PUT /v1/freshness-policies", "set_freshness_policy", authz.AllowlistWrite, nil, nil, http.HandlerFunc(h.setFreshnessPolicy)},
		{"POST /v1/agent-pins", "register_agent_pin", authz.PrincipalManage, nil, nil, http.HandlerFunc(h.registerAgentPin)},
		{"DELETE /v1/agent-pins/{id}", "revoke_agent_pin", authz.PrincipalManage, nil, nil, http.HandlerFunc(h.revokeAgentPin)},
	}
}

func (h *authoringHandlers) analyzeVerifiability(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantOf(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, errUnauthorized)
		return
	}
	req, ok := decodeBody[mcptools.VerifiabilityInput](w, r)
	if !ok {
		return
	}
	if strings.TrimSpace(req.Title) == "" || strings.TrimSpace(req.Statement) == "" {
		writeError(w, http.StatusBadRequest, errInvalidQuery)
		return
	}
	var complete llmgw.CompleteFunc
	if h.gateway != nil && h.db != nil {
		if pol, err := llmgw.GetTenantPolicy(r.Context(), h.db, tenant); err == nil && pol.AllowAuthoringAssist {
			complete = h.gateway.For(tenant)
		}
	}
	out, err := llmgw.AnalyzeVerifiability(r.Context(), tenant, complete, req)
	if errors.Is(err, llmgw.ErrBudget) {
		writeError(w, http.StatusTooManyRequests, errRateLimited)
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, errInvalidQuery)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *authoringHandlers) evaluateLLMCheck(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantOf(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, errUnauthorized)
		return
	}
	req, ok := decodeBody[llmgw.EvalRequest](w, r)
	if !ok {
		return
	}
	pol, err := llmgw.GetTenantPolicy(r.Context(), h.db, tenant)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errInternal)
		return
	}
	if !pol.AllowCheckEval {
		writeError(w, http.StatusForbidden, errForbidden)
		return
	}
	if h.gateway == nil {
		writeError(w, http.StatusServiceUnavailable, errUnavailable)
		return
	}
	out, err := llmgw.EvaluateCheck(r.Context(), h.gateway.For(tenant), req)
	if errors.Is(err, llmgw.ErrBudget) {
		writeError(w, http.StatusTooManyRequests, errRateLimited)
		return
	}
	if errors.Is(err, llmgw.ErrUnavailable) {
		writeError(w, http.StatusServiceUnavailable, errUnavailable)
		return
	}
	if err != nil {
		writeError(w, http.StatusBadRequest, errInvalidQuery)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *authoringHandlers) getLLMPolicy(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantOf(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, errUnauthorized)
		return
	}
	pol, err := llmgw.GetTenantPolicy(r.Context(), h.db, tenant)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errInternal)
		return
	}
	writeJSON(w, http.StatusOK, pol)
}

type llmPolicyRequest struct {
	AllowAuthoringAssist bool `json:"allow_authoring_assist"`
	AllowCheckEval       bool `json:"allow_check_eval"`
}

func (h *authoringHandlers) setLLMPolicy(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeBody[llmPolicyRequest](w, r)
	if !ok {
		return
	}
	wh := &writeHandlers{db: h.db, log: h.log}
	wh.write(w, r, "set_llm_policy", http.StatusOK, func(ctx context.Context, tx *sql.Tx, caller Caller) (string, any, error) {
		pol, err := llmgw.SetTenantPolicy(ctx, tx, caller.Tenant, req.AllowAuthoringAssist, req.AllowCheckEval)
		if err != nil {
			return "", nil, err
		}
		return fmt.Sprintf("llm_policy assist=%v eval=%v", pol.AllowAuthoringAssist, pol.AllowCheckEval), pol, nil
	})
}

func (h *authoringHandlers) listFreshnessPolicies(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantOf(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, errUnauthorized)
		return
	}
	items, err := verification.ListFreshnessPolicies(r.Context(), h.db, tenant)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errInternal)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"freshness_policies": items})
}

type freshnessPolicyRequest struct {
	Env        string `json:"env"`
	MaxAgeDays int    `json:"max_age_days"`
}

func (h *authoringHandlers) setFreshnessPolicy(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeBody[freshnessPolicyRequest](w, r)
	if !ok {
		return
	}
	wh := &writeHandlers{db: h.db, log: h.log}
	wh.write(w, r, "set_freshness_policy", http.StatusOK, func(ctx context.Context, tx *sql.Tx, caller Caller) (string, any, error) {
		pol, err := verification.SetFreshnessPolicy(ctx, tx, caller.Tenant, req.Env, req.MaxAgeDays)
		if errors.Is(err, verification.ErrInvalid) {
			return "", nil, registry.ErrInvalidQuery
		}
		if err != nil {
			return "", nil, err
		}
		return fmt.Sprintf("freshness_policy env=%q days=%d", pol.Env, pol.MaxAgeDays), pol, nil
	})
}

func (h *authoringHandlers) listAgentPins(w http.ResponseWriter, r *http.Request) {
	tenant, ok := tenantOf(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, errUnauthorized)
		return
	}
	pins, err := verification.ListAgentPins(r.Context(), h.db, tenant)
	if err != nil {
		writeError(w, http.StatusInternalServerError, errInternal)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"agent_pins": pins})
}

type registerAgentPinRequest struct {
	Name      string `json:"name"`
	Repo      string `json:"repo"`
	Env       string `json:"env"`
	PublicKey string `json:"public_key"`
}

func (h *authoringHandlers) registerAgentPin(w http.ResponseWriter, r *http.Request) {
	req, ok := decodeBody[registerAgentPinRequest](w, r)
	if !ok {
		return
	}
	wh := &writeHandlers{db: h.db, log: h.log}
	wh.write(w, r, "register_agent_pin", http.StatusCreated, func(ctx context.Context, tx *sql.Tx, caller Caller) (string, any, error) {
		pin, err := verification.RegisterAgentPin(ctx, tx, caller.Tenant, req.Name, req.Repo, req.Env, req.PublicKey)
		if errors.Is(err, verification.ErrInvalid) {
			return "", nil, registry.ErrInvalidQuery
		}
		if err != nil {
			return "", nil, err
		}
		return "agent_pin " + pin.ID.String(), pin, nil
	})
}

func (h *authoringHandlers) revokeAgentPin(w http.ResponseWriter, r *http.Request) {
	id, ok := pathID(w, r, "id")
	if !ok {
		return
	}
	revoked := false
	wh := &writeHandlers{db: h.db, log: h.log}
	wh.write(w, r, "revoke_agent_pin", http.StatusNoContent, func(ctx context.Context, tx *sql.Tx, caller Caller) (string, any, error) {
		removed, err := verification.RevokeAgentPin(ctx, tx, caller.Tenant, id)
		if err != nil {
			return "", nil, err
		}
		if !removed {
			return "", nil, registry.ErrNotFound
		}
		revoked = true
		return "agent_pin " + id.String(), nil, nil
	})
	if revoked && h.evictPin != nil {
		h.evictPin(id)
	}
}

type humanDraftCheck struct {
	Engine     string         `json:"engine"`
	Target     string         `json:"target,omitempty"`
	Ref        string         `json:"ref,omitempty"`
	Mode       string         `json:"mode,omitempty"`
	MaxAgeDays *int           `json:"max_age_days,omitempty"`
	LLMSpec    *llmcheck.Spec `json:"llm_spec,omitempty"`
}

type humanDraftPremise struct {
	ID        string `json:"id"`
	Statement string `json:"statement"`
	Every     int    `json:"every,omitempty"`
}

type createHumanProposalRequest struct {
	Title       string              `json:"title"`
	Statement   string              `json:"statement"`
	Context     string              `json:"context,omitempty"`
	Owner       string              `json:"owner,omitempty"`
	Criticality string              `json:"criticality,omitempty"`
	ReviewBy    string              `json:"review_by,omitempty"`
	ScopeRefs   []string            `json:"scope_refs"`
	Checks      []humanDraftCheck   `json:"checks,omitempty"`
	Premises    []humanDraftPremise `json:"premises,omitempty"`
	ApproveNow  bool                `json:"approve_now,omitempty"`
}

type createHumanProposalAnswer struct {
	ProposalID string `json:"proposal_id"`
	Status     string `json:"status"`
	DecisionID string `json:"decision_id,omitempty"`
	Slug       string `json:"slug,omitempty"`
}

var errApproveForbidden = errors.New("caller lacks decision.approve on target scopes")

func (h *authoringHandlers) createHumanProposal(w http.ResponseWriter, r *http.Request) {
	caller, ok := personOf(r)
	if !ok {
		writeError(w, http.StatusUnauthorized, errUnauthorized)
		return
	}
	req, ok := decodeBody[createHumanProposalRequest](w, r)
	if !ok {
		return
	}
	title := strings.TrimSpace(req.Title)
	statement := strings.TrimSpace(req.Statement)
	if title == "" || statement == "" || len(req.ScopeRefs) == 0 || len(req.ScopeRefs) > 100 {
		writeError(w, http.StatusBadRequest, errInvalidQuery)
		return
	}
	// Pre-validate any inline engine: llm specs (including allow+deny fixtures for mode: block).
	// Contextual approval requires an inline llm_spec for every engine: llm check so runners always
	// receive an approved spec in AcceptedChecks alongside decision version 1.
	for _, ch := range req.Checks {
		switch ch.Engine {
		case "opa", "semgrep", "checkov", "kyverno", "llm", "llm-advisory":
		default:
			writeError(w, http.StatusBadRequest, errInvalidQuery)
			return
		}
		if ch.Engine == "llm" && ch.LLMSpec == nil {
			writeError(w, http.StatusBadRequest, errInvalidQuery)
			return
		}
		if ch.Engine == "llm" && ch.LLMSpec != nil {
			raw, err := llmcheck.MarshalCanonical(*ch.LLMSpec)
			if err != nil {
				writeError(w, http.StatusBadRequest, errInvalidQuery)
				return
			}
			requireBlock := ch.Mode == "" || ch.Mode == "block"
			if _, err := llmcheck.ParseAndValidate(raw, ch.Target, requireBlock); err != nil {
				writeError(w, http.StatusBadRequest, errInvalidQuery)
				return
			}
		}
	}

	slug := slugify(title)
	payloadMap := map[string]any{
		"slug":        slug,
		"title":       title,
		"statement":   statement,
		"context":     strings.TrimSpace(req.Context),
		"owner":       nonEmptyText(req.Owner, "team:architecture"),
		"criticality": nonEmptyText(req.Criticality, "warning"),
		"scope_refs":  req.ScopeRefs,
	}
	if req.ReviewBy != "" {
		payloadMap["review_by"] = req.ReviewBy
	}
	if len(req.Checks) > 0 {
		payloadMap["checks"] = req.Checks
	}
	if len(req.Premises) > 0 {
		payloadMap["premises"] = req.Premises
	}
	payloadBytes, err := json.Marshal(payloadMap)
	if err != nil {
		writeError(w, http.StatusBadRequest, errInvalidQuery)
		return
	}

	ctx := r.Context()
	var answer createHumanProposalAnswer
	err = identity.WithAction(ctx, h.db, caller.Tenant, caller.Principal, "api.create_human_proposal", func(tx *sql.Tx) (string, error) {
		propID, err := proposals.InsertHumanProposal(ctx, tx, caller.Tenant, caller.Principal, payloadBytes)
		if err != nil {
			return "", err
		}
		if !req.ApproveNow {
			answer = createHumanProposalAnswer{
				ProposalID: propID.String(),
				Status:     "pending",
				Slug:       slug,
			}
			return "human_proposal " + propID.String(), nil
		}

		scopeIDs, err := resolveScopeRefsTx(ctx, tx, req.ScopeRefs)
		if err != nil || len(scopeIDs) == 0 {
			return "", registry.ErrInvalidQuery
		}
		if err := h.requireDecisionApprove(ctx, caller.Tenant, caller.Principal, scopeIDs); err != nil {
			return "", err
		}

		bodyBytes, err := buildEDRBodyFromHumanDraft(slug, req)
		if err != nil {
			return "", registry.ErrInvalidQuery
		}
		approval, err := proposals.Approve(ctx, tx, caller.Tenant, caller.Principal, proposals.QueueHumanProposals, propID, proposals.OutcomeApproved, &registry.NewDecision{
			Body:      bodyBytes,
			ScopeRefs: scopeIDs,
			ValidFrom: time.Now().UTC(),
		})
		if err != nil {
			return "", err
		}
		answer = createHumanProposalAnswer{
			ProposalID: propID.String(),
			Status:     "approved",
			DecisionID: approval.DecisionID.String(),
			Slug:       slug,
		}
		return fmt.Sprintf("human_proposal %s approved as decision %s", propID, approval.DecisionID), nil
	})
	if errors.Is(err, errApproveForbidden) {
		writeError(w, http.StatusForbidden, errForbidden)
		return
	}
	if err != nil {
		writeStoreError(w, h.log, "create_human_proposal", err)
		return
	}
	writeJSON(w, http.StatusCreated, answer)
}

func (h *authoringHandlers) requireDecisionApprove(ctx context.Context, tenant, principalID uuid.UUID, scopes []uuid.UUID) error {
	if h.policy == nil {
		return errApproveForbidden
	}
	p, err := identity.Get(ctx, h.db, tenant, principalID)
	if err != nil {
		return errApproveForbidden
	}
	unique := registry.UniqueIDs(scopes)
	var chains [][]uuid.UUID
	for chunk := range slices.Chunk(unique, authz.MaxTargets) {
		read, err := authz.Targets(ctx, h.db, tenant, chunk)
		if err != nil {
			return err
		}
		chains = append(chains, read...)
	}
	if len(chains) == 0 {
		return errApproveForbidden
	}
	for chunk := range slices.Chunk(chains, authz.MaxTargets) {
		ok, err := h.policy.Allow(ctx, authz.Input{
			Kind:    p.Kind,
			Grants:  p.Grants,
			Action:  authz.DecisionApprove,
			Targets: chunk,
		})
		if err != nil || !ok {
			return errApproveForbidden
		}
	}
	return nil
}

func resolveScopeRefsTx(ctx context.Context, tx *sql.Tx, refs []string) ([]uuid.UUID, error) {
	if len(refs) == 0 {
		return nil, registry.ErrInvalidQuery
	}
	var ids []uuid.UUID
	for _, raw := range refs {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		if id, err := uuid.Parse(trimmed); err == nil && id != uuid.Nil {
			ids = append(ids, id)
			continue
		}
		var kind, selector string
		if k, sel, hasPrefix := strings.Cut(trimmed, ":"); hasPrefix {
			kind, selector = strings.ToLower(strings.TrimSpace(k)), strings.TrimSpace(sel)
		} else if strings.Contains(trimmed, "/") {
			kind, selector = "repo", strings.ToLower(trimmed)
		} else {
			kind, selector = "org", strings.ToLower(trimmed)
		}
		var found uuid.UUID
		if err := tx.QueryRowContext(ctx, `
			SELECT id FROM registry.scope
			WHERE tenant_id = ipso.current_tenant() AND kind = $1 AND lower(selector) = lower($2)
			LIMIT 1`, kind, selector).Scan(&found); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil, registry.ErrInvalidQuery
			}
			return nil, err
		}
		ids = append(ids, found)
	}
	return registry.UniqueIDs(ids), nil
}

func buildEDRBodyFromHumanDraft(slug string, req createHumanProposalRequest) ([]byte, error) {
	status := "accepted"
	checksOut := make([]map[string]any, 0, len(req.Checks))
	for i, ch := range req.Checks {
		if ch.Engine != "llm-advisory" {
			status = "verified"
		}
		mode := nonEmptyText(ch.Mode, "warn")
		ref := strings.TrimSpace(ch.Ref)
		if ref == "" && ch.Engine == "llm" {
			ref = fmt.Sprintf(".ipso/checks/%s-%d.llm.json", slug, i)
		}
		item := map[string]any{
			"engine": ch.Engine,
			"mode":   mode,
			"status": "verified",
		}
		if ch.Engine == "llm-advisory" {
			item["status"] = "advisory"
			item["mode"] = "advise"
		}
		target := strings.TrimSpace(ch.Target)
		if target == "" && ch.LLMSpec != nil {
			target = strings.TrimSpace(ch.LLMSpec.Target)
		}
		if target != "" {
			item["target"] = target
		}
		if ref != "" {
			item["ref"] = ref
		}
		if ch.MaxAgeDays != nil {
			item["max_age_days"] = *ch.MaxAgeDays
		}
		checksOut = append(checksOut, item)
	}
	body := map[string]any{
		"edr_version": "1.1",
		"id":          newULIDNow(),
		"slug":        slug,
		"title":       strings.TrimSpace(req.Title),
		"status":      status,
		"criticality": nonEmptyText(req.Criticality, "warning"),
		"owner":       nonEmptyText(req.Owner, "team:architecture"),
		"decided_at":  time.Now().UTC().Format("2006-01-02"),
		"statement":   strings.TrimSpace(req.Statement),
	}
	if strings.TrimSpace(req.Context) != "" {
		body["context"] = strings.TrimSpace(req.Context)
	}
	if strings.TrimSpace(req.ReviewBy) != "" {
		body["review_by"] = strings.TrimSpace(req.ReviewBy)
	}
	if len(checksOut) > 0 {
		body["checks"] = checksOut
	}
	if len(req.Premises) > 0 {
		body["premises"] = req.Premises
	}
	return json.Marshal(body)
}

var nonSlugRunes = regexp.MustCompile(`[^a-z0-9]+`)

func slugify(title string) string {
	s := strings.ToLower(strings.TrimSpace(title))
	s = nonSlugRunes.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if len(s) > 80 {
		s = strings.Trim(s[:80], "-")
	}
	if s == "" {
		return "decision"
	}
	return s
}

func nonEmptyText(v, fallback string) string {
	if strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return fallback
}

const crockfordBase32 = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

func newULIDNow() string {
	var raw [16]byte
	ms := uint64(time.Now().UTC().UnixMilli())
	raw[0] = byte(ms >> 40)
	raw[1] = byte(ms >> 32)
	raw[2] = byte(ms >> 24)
	raw[3] = byte(ms >> 16)
	raw[4] = byte(ms >> 8)
	raw[5] = byte(ms)
	_, _ = rand.Read(raw[6:])

	var out [26]byte
	out[0] = crockfordBase32[(raw[0]&224)>>5]
	out[1] = crockfordBase32[raw[0]&31]
	out[2] = crockfordBase32[(raw[1]&248)>>3]
	out[3] = crockfordBase32[((raw[1]&7)<<2)|((raw[2]&192)>>6)]
	out[4] = crockfordBase32[(raw[2]&62)>>1]
	out[5] = crockfordBase32[((raw[2]&1)<<4)|((raw[3]&240)>>4)]
	out[6] = crockfordBase32[((raw[3]&15)<<1)|((raw[4]&128)>>7)]
	out[7] = crockfordBase32[(raw[4]&124)>>2]
	out[8] = crockfordBase32[((raw[4]&3)<<3)|((raw[5]&224)>>5)]
	out[9] = crockfordBase32[raw[5]&31]
	out[10] = crockfordBase32[(raw[6]&248)>>3]
	out[11] = crockfordBase32[((raw[6]&7)<<2)|((raw[7]&192)>>6)]
	out[12] = crockfordBase32[(raw[7]&62)>>1]
	out[13] = crockfordBase32[((raw[7]&1)<<4)|((raw[8]&240)>>4)]
	out[14] = crockfordBase32[((raw[8]&15)<<1)|((raw[9]&128)>>7)]
	out[15] = crockfordBase32[(raw[9]&124)>>2]
	out[16] = crockfordBase32[((raw[9]&3)<<3)|((raw[10]&224)>>5)]
	out[17] = crockfordBase32[raw[10]&31]
	out[18] = crockfordBase32[(raw[11]&248)>>3]
	out[19] = crockfordBase32[((raw[11]&7)<<2)|((raw[12]&192)>>6)]
	out[20] = crockfordBase32[(raw[12]&62)>>1]
	out[21] = crockfordBase32[((raw[12]&1)<<4)|((raw[13]&240)>>4)]
	out[22] = crockfordBase32[((raw[13]&15)<<1)|((raw[14]&128)>>7)]
	out[23] = crockfordBase32[(raw[14]&124)>>2]
	out[24] = crockfordBase32[((raw[14]&3)<<3)|((raw[15]&224)>>5)]
	out[25] = crockfordBase32[raw[15]&31]
	return string(out[:])
}
