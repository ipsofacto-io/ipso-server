package proposals

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/llmgw"
	"github.com/ipsofacto-io/ipso-server/internal/registry"
)

const (
	// relaterQueueSize bounds the agent proposals waiting for an annotation. A full queue drops the next one.
	relaterQueueSize = 64
	// relaterJobTimeout bounds one annotation of an agent proposal: one model call, which the gateway gives
	// up to 600 seconds on a CPU route, and the reads around it. It matches the merged pull request lane.
	relaterJobTimeout = 15 * time.Minute
	// searchPage is how many decisions keyword search returns for one stem.
	searchPage = 100
)

// annotationTarget names the column of proposals.relation_annotation and its unique constraint for the
// queue of the proposal. Only pull request and agent proposals are annotated (ADR-0172).
func annotationTarget(queue Queue) (column, constraint string, err error) {
	switch queue {
	case QueueProposals:
		return "proposal_id", "relation_annotation_proposal_once", nil
	case QueueAgentProposals:
		return "agent_proposal_id", "relation_annotation_agent_proposal_once", nil
	default:
		return "", "", errors.New("only pull request and agent proposals are annotated")
	}
}

func (a Annotation) validate() error {
	if len(a.Hints) > maxRelationCandidates {
		return errors.New("an annotation holds at most five hints")
	}
	if n := utf8.RuneCountInString(a.Model); n == 0 || n > 200 || strings.TrimSpace(a.PromptVersion) == "" {
		return errors.New("an annotation names its model and prompt version")
	}
	seen := map[uuid.UUID]bool{}
	for _, hint := range a.Hints {
		if hint.DecisionID == uuid.Nil || hint.Version < 1 || seen[hint.DecisionID] {
			return errors.New("a hint names one decision version once")
		}
		seen[hint.DecisionID] = true
		if n := utf8.RuneCountInString(hint.Title); n == 0 || n > maxRelationTitleRunes {
			return errors.New("a hint holds the title the model read")
		}
		if hint.Relation != RelationDuplicates && hint.Relation != RelationSupersedes && hint.Relation != RelationConflicts {
			return errors.New("a hint holds one of three relations")
		}
	}
	return nil
}

// storeAnnotation writes the annotation of one proposal and its hints in one transaction, and reports
// whether it wrote one. An annotation with no hint is not stored, and a proposal keeps the first
// annotation it got. Nothing here touches the proposal row.
func storeAnnotation(ctx context.Context, db *sql.DB, tenant uuid.UUID, queue Queue, proposal uuid.UUID, annotation Annotation) (bool, error) {
	if tenant == uuid.Nil || proposal == uuid.Nil {
		return false, errors.New("an annotation needs a tenant and a proposal")
	}
	column, constraint, err := annotationTarget(queue)
	if err != nil {
		return false, err
	}
	if err := annotation.validate(); err != nil {
		return false, err
	}
	if len(annotation.Hints) == 0 {
		return false, nil
	}
	stored := false
	err = tenantTx(ctx, db, tenant, false, func(tx *sql.Tx) error {
		var id uuid.UUID
		err := tx.QueryRowContext(ctx, `
			INSERT INTO proposals.relation_annotation (tenant_id, `+column+`, model_id, prompt_version)
			VALUES ($1, $2, $3, $4)
			ON CONFLICT ON CONSTRAINT `+constraint+` DO NOTHING
			RETURNING id`, tenant, proposal, annotation.Model, annotation.PromptVersion).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("insert a relation annotation: %w", err)
		}
		for _, hint := range annotation.Hints {
			if _, err := tx.ExecContext(ctx, `
				INSERT INTO proposals.relation_hint (tenant_id, annotation_id, decision_id, decision_version, title, relation)
				VALUES ($1, $2, $3, $4, $5, $6)`, tenant, id, hint.DecisionID, hint.Version, hint.Title, string(hint.Relation)); err != nil {
				return fmt.Errorf("insert a relation hint: %w", err)
			}
		}
		stored = true
		return nil
	})
	return stored && err == nil, err
}

// inboxRelations is the annotation as the inbox serves it (ADR-0172).
type inboxRelations struct {
	ModelID       string         `json:"model_id"`
	PromptVersion string         `json:"prompt_version"`
	Decisions     []inboxHintRow `json:"decisions"`
}

type inboxHintRow struct {
	DecisionID      uuid.UUID `json:"decision_id"`
	DecisionVersion int       `json:"decision_version"`
	Title           string    `json:"title"`
	Relation        string    `json:"relation"`
}

// readRelations returns the annotations of the listed proposals of the queue, by proposal. Hints come
// in the order supersedes, conflicts, duplicates, then by decision id.
func readRelations(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, queue Queue, proposals []uuid.UUID) (map[uuid.UUID]*inboxRelations, error) {
	found := map[uuid.UUID]*inboxRelations{}
	if len(proposals) == 0 {
		return found, nil
	}
	column, _, err := annotationTarget(queue)
	if err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT a.`+column+`, a.model_id, a.prompt_version, h.decision_id, h.decision_version, h.title, h.relation
		FROM proposals.relation_annotation a
		JOIN proposals.relation_hint h ON h.tenant_id = a.tenant_id AND h.annotation_id = a.id
		WHERE a.tenant_id = $1 AND a.`+column+` = ANY($2::uuid[])
		ORDER BY a.`+column+`,
		         CASE h.relation WHEN 'supersedes' THEN 1 WHEN 'conflicts' THEN 2 ELSE 3 END,
		         h.decision_id`, tenant, proposals)
	if err != nil {
		return nil, fmt.Errorf("read relation annotations: %w", err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var proposal uuid.UUID
		var model, prompt string
		var hint inboxHintRow
		if err := rows.Scan(&proposal, &model, &prompt, &hint.DecisionID, &hint.DecisionVersion, &hint.Title, &hint.Relation); err != nil {
			return nil, fmt.Errorf("read relation annotations: %w", err)
		}
		entry := found[proposal]
		if entry == nil {
			entry = &inboxRelations{ModelID: model, PromptVersion: prompt}
			found[proposal] = entry
		}
		entry.Decisions = append(entry.Decisions, hint)
	}
	return found, rows.Err()
}

// RelateStats counts what the annotation of new proposals did. It holds no text (ADR-0012).
type RelateStats struct {
	// Annotated counts the proposals that got an annotation with at least one hint.
	Annotated int
	// Unrelated counts the proposals the model compared and related to no candidate, or that had none.
	Unrelated int
	// Failed counts the proposals whose annotation a gateway error, a budget refusal, a refused answer, or
	// the job's deadline stopped.
	Failed int
}

// relatedProposal is a proposal just stored, with the text the model compares.
type relatedProposal struct {
	id        uuid.UUID
	title     string
	statement string
}

// annotate compares each proposal with the decisions in force and stores what the model found. It never
// fails its caller: the proposals are stored already, and an annotation is a hint. A budget refusal or
// the end of the context stops the rest, because every later call would fail the same way.
func annotate(ctx context.Context, db *sql.DB, complete SchemaCompleteFunc, tenant uuid.UUID, queue Queue, found []relatedProposal, decisions []DecisionInForce) RelateStats {
	var stats RelateStats
	for i, proposal := range found {
		candidates := RelationCandidates(proposal.title, proposal.statement, decisions)
		if len(candidates) == 0 {
			stats.Unrelated++
			continue
		}
		annotation, err := Relate(ctx, complete, proposal.title, proposal.statement, candidates)
		if err == nil {
			var stored bool
			stored, err = storeAnnotation(ctx, db, tenant, queue, proposal.id, annotation)
			if err == nil && !stored {
				stats.Unrelated++
				continue
			}
		}
		if err != nil {
			stats.Failed++
			if errors.Is(err, llmgw.ErrBudget) || ctx.Err() != nil {
				stats.Failed += len(found) - i - 1
				return stats
			}
			continue
		}
		stats.Annotated++
	}
	return stats
}

// agentDecisions finds the decisions in force of the tenant that share a subject stem with an agent
// proposal, which names no repository. Keyword search reads each stem as a prefix under row-level
// security (ADR-0169), and annotate ranks the union with RelationCandidates.
func agentDecisions(ctx context.Context, db *sql.DB, tenant uuid.UUID, title, statement string, now time.Time) ([]DecisionInForce, error) {
	var all []registry.Decision
	for _, stem := range searchStems(title, statement) {
		found, err := registry.SearchDecisions(ctx, db, tenant, stem, now, now, registry.Page{Limit: searchPage})
		if err != nil {
			return nil, err
		}
		all = append(all, found...)
	}
	return InForce(all), nil
}

// Relater annotates agent proposals in the api role, after the proposal is stored (ADR-0172). Jobs wait
// in a bounded queue in memory and one worker runs them, so an agent that proposes in bulk cannot start
// more model calls than one at a time, and every call is charged to its tenant's budget. It runs only for
// a tenant that opts in with allow_agent_proposal_relations, because the agent writes the text that starts
// each call. A full queue, a restart, or a failed call leaves the proposal with no annotation, which is the
// state it had before.
type Relater struct {
	db       *sql.DB
	complete func(tenant uuid.UUID) SchemaCompleteFunc
	log      *slog.Logger
	now      func() time.Time
	jobs     chan relateJob
}

type relateJob struct {
	tenant   uuid.UUID
	proposal uuid.UUID
}

// NewRelater returns the lane that annotates agent proposals through the gateway.
func NewRelater(db *sql.DB, gateway *llmgw.Gateway, log *slog.Logger) *Relater {
	return newRelater(db, func(tenant uuid.UUID) SchemaCompleteFunc {
		return SchemaCompleteFunc(gateway.ForSchema(tenant))
	}, log)
}

func newRelater(db *sql.DB, complete func(tenant uuid.UUID) SchemaCompleteFunc, log *slog.Logger) *Relater {
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Relater{db: db, complete: complete, log: log, now: time.Now, jobs: make(chan relateJob, relaterQueueSize)}
}

// Enqueue asks for the annotation of one agent proposal of the tenant and never waits. It reports false
// when the queue is full and the proposal will have no annotation.
func (r *Relater) Enqueue(tenant, proposal uuid.UUID) bool {
	if tenant == uuid.Nil || proposal == uuid.Nil {
		return false
	}
	select {
	case r.jobs <- relateJob{tenant: tenant, proposal: proposal}:
		return true
	default:
		r.log.Warn("agent proposal annotation dropped: the queue is full", "tenant", tenant.String())
		return false
	}
}

// Run is the one worker of the lane. It works the queue until ctx ends. A job still running then is
// cancelled, and queued jobs are dropped.
func (r *Relater) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case job := <-r.jobs:
			r.work(ctx, job)
		}
	}
}

func (r *Relater) work(parent context.Context, job relateJob) {
	ctx, cancel := context.WithTimeout(parent, relaterJobTimeout)
	defer cancel()
	stats, err := func() (stats RelateStats, err error) {
		defer func() {
			if recovered := recover(); recovered != nil {
				err = errors.New("the annotation panicked")
			}
		}()
		return r.relateAgentProposal(ctx, job)
	}()
	if err != nil {
		r.log.ErrorContext(ctx, "agent proposal annotation failed", "tenant", job.tenant.String(), "error", err)
		return
	}
	r.log.InfoContext(ctx, "agent proposal annotated", "tenant", job.tenant.String(),
		"annotated", stats.Annotated, "unrelated", stats.Unrelated, "failed", stats.Failed)
}

// relateAgentProposal reads the proposal while it is still pending, has no annotation, and its tenant still
// opts in to the annotation of agent proposals, then compares it with the decisions in force of its tenant.
func (r *Relater) relateAgentProposal(ctx context.Context, job relateJob) (RelateStats, error) {
	var payload []byte
	err := tenantTx(ctx, r.db, job.tenant, true, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `
			SELECT p.payload FROM proposals.agent_proposal p
			WHERE p.tenant_id = $1 AND p.id = $2
			  AND NOT EXISTS (SELECT 1 FROM proposals.agent_approval a WHERE a.tenant_id = p.tenant_id AND a.proposal_id = p.id)
			  AND NOT EXISTS (SELECT 1 FROM proposals.relation_annotation n WHERE n.tenant_id = p.tenant_id AND n.agent_proposal_id = p.id)
			  AND EXISTS (SELECT 1 FROM llm.tenant_policy t WHERE t.tenant_id = p.tenant_id AND t.allow_agent_proposal_relations)`,
			job.tenant, job.proposal).Scan(&payload)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return RelateStats{}, nil
	}
	if err != nil {
		return RelateStats{}, err
	}
	var text struct {
		Title     string `json:"title"`
		Statement string `json:"statement"`
	}
	if err := json.Unmarshal(payload, &text); err != nil || strings.TrimSpace(text.Title) == "" {
		return RelateStats{Unrelated: 1}, nil
	}
	decisions, err := agentDecisions(ctx, r.db, job.tenant, text.Title, text.Statement, r.now())
	if err != nil {
		return RelateStats{}, err
	}
	found := []relatedProposal{{id: job.proposal, title: text.Title, statement: text.Statement}}
	return annotate(ctx, r.db, r.complete(job.tenant), job.tenant, QueueAgentProposals, found, decisions), nil
}
