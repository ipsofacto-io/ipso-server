//go:build integration

package proposals

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/integrations"
	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
	"github.com/ipsofacto-io/ipso-server/internal/registry"
)

// relationJudge answers a relation call by the titles it was sent: the relation byTitle names, or none.
// It keeps the titles of each call, so a test sees exactly what reached the model.
type relationJudge struct {
	byTitle map[string]Relation
	sent    [][]string
}

func (j *relationJudge) complete(_ context.Context, _, user string, _ int, _ json.RawMessage) (Completion, error) {
	lines := strings.Split(user, "\n")
	var message struct {
		Decisions []shownDecision `json:"decisions"`
	}
	if len(lines) != 3 || json.Unmarshal([]byte(lines[1]), &message) != nil {
		return Completion{}, errors.New("not a relation message")
	}
	answer := map[string]string{}
	titles := []string{}
	for _, decision := range message.Decisions {
		titles = append(titles, decision.Title)
		word := relationNone
		if relation, ok := j.byTitle[decision.Title]; ok {
			word = string(relation)
		}
		answer[decision.Ref] = word
	}
	j.sent = append(j.sent, titles)
	text, err := json.Marshal(answer)
	return Completion{Text: string(text), Model: "relation-model"}, err
}

func seedScope(t *testing.T, db *sql.DB, tenant uuid.UUID, selector string) uuid.UUID {
	t.Helper()
	var scope uuid.UUID
	if err := pgtest.Scan(t.Context(), db, tenant.String(), `
		INSERT INTO registry.scope (tenant_id, parent_id, kind, selector) VALUES ($1, NULL, 'org', $2) RETURNING id`,
		[]any{tenant, selector}, &scope); err != nil {
		t.Fatal(err)
	}
	return scope
}

func seedDecision(t *testing.T, db *sql.DB, tenant, scope uuid.UUID, title, statement string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := pgtest.Scan(t.Context(), db, tenant.String(), `
		INSERT INTO registry.decision_version (decision_id, version, tenant_id, body, scope_refs, valid_period)
		VALUES (gen_random_uuid(), 1, $1, jsonb_build_object('title', $3::text, 'statement', $4::text), ARRAY[$2::uuid], '[2026-01-01,)')
		RETURNING decision_id`, []any{tenant, scope, title, statement}, &id); err != nil {
		t.Fatal(err)
	}
	return id
}

func seedAgent(t *testing.T, db *sql.DB, tenant uuid.UUID) (person, agent uuid.UUID) {
	t.Helper()
	if err := pgtest.Scan(t.Context(), db, tenant.String(), `INSERT INTO identity.principal (tenant_id, kind, name) VALUES ($1, 'human', 'Ada') RETURNING id`, []any{tenant}, &person); err != nil {
		t.Fatal(err)
	}
	if err := pgtest.Scan(t.Context(), db, tenant.String(), `INSERT INTO identity.principal (tenant_id, kind, name, sponsor_id) VALUES ($1, 'agent', 'claude-code', $2) RETURNING id`, []any{tenant, person}, &agent); err != nil {
		t.Fatal(err)
	}
	return person, agent
}

func seedAgentProposal(t *testing.T, db *sql.DB, tenant, agent uuid.UUID, title, statement string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := pgtest.Scan(t.Context(), db, tenant.String(), `
		INSERT INTO proposals.agent_proposal (tenant_id, principal_id, payload)
		VALUES ($1, $2, jsonb_build_object('title', $3::text, 'statement', $4::text)) RETURNING id`,
		[]any{tenant, agent, title, statement}, &id); err != nil {
		t.Fatal(err)
	}
	return id
}

// inboxRelationsOf reads one inbox route and returns the relations of each item by its id.
func inboxRelationsOf(t *testing.T, db *sql.DB, tenant uuid.UUID, path string) map[uuid.UUID]*inboxRelations {
	t.Helper()
	recorder := httptest.NewRecorder()
	Handler(db, func(*http.Request) (uuid.UUID, bool) { return tenant, true }).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("%s: status %d: %s", path, recorder.Code, recorder.Body)
	}
	type item struct {
		ID        uuid.UUID       `json:"id"`
		Relations *inboxRelations `json:"relations"`
	}
	var answer struct {
		Proposals      []item `json:"proposals"`
		AgentProposals []item `json:"agent_proposals"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &answer); err != nil {
		t.Fatal(err)
	}
	out := map[uuid.UUID]*inboxRelations{}
	for _, entry := range append(answer.Proposals, answer.AgentProposals...) {
		out[entry.ID] = entry.Relations
	}
	return out
}

func countRows(t *testing.T, db *sql.DB, tenant uuid.UUID, table string) int {
	t.Helper()
	var n int
	if err := pgtest.Scan(t.Context(), db, tenant.String(), `SELECT count(*) FROM `+table, nil, &n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestProcessAnnotatesOnlyWithTheTenantsDecisions gives two tenants a decision with the same title. The
// pull request proposal of tenant A is compared with A's decision only, its hint names A's decision, and
// tenant B reads none of A's rows, through the inbox or the tables (ADR-0172).
func TestProcessAnnotatesOnlyWithTheTenantsDecisions(t *testing.T) {
	db := newDB(t)
	const mysql = "Use MySQL for new services"
	decisionA := seedDecision(t, db, tenantA, seedScope(t, db, tenantA, "acme"), mysql, "New services store their data in MySQL.")
	decisionB := seedDecision(t, db, tenantB, seedScope(t, db, tenantB, "acme"), mysql, "New services store their data in MySQL.")
	seedDecision(t, db, tenantA, seedScope(t, db, tenantA, "globex"), "Use Oracle for new services", "Another org's services use Oracle.")

	judge := &relationJudge{byTitle: map[string]Relation{mysql: RelationSupersedes}}
	llm := &fakeLLM{answer: oneCandidate}
	created, stats, err := Process(t.Context(), db, llm.complete, judge.complete, testWriters, tenantA, testRepo, testNumber, []integrations.Comment{comment(1, "We decided to use Postgres for new services.")})
	if err != nil || created != 1 || stats.Related != (RelateStats{Annotated: 1}) {
		t.Fatalf("created %d stats %+v err %v", created, stats, err)
	}
	if len(judge.sent) != 1 || len(judge.sent[0]) != 1 || judge.sent[0][0] != mysql {
		t.Fatalf("the model read %q", judge.sent)
	}
	relations := inboxRelationsOf(t, db, tenantA, "/v1/proposals")
	if len(relations) != 1 {
		t.Fatalf("inbox %+v", relations)
	}
	for _, got := range relations {
		if got == nil || got.ModelID != "relation-model" || got.PromptVersion != relationPromptVersion || len(got.Decisions) != 1 {
			t.Fatalf("relations %+v", got)
		}
		hint := got.Decisions[0]
		if hint.DecisionID != decisionA || hint.DecisionID == decisionB || hint.DecisionVersion != 1 || hint.Title != mysql || hint.Relation != "supersedes" {
			t.Fatalf("hint %+v", hint)
		}
	}
	if other := inboxRelationsOf(t, db, tenantB, "/v1/proposals"); len(other) != 0 {
		t.Fatalf("tenant B read %+v", other)
	}
	for _, table := range []string{"proposals.relation_annotation", "proposals.relation_hint"} {
		if n := countRows(t, db, tenantB, table); n != 0 {
			t.Fatalf("tenant B reads %d rows of %s", n, table)
		}
		if n := countRows(t, db, tenantA, table); n != 1 {
			t.Fatalf("tenant A reads %d rows of %s", n, table)
		}
	}
}

// TestAnAnnotationChangesNothingAboutItsProposal annotates a stored proposal and finds its row, its inbox
// place and its status as they were, and the approval works as before.
func TestAnAnnotationChangesNothingAboutItsProposal(t *testing.T) {
	db := newDB(t)
	scope := seedScope(t, db, tenantA, "acme")
	mysql := seedDecision(t, db, tenantA, scope, "Use MySQL for new services", "New services store their data in MySQL.")
	for i, statement := range []string{"We decided to use Postgres for new services.", "We decided to cache sessions in Redis."} {
		answer := oneCandidate
		if i == 1 {
			answer = `{"candidates":[{"source":0,"title":"Cache sessions in Redis","statement":"Sessions are cached in Redis.","rationale":"","confidence":0.8}]}`
		}
		if created, _, err := Process(t.Context(), db, (&fakeLLM{answer: answer}).complete, nil, testWriters, tenantA, testRepo, testNumber, []integrations.Comment{comment(i, statement)}); err != nil || created != 1 {
			t.Fatalf("seed %d: created %d err %v", i, created, err)
		}
	}
	row := func(id uuid.UUID) string {
		t.Helper()
		var text string
		if err := pgtest.Scan(t.Context(), db, tenantA.String(), `SELECT to_jsonb(p)::text FROM proposals.proposal p WHERE id = $1`, []any{id}, &text); err != nil {
			t.Fatal(err)
		}
		return text
	}
	before := readInbox(t, db, tenantA, "")
	if len(before.Proposals) != 2 || before.Proposals[1].Payload.Title != "Use Postgres" {
		t.Fatalf("inbox %+v", before)
	}
	postgres := before.Proposals[1].ID
	rowBefore := row(postgres)

	stored, err := storeAnnotation(t.Context(), db, tenantA, QueueProposals, postgres, Annotation{
		Model: "relation-model", PromptVersion: relationPromptVersion,
		Hints: []Hint{{DecisionID: mysql, Version: 1, Title: "Use MySQL for new services", Relation: RelationSupersedes}},
	})
	if err != nil || !stored {
		t.Fatalf("stored %v err %v", stored, err)
	}
	again, err := storeAnnotation(t.Context(), db, tenantA, QueueProposals, postgres, Annotation{
		Model: "other-model", PromptVersion: relationPromptVersion,
		Hints: []Hint{{DecisionID: mysql, Version: 1, Title: "Use MySQL for new services", Relation: RelationConflicts}},
	})
	if err != nil || again {
		t.Fatalf("a second annotation: stored %v err %v", again, err)
	}
	if rowAfter := row(postgres); rowAfter != rowBefore {
		t.Fatalf("the row changed:\n%s\n%s", rowBefore, rowAfter)
	}
	after := readInbox(t, db, tenantA, "")
	if len(after.Proposals) != 2 {
		t.Fatalf("inbox %+v", after)
	}
	for i := range after.Proposals {
		if after.Proposals[i] != before.Proposals[i] || after.Proposals[i].Status != "pending" {
			t.Fatalf("inbox place %d: %+v, was %+v", i, after.Proposals[i], before.Proposals[i])
		}
	}
	if got := inboxRelationsOf(t, db, tenantA, "/v1/proposals")[postgres]; got == nil || got.ModelID != "relation-model" || got.Decisions[0].Relation != "supersedes" {
		t.Fatalf("the first annotation is kept: %+v", got)
	}

	var approver uuid.UUID
	if err := pgtest.Scan(t.Context(), db, tenantA.String(), `INSERT INTO identity.principal (tenant_id, kind, name) VALUES ($1, 'human', 'Ada') RETURNING id`, []any{tenantA}, &approver); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(t.Context(), &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(t.Context(), `SELECT set_config('ipso.tenant', $1, true)`, tenantA.String()); err != nil {
		t.Fatal(err)
	}
	approval, err := Approve(t.Context(), tx, tenantA, approver, QueueProposals, postgres, OutcomeApproved, &registry.NewDecision{
		Body:      json.RawMessage(`{"slug":"use-postgres","title":"Use Postgres","statement":"The team uses Postgres for new services."}`),
		ScopeRefs: []uuid.UUID{scope},
		ValidFrom: time.Now(),
	})
	if err != nil || approval.DecisionID == uuid.Nil {
		t.Fatalf("approval %+v err %v", approval, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if left := readInbox(t, db, tenantA, ""); len(left.Proposals) != 1 || left.Proposals[0].ID == postgres {
		t.Fatalf("after the approval %+v", left)
	}
	if rowAfter := row(postgres); rowAfter != rowBefore {
		t.Fatalf("the approval changed the row:\n%s\n%s", rowBefore, rowAfter)
	}
}

// TestRelationTablesRefuseWhatTheyMustNotHold writes the tables as the application role, as a bug or an
// attacker with its connection could.
func TestRelationTablesRefuseWhatTheyMustNotHold(t *testing.T) {
	db := newDB(t)
	ctx := t.Context()
	_, agent := seedAgent(t, db, tenantA)
	agentProposal := seedAgentProposal(t, db, tenantA, agent, "Cache sessions in Redis", "")
	_, agentB := seedAgent(t, db, tenantB)
	foreign := seedAgentProposal(t, db, tenantB, agentB, "Cache sessions in Redis", "")
	if created, _, err := Process(ctx, db, (&fakeLLM{answer: oneCandidate}).complete, nil, testWriters, tenantA, testRepo, testNumber, []integrations.Comment{comment(1, "We decided to use Postgres.")}); err != nil || created != 1 {
		t.Fatalf("created %d err %v", created, err)
	}
	var proposal uuid.UUID
	if err := pgtest.Scan(ctx, db, tenantA.String(), `SELECT id FROM proposals.proposal`, nil, &proposal); err != nil {
		t.Fatal(err)
	}
	annotate := func(proposal, agentProposal any) error {
		_, err := pgtest.Exec(ctx, db, tenantA.String(), `
			INSERT INTO proposals.relation_annotation (tenant_id, proposal_id, agent_proposal_id, model_id, prompt_version)
			VALUES ($1, $2, $3, 'm', 'p')`, tenantA, proposal, agentProposal)
		return err
	}
	for name, c := range map[string]struct {
		proposal, agentProposal any
		refusal                 string
	}{
		"neither proposal":              {nil, nil, "relation_annotation_one_proposal"},
		"both proposals":                {proposal, agentProposal, "relation_annotation_one_proposal"},
		"another tenant's proposal":     {nil, foreign, "relation_annotation_agent_proposal"},
		"a proposal that never existed": {uuid.New(), nil, "relation_annotation_proposal"},
	} {
		if err := annotate(c.proposal, c.agentProposal); err == nil || !strings.Contains(err.Error(), c.refusal) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if err := annotate(proposal, nil); err != nil {
		t.Fatal(err)
	}
	if err := annotate(proposal, nil); err == nil || !strings.Contains(err.Error(), "relation_annotation_proposal_once") {
		t.Fatalf("a second annotation: %v", err)
	}
	if _, err := pgtest.Exec(ctx, db, tenantA.String(), `
		INSERT INTO proposals.relation_annotation (tenant_id, agent_proposal_id, model_id, prompt_version)
		VALUES ($1, $2, '', 'p')`, tenantA, agentProposal); err == nil || !strings.Contains(err.Error(), "relation_annotation_model") {
		t.Fatalf("an empty model: %v", err)
	}
	var annotation uuid.UUID
	if err := pgtest.Scan(ctx, db, tenantA.String(), `SELECT id FROM proposals.relation_annotation`, nil, &annotation); err != nil {
		t.Fatal(err)
	}
	hint := func(tenant uuid.UUID, version int, title, relation string) error {
		_, err := pgtest.Exec(ctx, db, tenant.String(), `
			INSERT INTO proposals.relation_hint (tenant_id, annotation_id, decision_id, decision_version, title, relation)
			VALUES ($1, $2, gen_random_uuid(), $3, $4, $5)`, tenant, annotation, version, title, relation)
		return err
	}
	for name, c := range map[string]struct {
		version         int
		title, relation string
		refusal         string
	}{
		"an approval":      {1, "T", "approves", "relation_hint_relation"},
		"none":             {1, "T", "none", "relation_hint_relation"},
		"version 0":        {0, "T", "conflicts", "relation_hint_version"},
		"no title":         {1, "", "conflicts", "relation_hint_title"},
		"a title too long": {1, strings.Repeat("t", 201), "conflicts", "relation_hint_title"},
	} {
		if err := hint(tenantA, c.version, c.title, c.relation); err == nil || !strings.Contains(err.Error(), c.refusal) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if err := hint(tenantB, 1, "T", "conflicts"); err == nil || !strings.Contains(err.Error(), "relation_hint_annotation") {
		t.Fatalf("tenant B hints on tenant A's annotation: %v", err)
	}
	if err := hint(tenantA, 1, "T", "conflicts"); err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`UPDATE proposals.relation_annotation SET model_id = 'x'`,
		`DELETE FROM proposals.relation_annotation`,
		`UPDATE proposals.relation_hint SET relation = 'duplicates'`,
		`DELETE FROM proposals.relation_hint`,
	} {
		if _, err := pgtest.Exec(ctx, db, tenantA.String(), statement); err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Fatalf("%s: %v", statement, err)
		}
	}
}

// setAgentRelations stores the tenant and its opt-in to the annotation of agent proposals (ADR-0172).
func setAgentRelations(t *testing.T, db *sql.DB, tenant uuid.UUID, on bool) {
	t.Helper()
	if _, err := pgtest.Exec(t.Context(), db, tenant.String(), `
		INSERT INTO tenancy.tenant (tenant_id, name) VALUES ($1, 'synthetic tenant') ON CONFLICT DO NOTHING`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := pgtest.Exec(t.Context(), db, tenant.String(), `
		INSERT INTO llm.tenant_policy (tenant_id, allow_agent_proposal_relations) VALUES ($1, $2)
		ON CONFLICT (tenant_id) DO UPDATE SET allow_agent_proposal_relations = $2`, tenant, on); err != nil {
		t.Fatal(err)
	}
}

// TestRelaterAnnotatesAnAgentProposalOnce runs the lane of the api role against PostgreSQL: it calls the
// model only while the tenant opts in, keyword search finds the tenant's decisions under row-level
// security, the hint reaches the agent inbox, and a proposal already annotated or already decided gets no
// second call.
func TestRelaterAnnotatesAnAgentProposalOnce(t *testing.T) {
	db := newDB(t)
	const memcached = "Cache sessions in Memcached"
	decisionA := seedDecision(t, db, tenantA, seedScope(t, db, tenantA, "acme"), memcached, "Sessions are cached in Memcached.")
	seedDecision(t, db, tenantB, seedScope(t, db, tenantB, "acme"), memcached, "Sessions are cached in Memcached.")
	person, agent := seedAgent(t, db, tenantA)
	proposal := seedAgentProposal(t, db, tenantA, agent, "Cache sessions in Redis", "Sessions are cached in Redis, not Memcached.")
	decided := seedAgentProposal(t, db, tenantA, agent, "Cache sessions in Valkey", "Sessions are cached in Valkey.")
	if _, err := pgtest.Exec(t.Context(), db, tenantA.String(), `
		INSERT INTO proposals.agent_approval (tenant_id, proposal_id, approver_id, outcome) VALUES ($1, $2, $3, 'rejected')`,
		tenantA, decided, person); err != nil {
		t.Fatal(err)
	}

	judge := &relationJudge{byTitle: map[string]Relation{memcached: RelationSupersedes}}
	relater := newRelater(db, func(tenant uuid.UUID) SchemaCompleteFunc {
		if tenant != tenantA {
			t.Errorf("the call is charged to %s", tenant)
		}
		return judge.complete
	}, nil)
	// A tenant that has not opted in, or has opted out since the job was queued, gets no call.
	job := relateJob{tenant: tenantA, proposal: proposal}
	if stats, err := relater.relateAgentProposal(t.Context(), job); err != nil || stats != (RelateStats{}) {
		t.Fatalf("without a policy: stats %+v err %v", stats, err)
	}
	setAgentRelations(t, db, tenantA, false)
	if stats, err := relater.relateAgentProposal(t.Context(), job); err != nil || stats != (RelateStats{}) || len(judge.sent) != 0 {
		t.Fatalf("opted out: stats %+v err %v, %d calls", stats, err, len(judge.sent))
	}
	setAgentRelations(t, db, tenantA, true)
	stats, err := relater.relateAgentProposal(t.Context(), job)
	if err != nil || stats != (RelateStats{Annotated: 1}) {
		t.Fatalf("stats %+v err %v", stats, err)
	}
	if len(judge.sent) != 1 || len(judge.sent[0]) != 1 || judge.sent[0][0] != memcached {
		t.Fatalf("the model read %q", judge.sent)
	}
	got := inboxRelationsOf(t, db, tenantA, "/v1/agent-proposals")[proposal]
	if got == nil || got.ModelID != "relation-model" || len(got.Decisions) != 1 || got.Decisions[0].DecisionID != decisionA || got.Decisions[0].Relation != "supersedes" {
		t.Fatalf("relations %+v", got)
	}
	for name, job := range map[string]relateJob{
		"annotated":        {tenant: tenantA, proposal: proposal},
		"decided":          {tenant: tenantA, proposal: decided},
		"another tenant's": {tenant: tenantB, proposal: proposal},
	} {
		if stats, err := relater.relateAgentProposal(t.Context(), job); err != nil || stats != (RelateStats{}) {
			t.Fatalf("%s: stats %+v err %v", name, stats, err)
		}
	}
	if len(judge.sent) != 1 {
		t.Fatalf("%d calls", len(judge.sent))
	}
	if n := countRows(t, db, tenantB, "proposals.relation_annotation"); n != 0 {
		t.Fatalf("tenant B reads %d annotations", n)
	}
}

// TestRelaterRunWorksTheQueue runs the lane as the api role does: a job enqueued while Run works gets its
// annotation, and Run returns when its context ends.
func TestRelaterRunWorksTheQueue(t *testing.T) {
	db := newDB(t)
	const memcached = "Cache sessions in Memcached"
	seedDecision(t, db, tenantA, seedScope(t, db, tenantA, "acme"), memcached, "Sessions are cached in Memcached.")
	_, agent := seedAgent(t, db, tenantA)
	proposal := seedAgentProposal(t, db, tenantA, agent, "Cache sessions in Redis", "Sessions are cached in Redis, not Memcached.")
	setAgentRelations(t, db, tenantA, true)
	judge := &relationJudge{byTitle: map[string]Relation{memcached: RelationSupersedes}}
	relater := newRelater(db, func(uuid.UUID) SchemaCompleteFunc { return judge.complete }, nil)

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		relater.Run(ctx)
		close(done)
	}()
	if !relater.Enqueue(tenantA, proposal) {
		t.Fatal("the queue refused the job")
	}
	deadline := time.Now().Add(30 * time.Second)
	for countRows(t, db, tenantA, "proposals.relation_annotation") == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the lane stored no annotation")
		}
		time.Sleep(50 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return when its context ended")
	}
	if got := inboxRelationsOf(t, db, tenantA, "/v1/agent-proposals")[proposal]; got == nil || len(got.Decisions) != 1 {
		t.Fatalf("relations %+v", got)
	}
}
