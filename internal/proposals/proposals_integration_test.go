//go:build integration

package proposals

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/integrations"
	"github.com/ipsofacto-io/ipso-server/internal/migrate"
	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
)

var server *pgtest.Server

func TestMain(m *testing.M) {
	os.Exit(runTests(m))
}

func runTests(m *testing.M) int {
	s, err := pgtest.Start(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = s.Terminate() }()
	server = s
	return m.Run()
}

// Synthetic tenants. No customer data is involved.
var (
	tenantA = uuid.MustParse("00000000-0000-4000-8000-00000000000a")
	tenantB = uuid.MustParse("00000000-0000-4000-8000-00000000000b")
)

func newDB(t *testing.T) *sql.DB {
	t.Helper()
	db := server.NewDatabase(t)
	if _, err := migrate.Run(t.Context(), db.DSN(pgtest.Migrate)); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return db.Open(t, pgtest.App)
}

type inboxAnswer struct {
	Proposals []struct {
		ID        uuid.UUID `json:"id"`
		Status    string    `json:"status"`
		Origin    string    `json:"origin"`
		Trust     string    `json:"trust_level"`
		SourceURL string    `json:"source_url"`
		Model     string    `json:"model_id"`
		Payload   struct {
			Title string `json:"title"`
		} `json:"payload"`
	} `json:"proposals"`
}

func readInbox(t *testing.T, db *sql.DB, tenant uuid.UUID, query string) inboxAnswer {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler := Handler(db, func(*http.Request) (uuid.UUID, bool) { return tenant, true })
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/proposals"+query, nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d: %s", recorder.Code, recorder.Body)
	}
	var answer inboxAnswer
	if err := json.Unmarshal(recorder.Body.Bytes(), &answer); err != nil {
		t.Fatal(err)
	}
	return answer
}

func TestProposalAppearsInTheInboxPending(t *testing.T) {
	db := newDB(t)
	llm := &fakeLLM{answer: oneCandidate}
	source := comment(1, "We decided to use Postgres.")
	created, _, err := Process(t.Context(), db, llm.complete, tenantA, testRepo, testNumber, []integrations.Comment{source})
	if err != nil || created != 1 {
		t.Fatalf("created %d err %v", created, err)
	}
	answer := readInbox(t, db, tenantA, "")
	if len(answer.Proposals) != 1 {
		t.Fatalf("inbox %+v", answer)
	}
	got := answer.Proposals[0]
	if got.Status != "pending" || got.Origin != "llm" || got.Trust != "untrusted" || got.SourceURL != source.URL || got.Payload.Title != "Use Postgres" || got.Model != "test-model" {
		t.Fatalf("proposal %+v", got)
	}
	if other := readInbox(t, db, tenantB, ""); len(other.Proposals) != 0 {
		t.Fatalf("tenant B read %+v", other)
	}
}

func TestRedeliveryAddsNothingAndSpendsNothing(t *testing.T) {
	db := newDB(t)
	llm := &fakeLLM{answer: oneCandidate}
	comments := []integrations.Comment{comment(1, "We decided to use Postgres.")}
	if _, _, err := Process(t.Context(), db, llm.complete, tenantA, testRepo, testNumber, comments); err != nil {
		t.Fatal(err)
	}
	created, _, err := Process(t.Context(), db, llm.complete, tenantA, testRepo, testNumber, comments)
	if err != nil || created != 0 || llm.calls != 1 {
		t.Fatalf("created %d err %v calls %d", created, err, llm.calls)
	}
}

func TestDatabaseCannotHoldAnApproval(t *testing.T) {
	db := newDB(t)
	llm := &fakeLLM{answer: oneCandidate}
	if _, _, err := Process(t.Context(), db, llm.complete, tenantA, testRepo, testNumber, []integrations.Comment{comment(1, "We decided to use Postgres.")}); err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()
	if _, err := db.ExecContext(ctx, `UPDATE proposals.proposal SET status = 'approved'`); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("update: %v", err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM proposals.proposal`); err == nil || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("delete: %v", err)
	}
	insert := func(status, link string) error {
		_, err := db.ExecContext(ctx, `
			INSERT INTO proposals.proposal
				(tenant_id, status, payload, confidence, model_id, prompt_version, repo, pr_number,
				 external_id, source_url, source_sha256, candidate_index)
			VALUES ($1, $2, '{}', 0.5, 'm', 'p', 'acme/payments', 8, 'pull-8', $3, $4, 0)`,
			tenantA, status, link, make([]byte, 32))
		return err
	}
	if err := insert("approved", "https://github.com/acme/payments/pull/8"); err == nil || !strings.Contains(err.Error(), "proposal_status") {
		t.Fatalf("approved row: %v", err)
	}
	if err := insert("pending", "https://evil.example/acme/payments/pull/8"); err == nil || !strings.Contains(err.Error(), "proposal_source_url") {
		t.Fatalf("foreign link: %v", err)
	}
}

func TestRedTeamEndToEndLeavesOnlyPending(t *testing.T) {
	db := newDB(t)
	raw, err := os.ReadFile("testdata/redteam.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus []struct {
		Body string `json:"body"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	comments := []integrations.Comment{comment(1000, "We decided to use Postgres.")}
	for i, item := range corpus {
		comments = append(comments, comment(i, item.Body))
	}
	llm := &fakeLLM{answer: oneCandidate}
	created, stats, err := Process(t.Context(), db, llm.complete, tenantA, testRepo, testNumber, comments)
	if err != nil {
		t.Fatal(err)
	}
	if created != 1 || stats.Flagged != len(corpus) || strings.Contains(llm.user, "approve") {
		t.Fatalf("created %d stats %+v user %q", created, stats, llm.user)
	}
	var notPending int
	if err := db.QueryRowContext(t.Context(), `SELECT count(*) FROM proposals.proposal WHERE status <> 'pending'`).Scan(&notPending); err != nil {
		t.Fatal(err)
	}
	if notPending != 0 {
		t.Fatalf("%d proposals are not pending", notPending)
	}
}

func TestInboxPages(t *testing.T) {
	db := newDB(t)
	llm := &fakeLLM{answer: oneCandidate}
	for i := range 3 {
		if _, _, err := Process(t.Context(), db, llm.complete, tenantA, testRepo, testNumber, []integrations.Comment{comment(i, "We decided to use Postgres.")}); err != nil {
			t.Fatal(err)
		}
	}
	first := readInbox(t, db, tenantA, "?limit=2")
	if len(first.Proposals) != 2 {
		t.Fatalf("first page %+v", first)
	}
	rest := readInbox(t, db, tenantA, "?limit=2&before="+first.Proposals[1].ID.String())
	if len(rest.Proposals) != 1 || rest.Proposals[0].ID == first.Proposals[1].ID {
		t.Fatalf("second page %+v", rest)
	}
	for _, query := range []string{"?limit=0", "?limit=101", "?limit=x", "?before=x"} {
		recorder := httptest.NewRecorder()
		Handler(db, func(*http.Request) (uuid.UUID, bool) { return tenantA, true }).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/proposals"+query, nil))
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("%s: status %d", query, recorder.Code)
		}
	}
}
