//go:build integration

package chat

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/migrate"
	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
)

func TestMain(m *testing.M) {
	s, err := pgtest.Start(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer func() { _ = s.Terminate() }()
	pg = s
	os.Exit(m.Run())
}

var pg *pgtest.Server

func TestADigestNamesTheDecisionAndASecondRunSendsNothingNew(t *testing.T) {
	db := pg.NewDatabase(t)
	if _, err := migrate.Run(t.Context(), db.DSN(pgtest.Migrate)); err != nil {
		t.Fatal(err)
	}
	app := db.Open(t, pgtest.App)
	tenant := uuid.MustParse("00000000-0000-4000-8000-0000000000aa")
	pgtest.SeedEveryTable(t, app, tenant.String())
	var person uuid.UUID
	if err := pgtest.Scan(t.Context(), app, tenant.String(), `SELECT id FROM identity.principal WHERE tenant_id = $1::uuid AND kind = 'human'`, []any{tenant}, &person); err != nil {
		t.Fatal(err)
	}

	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i + 1)
	}
	store := NewStore(app, tenant, key)
	const webhook = "https://hooks.slack.com/services/T000/B000/secretvalue"
	if _, err := store.Put(t.Context(), person, Slack, webhook); err != nil {
		t.Fatal(err)
	}
	listed, err := store.List(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].Connector != Slack || listed[0].URL != webhook {
		t.Fatalf("list = %+v", listed)
	}
	var subject string
	if err := pgtest.Scan(t.Context(), app, tenant.String(), `SELECT subject FROM identity.action_log WHERE action = 'api.put_chat'`, nil, &subject); err != nil {
		t.Fatal(err)
	}
	if subject != "chat slack" || strings.Contains(subject, "secretvalue") {
		t.Fatalf("subject = %q", subject)
	}

	// The seed already delivered the notice to slack, so only the other connector still owes it.
	if text, ids, err := store.PendingWaivers(t.Context(), Slack); err != nil || text != "" || len(ids) != 0 {
		t.Fatalf("slack still owes a notice: %q %v %v", text, ids, err)
	}
	text, ids, err := store.PendingWaivers(t.Context(), Teams)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "expires today") || !strings.Contains(text, "OPS-1") || !strings.Contains(text, pgtest.DecisionKeep) {
		t.Fatalf("text = %q", text)
	}
	if strings.Contains(text, "Ada") || strings.Contains(text, "synthetic") || strings.Contains(text, "http") {
		t.Fatalf("text = %q", text)
	}
	if err := store.Record(t.Context(), Teams, KindWaiver, ids); err != nil {
		t.Fatal(err)
	}
	if text, ids, err = store.PendingWaivers(t.Context(), Teams); err != nil || text != "" || len(ids) != 0 {
		t.Fatalf("second run = %q %v %v", text, ids, err)
	}

	if _, err := pgtest.Exec(t.Context(), app, tenant.String(), `
		INSERT INTO registry.premise_evaluation
			(tenant_id, decision_id, premise_id, result, url, pointer, expected, observed, body_sha256)
		VALUES ($1::uuid, $2::uuid, 'tls-version', 'fail', 'https://secret.example/status', '', '1'::jsonb, '0'::jsonb, sha256('again'))`,
		tenant, pgtest.DecisionKeep); err != nil {
		t.Fatal(err)
	}
	var reason uuid.UUID
	if err := pgtest.Scan(t.Context(), app, tenant.String(), `
		INSERT INTO registry.premise_reason (tenant_id, decision_id, premise_id, evaluation_id)
		SELECT $1::uuid, $2::uuid, 'tls-version', id FROM registry.premise_evaluation
		WHERE tenant_id = $1::uuid AND url = 'https://secret.example/status'
		RETURNING id`, []any{tenant, pgtest.DecisionKeep}, &reason); err != nil {
		t.Fatal(err)
	}
	text, ids, err = store.PendingPremises(t.Context(), Teams)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "premise tls-version") || strings.Contains(text, "secret.example") || strings.Contains(text, "http") {
		t.Fatalf("text = %q", text)
	}
	if len(ids) != 1 || ids[0] != reason {
		t.Fatalf("ids = %v, want %s", ids, reason)
	}
	if err := store.Record(t.Context(), Teams, KindPremise, ids); err != nil {
		t.Fatal(err)
	}
	if text, ids, err = store.PendingPremises(t.Context(), Teams); err != nil || text != "" || len(ids) != 0 {
		t.Fatalf("second premise run = %q %v %v", text, ids, err)
	}

	if _, err := pgtest.Exec(t.Context(), app, tenant.String(), `
		INSERT INTO integrations.chat_destination (tenant_id, connector, url_sealed)
		VALUES ($1::uuid, 'teams', decode(repeat('cd', 29), 'hex'))`, tenant); err != nil {
		t.Fatal(err)
	}
	listed, err = store.List(t.Context())
	if !errors.Is(err, ErrInvalid) || len(listed) != 2 || listed[0].Connector != Slack || listed[0].URL != webhook || listed[1].Connector != Teams || listed[1].URL != "" {
		t.Fatalf("a bad teams row hid slack: %+v %v", listed, err)
	}
	if err := store.Delete(t.Context(), person, Slack); err != nil {
		t.Fatal(err)
	}
	listed, err = store.List(t.Context())
	if !errors.Is(err, ErrInvalid) || len(listed) != 1 || listed[0].Connector != Teams || listed[0].URL != "" {
		t.Fatalf("after delete = %+v %v", listed, err)
	}
	if err := store.Delete(t.Context(), person, Teams); err != nil {
		t.Fatal(err)
	}
	listed, err = store.List(t.Context())
	if err != nil || len(listed) != 0 {
		t.Fatalf("after both deletes = %+v %v", listed, err)
	}
	if err := store.Delete(t.Context(), person, Teams); err != ErrNotFound {
		t.Fatalf("delete missing = %v", err)
	}
}
