//go:build integration

package identity_test

import (
	"bytes"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ipsofacto-io/ipso-server/internal/identity"
	"github.com/ipsofacto-io/ipso-server/internal/migrate"
	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
)

// roles holds one migrated database through the three roles the chain has to hold against: the
// application role, the owner of the schema, and a superuser, which stands for whoever can reach the
// files or the console.
type roles struct {
	app, owner, admin *sql.DB
}

func chained(t *testing.T) roles {
	t.Helper()
	db := server.NewDatabase(t)
	if _, err := migrate.Run(t.Context(), db.DSN(pgtest.Migrate)); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return roles{app: db.Open(t, pgtest.App), owner: db.Open(t, pgtest.Migrate), admin: db.Open(t, pgtest.Admin)}
}

func sqlState(err error) string {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg.Code
	}
	return ""
}

// record writes n entries for the tenant, one by one, as the application does.
func record(t *testing.T, db *sql.DB, tenant, person uuid.UUID, n int) {
	t.Helper()
	for i := 1; i <= n; i++ {
		if _, err := identity.RecordAction(t.Context(), db, tenant, person, "api.record_waiver", fmt.Sprintf("waiver %d", i)); err != nil {
			t.Fatal(err)
		}
	}
}

func verify(t *testing.T, db *sql.DB, tenant uuid.UUID) identity.LogReport {
	t.Helper()
	report, err := identity.VerifyLog(t.Context(), db, tenant)
	if err != nil {
		t.Fatal(err)
	}
	return report
}

// asReplica runs statements as the role of db with triggers off, the way an operator or an attacker with
// a console skips the guards of the table. The statements belong to the caller.
func asReplica(t *testing.T, db *sql.DB, statements ...string) {
	t.Helper()
	tx, err := db.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(t.Context(), `SET LOCAL session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	for _, statement := range statements {
		if _, err := tx.ExecContext(t.Context(), statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestTheDatabaseSetsThePositionTheHashAndTheTimeWhateverTheCallerSends(t *testing.T) {
	r := chained(t)
	ctx := t.Context()
	person := principal(t, r.app, tenantA, identity.KindHuman, "Ada", nil)
	record(t, r.app, tenantA, person, 1)

	past := time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
	var seq int64
	var prev, hash []byte
	var at time.Time
	err := pgtest.Scan(ctx, r.app, tenantA.String(), `
		INSERT INTO identity.action_log (tenant_id, principal_id, responsible_id, action, subject, seq, prev_hash, hash, sys_period)
		VALUES ($1, $2, $2, 'api.x', 'forged', 99, decode(repeat('ab', 32), 'hex'), decode(repeat('cd', 32), 'hex'), tstzrange($3::timestamptz, NULL))
		RETURNING seq, prev_hash, hash, lower(sys_period)`, []any{tenantA, person, past}, &seq, &prev, &hash, &at)
	if err != nil {
		t.Fatal(err)
	}
	if seq != 2 {
		t.Fatalf("a caller chose its position: %d", seq)
	}
	if !at.After(past.Add(24 * time.Hour)) {
		t.Fatalf("a caller backdated its entry: %s", at)
	}
	entries, err := identity.LogPage(ctx, r.app, tenantA, 0, 10)
	if err != nil || len(entries) != 2 {
		t.Fatalf("%v %v", entries, err)
	}
	if !bytes.Equal(prev, entries[0].Hash[:]) || !bytes.Equal(hash, func() []byte { s := entries[1].Sum(); return s[:] }()) {
		t.Fatalf("a caller chose a hash: prev %x hash %x", prev, hash)
	}
	if report := verify(t, r.app, tenantA); !report.Intact || report.Entries != 2 {
		t.Fatalf("%+v", report)
	}
}

// The same two vectors as chain_test.go, given to the SQL function the trigger and the backfill use.
func TestTheSQLHashIsTheVector(t *testing.T) {
	r := chained(t)
	hashOf := func(prev []byte, seq int64, id string, at time.Time, principal, responsible, action, subject string) string {
		t.Helper()
		var got []byte
		err := r.app.QueryRowContext(t.Context(), `SELECT identity.action_log_hash($1, $2, $3::uuid, $4, $5::uuid, $6::uuid, $7, $8)`,
			prev, seq, id, at, principal, responsible, action, subject).Scan(&got)
		if err != nil {
			t.Fatal(err)
		}
		return hex.EncodeToString(got)
	}
	zeros := make([]byte, 32)
	one := hashOf(zeros, 1, "018f3e6a-1c2b-7d4e-8f50-123456789abc", time.Date(2026, time.November, 15, 8, 30, 0, 123456000, time.UTC),
		"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", "api.record_waiver", `waiver w1 of "use-tls" \ é 日本`)
	if want := "3d0a1548f7077ac48f360148a5ce92e0dc57c63d8ac070b494079962b74ee2d2"; one != want {
		t.Fatalf("hash %s, want %s", one, want)
	}
	prev, _ := hex.DecodeString(one)
	// A zone on the input changes nothing: the hash is of the instant, written in UTC.
	cest := time.Date(2026, time.November, 15, 9, 30, 1, 0, time.FixedZone("CET", 3600))
	two := hashOf(prev, 2, "018f3e6a-1c2c-7000-8000-00000000000a", cest,
		"11111111-1111-4111-8111-111111111111", "11111111-1111-4111-8111-111111111111", "api.start_export", "export 5")
	if want := "e89b4fde2c6f69c80840a1bb0ffab16d8746e5760510782d21ec32c41b7f2f11"; two != want {
		t.Fatalf("hash %s, want %s", two, want)
	}
}

func TestEveryTenantHasItsOwnChainFromOne(t *testing.T) {
	r := chained(t)
	ctx := t.Context()
	ada := principal(t, r.app, tenantA, identity.KindHuman, "Ada", nil)
	bea := principal(t, r.app, tenantB, identity.KindHuman, "Bea", nil)
	if report := verify(t, r.app, tenantA); !report.Intact || report.Entries != 0 || report.HeadSeq != 0 || report.Head != "" {
		t.Fatalf("an empty log: %+v", report)
	}
	record(t, r.app, tenantA, ada, 3)
	record(t, r.app, tenantB, bea, 2)
	record(t, r.app, tenantA, ada, 1)

	a, b := verify(t, r.app, tenantA), verify(t, r.app, tenantB)
	if !a.Intact || a.Entries != 4 || a.HeadSeq != 4 || len(a.Head) != 64 {
		t.Fatalf("tenant A: %+v", a)
	}
	if !b.Intact || b.Entries != 2 || b.HeadSeq != 2 {
		t.Fatalf("tenant B: %+v", b)
	}
	// The first entry of each chain starts from 32 zero bytes, and a page sees one tenant only.
	for tenant, want := range map[uuid.UUID]int{tenantA: 4, tenantB: 2} {
		entries, err := identity.LogPage(ctx, r.app, tenant, 0, identity.LogPageSize)
		if err != nil || len(entries) != want {
			t.Fatalf("%d entries, want %d: %v", len(entries), want, err)
		}
		if entries[0].Seq != 1 || entries[0].Prev != [32]byte{} {
			t.Fatalf("the chain does not start at 1 from zeros: %+v", entries[0])
		}
	}
	// A page continues from a position and ends at the head.
	entries, err := identity.LogPage(ctx, r.app, tenantA, 2, 10)
	if err != nil || len(entries) != 2 || entries[0].Seq != 3 || entries[1].Seq != 4 {
		t.Fatalf("after 2: %+v %v", entries, err)
	}
	if entries, err = identity.LogPage(ctx, r.app, tenantA, 4, 10); err != nil || len(entries) != 0 {
		t.Fatalf("after the head: %+v %v", entries, err)
	}
	if entries, err = identity.LogPage(ctx, r.app, tenantA, 0, 3); err != nil || len(entries) != 3 {
		t.Fatalf("a page of 3: %+v %v", entries, err)
	}
	for _, bad := range []struct {
		after int64
		limit int
	}{{-1, 10}, {0, 0}, {0, identity.LogPageSize + 1}} {
		if _, err := identity.LogPage(ctx, r.app, tenantA, bad.after, bad.limit); !errors.Is(err, identity.ErrInvalidQuery) {
			t.Errorf("%+v: %v", bad, err)
		}
	}
	if _, err := identity.LogPage(ctx, r.app, uuid.Nil, 0, 10); !errors.Is(err, identity.ErrInvalidQuery) {
		t.Errorf("no tenant: %v", err)
	}
	if _, err := identity.VerifyLog(ctx, r.app, uuid.Nil); !errors.Is(err, identity.ErrInvalidQuery) {
		t.Errorf("no tenant: %v", err)
	}
}

// Entries written at the same moment by different writers still make one chain: the position is taken
// under a lock that is held to the commit, so no two writers read the same head.
func TestConcurrentAppendsMakeOneChainInTheOrderOfTheirCommits(t *testing.T) {
	r := chained(t)
	ctx := t.Context()
	ada := principal(t, r.app, tenantA, identity.KindHuman, "Ada", nil)
	const writers = 24
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			var err error
			if i%2 == 0 {
				_, err = identity.RecordAction(ctx, r.app, tenantA, ada, "api.x", fmt.Sprintf("record %d", i))
			} else {
				err = identity.WithAction(ctx, r.app, tenantA, ada, "api.y", func(*sql.Tx) (string, error) { return fmt.Sprintf("with %d", i), nil })
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	report := verify(t, r.app, tenantA)
	if !report.Intact || report.Entries != writers || report.HeadSeq != writers {
		t.Fatalf("%+v", report)
	}
	entries, err := identity.LogPage(ctx, r.app, tenantA, 0, identity.LogPageSize)
	if err != nil {
		t.Fatal(err)
	}
	for i, e := range entries {
		if e.Seq != int64(i+1) {
			t.Fatalf("entry %d holds position %d", i, e.Seq)
		}
		if i > 0 && e.At.Before(entries[i-1].At) {
			t.Fatalf("the time of entry %d runs back: %s before %s", e.Seq, e.At, entries[i-1].At)
		}
	}
}

// A write that is rolled back leaves no entry and no hole, and the next entry takes its place.
func TestARolledBackEntryLeavesNoGap(t *testing.T) {
	r := chained(t)
	ctx := t.Context()
	ada := principal(t, r.app, tenantA, identity.KindHuman, "Ada", nil)
	record(t, r.app, tenantA, ada, 1)
	boom := errors.New("boom")
	err := identity.WithAction(ctx, r.app, tenantA, ada, "api.x", func(*sql.Tx) (string, error) { return "", boom })
	if !errors.Is(err, boom) {
		t.Fatal(err)
	}
	if err := identity.WithAction(ctx, r.app, tenantA, ada, "BAD ACTION", func(*sql.Tx) (string, error) { return "x", nil }); err == nil {
		t.Fatal("a bad action was logged")
	}
	record(t, r.app, tenantA, ada, 1)
	if report := verify(t, r.app, tenantA); !report.Intact || report.Entries != 2 || report.HeadSeq != 2 {
		t.Fatalf("%+v", report)
	}
}

// A snapshot taken before the lock would read a head that another append has moved. The database refuses
// to chain an entry in any level but READ COMMITTED.
func TestAnEntryIsRefusedOutsideReadCommitted(t *testing.T) {
	r := chained(t)
	ada := principal(t, r.app, tenantA, identity.KindHuman, "Ada", nil)
	for name, level := range map[string]sql.IsolationLevel{"repeatable read": sql.LevelRepeatableRead, "serializable": sql.LevelSerializable} {
		tx, err := r.app.BeginTx(t.Context(), &sql.TxOptions{Isolation: level})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(t.Context(), `SELECT set_config('ipso.tenant', $1, true)`, tenantA.String()); err != nil {
			t.Fatal(err)
		}
		_, err = tx.ExecContext(t.Context(), `INSERT INTO identity.action_log (tenant_id, principal_id, responsible_id, action, subject) VALUES ($1, $2, $2, 'api.x', 'x')`, tenantA, ada)
		_ = tx.Rollback()
		if sqlState(err) != "0A000" {
			t.Errorf("%s: %v", name, err)
		}
	}
	if report := verify(t, r.app, tenantA); report.Entries != 0 {
		t.Fatalf("%+v", report)
	}
}

// The tampering of the acceptance criteria: whoever reaches the table with triggers off, as a superuser or the
// owner can, edits, removes or reorders entries, and the check says where the chain stops holding.
func TestTamperingIsDetectedAtTheFirstBadEntry(t *testing.T) {
	cases := []struct {
		name       string
		statements []string
		want       identity.LogBreak
	}{
		{"an edited subject", []string{`UPDATE identity.action_log SET subject = 'edited' WHERE seq = 3`}, identity.LogBreak{Seq: 3, Reason: identity.BreakHash}},
		{"a rewritten hash", []string{`UPDATE identity.action_log SET hash = decode(repeat('00', 32), 'hex') WHERE seq = 2`}, identity.LogBreak{Seq: 2, Reason: identity.BreakHash}},
		{"an edited time", []string{`UPDATE identity.action_log SET sys_period = tstzrange(lower(sys_period) + interval '1 second', NULL) WHERE seq = 4`}, identity.LogBreak{Seq: 4, Reason: identity.BreakHash}},
		{"a removed middle entry", []string{`DELETE FROM identity.action_log WHERE seq = 3`}, identity.LogBreak{Seq: 4, Reason: identity.BreakGap}},
		{"a removed first entry", []string{`DELETE FROM identity.action_log WHERE seq = 1`}, identity.LogBreak{Seq: 2, Reason: identity.BreakGap}},
		{"an entry rewritten with a hash of its own", []string{`UPDATE identity.action_log SET subject = 'edited', hash = identity.action_log_hash(prev_hash, seq, id, lower(sys_period), principal_id, responsible_id, action, 'edited') WHERE seq = 2`}, identity.LogBreak{Seq: 3, Reason: identity.BreakPrev}},
		{"swapped positions", []string{
			`UPDATE identity.action_log SET seq = 100 WHERE seq = 2`,
			`UPDATE identity.action_log SET seq = 2 WHERE seq = 3`,
			`UPDATE identity.action_log SET seq = 3 WHERE seq = 100`,
		}, identity.LogBreak{Seq: 2, Reason: identity.BreakPrev}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := chained(t)
			ada := principal(t, r.app, tenantA, identity.KindHuman, "Ada", nil)
			record(t, r.app, tenantA, ada, 5)
			if report := verify(t, r.app, tenantA); !report.Intact {
				t.Fatalf("before: %+v", report)
			}
			asReplica(t, r.admin, tc.statements...)
			report := verify(t, r.app, tenantA)
			if report.Intact || report.Break == nil || *report.Break != tc.want {
				t.Fatalf("%+v, want a break at %+v", report, tc.want)
			}
		})
	}
}

// What a chain cannot show by itself, and what the head kept elsewhere is for (ADR-0126): entries taken
// off the end leave a chain that still holds, and the head tells a reader how far it ran.
func TestEntriesRemovedFromTheEndAreShownOnlyByAnOlderHead(t *testing.T) {
	r := chained(t)
	ada := principal(t, r.app, tenantA, identity.KindHuman, "Ada", nil)
	record(t, r.app, tenantA, ada, 5)
	kept := verify(t, r.app, tenantA)
	asReplica(t, r.admin, `DELETE FROM identity.action_log WHERE seq > 3`)
	now := verify(t, r.app, tenantA)
	if !now.Intact || now.HeadSeq != 3 {
		t.Fatalf("%+v", now)
	}
	if now.HeadSeq == kept.HeadSeq || now.Head == kept.Head {
		t.Fatal("the head did not move, so a reader holding the old one could not tell")
	}
}

func TestTheCheckWalksPastAPageAndNamesTheEntry(t *testing.T) {
	r := chained(t)
	ada := principal(t, r.app, tenantA, identity.KindHuman, "Ada", nil)
	const n = identity.LogPageSize*2 + 100
	if _, err := pgtest.Exec(t.Context(), r.app, tenantA.String(), `
		INSERT INTO identity.action_log (tenant_id, principal_id, responsible_id, action, subject)
		SELECT $1, $2, $2, 'api.x', 'entry ' || g FROM generate_series(1, $3::int) AS g`, tenantA, ada, n); err != nil {
		t.Fatal(err)
	}
	if report := verify(t, r.app, tenantA); !report.Intact || report.Entries != n || report.HeadSeq != n {
		t.Fatalf("%+v", report)
	}
	asReplica(t, r.admin, `UPDATE identity.action_log SET subject = 'edited' WHERE seq = 1501`)
	report := verify(t, r.app, tenantA)
	if report.Intact || report.Break == nil || *report.Break != (identity.LogBreak{Seq: 1501, Reason: identity.BreakHash}) || report.Entries != 1501 {
		t.Fatalf("%+v", report)
	}
}

func TestAPositionIsUniqueInATenant(t *testing.T) {
	r := chained(t)
	ada := principal(t, r.app, tenantA, identity.KindHuman, "Ada", nil)
	record(t, r.app, tenantA, ada, 1)
	tx, err := r.admin.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	// With triggers off nothing stamps the row, so only the key stands in the way.
	if _, err := tx.ExecContext(t.Context(), `SET LOCAL session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	_, err = tx.ExecContext(t.Context(), `
		INSERT INTO identity.action_log (tenant_id, principal_id, responsible_id, action, subject, seq, prev_hash, hash)
		SELECT tenant_id, principal_id, responsible_id, 'api.fork', 'fork', seq, prev_hash, hash FROM identity.action_log`)
	if sqlState(err) != "23505" {
		t.Fatalf("a second entry at the same position: %v", err)
	}
}

// The log is append-only for every role. The application role has no UPDATE, DELETE or TRUNCATE. The owner
// and a superuser are stopped by triggers, and only a session that turns triggers off, which the restore
// and offboard commands do on purpose (ADR-0100), gets through.
func TestTheLogIsAppendOnly(t *testing.T) {
	r := chained(t)
	ctx := t.Context()
	ada := principal(t, r.app, tenantA, identity.KindHuman, "Ada", nil)
	record(t, r.app, tenantA, ada, 3)

	inTenant := func(db *sql.DB, statement string) (sql.Result, error) {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback() }()
		if _, err := tx.ExecContext(ctx, `SELECT set_config('ipso.tenant', $1, true)`, tenantA.String()); err != nil {
			t.Fatal(err)
		}
		return tx.ExecContext(ctx, statement)
	}
	refused := func(who string, db *sql.DB, statement, state, fragment string) {
		t.Helper()
		_, err := inTenant(db, statement)
		if err == nil || sqlState(err) != state || !strings.Contains(err.Error(), fragment) {
			t.Errorf("%s ran %q: %v", who, statement, err)
		}
	}

	for _, statement := range []string{
		`UPDATE identity.action_log SET subject = 'edited'`,
		`DELETE FROM identity.action_log`,
		`TRUNCATE identity.action_log`,
		`INSERT INTO identity.action_log (tenant_id, id, principal_id, responsible_id, action, subject)
		 SELECT tenant_id, id, principal_id, responsible_id, action, subject FROM identity.action_log
		 ON CONFLICT (tenant_id, id) DO UPDATE SET subject = 'edited'`,
	} {
		refused("the application role", r.app, statement, "42501", "permission denied")
	}
	for _, statement := range []string{`DELETE FROM identity.action_log`, `TRUNCATE identity.action_log`} {
		refused("the owner", r.owner, statement, "42501", "append-only")
		refused("a superuser", r.admin, statement, "42501", "append-only")
	}
	refused("a superuser", r.admin, `UPDATE identity.action_log SET subject = 'edited'`, "42501", "append-only")
	// The owner has no UPDATE policy, so under forced row-level security an update reaches no row.
	if res, err := inTenant(r.owner, `UPDATE identity.action_log SET subject = 'edited'`); err != nil {
		t.Errorf("the owner's update: %v", err)
	} else if n, _ := res.RowsAffected(); n != 0 {
		t.Errorf("the owner updated %d entries", n)
	}
	if report := verify(t, r.app, tenantA); !report.Intact || report.Entries != 3 {
		t.Fatalf("a refused statement changed the log: %+v", report)
	}

	// Offboarding deletes the log with triggers off, as the owner and for one tenant.
	tx, err := r.owner.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	for _, statement := range []string{`SET LOCAL session_replication_role = replica`, `SELECT set_config('ipso.tenant', '` + tenantA.String() + `', true)`} {
		if _, err := tx.ExecContext(ctx, statement); err != nil {
			t.Fatal(err)
		}
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM identity.action_log WHERE tenant_id = $1`, tenantA)
	if err != nil {
		t.Fatalf("the offboard delete: %v", err)
	}
	if n, _ := res.RowsAffected(); n != 3 {
		t.Fatalf("the offboard delete removed %d entries", n)
	}
}
