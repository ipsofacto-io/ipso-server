//go:build integration

package tenancy_test

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
	"github.com/ipsofacto-io/ipso-server/internal/tenancy"
)

// newStored is a lifecycle database with two tenants that each have a person to ask for an export.
func newStored(t *testing.T) *lifecycle {
	t.Helper()
	l := newLifecycle(t)
	for tenant, person := range map[string]string{tenantA: "00000000-0000-4000-8000-0000000000f1", tenantB: "00000000-0000-4000-8000-0000000000f2"} {
		l.provision(t, tenant, "synthetic tenant", &tenancy.Person{ID: uuid.MustParse(person), Name: "Ada", Issuer: "https://idp.example.test", Subject: "subject-" + tenant})
	}
	return l
}

// person is the first person of a tenant, whoever wrote it.
func (l *lifecycle) person(t *testing.T, tenant string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := l.admin.QueryRowContext(t.Context(), `SELECT id FROM identity.principal WHERE tenant_id = $1 ORDER BY id LIMIT 1`, tenant).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

// start records a request in the transaction the API opens for it, for the first person of the tenant.
func (l *lifecycle) start(t *testing.T, tenant, recipient string) (tenancy.StoredExport, error) {
	t.Helper()
	person := l.person(t, tenant)
	var e tenancy.StoredExport
	err := pgtest.WithTenant(t.Context(), l.app, tenant, func(tx *sql.Tx) error {
		var err error
		e, err = tenancy.StartExport(t.Context(), tx, uuid.MustParse(tenant), person, recipient)
		return err
	})
	return e, err
}

// corrupt changes the last character of a key, so that its checksum fails and the text still looks like a key.
func corrupt(key string) string {
	if strings.HasSuffix(key, "q") {
		return key[:len(key)-1] + "p"
	}
	return key[:len(key)-1] + "q"
}

func (l *lifecycle) get(t *testing.T, tenant string, id uuid.UUID) (tenancy.StoredExport, error) {
	t.Helper()
	return tenancy.GetExport(t.Context(), l.app, uuid.MustParse(tenant), id)
}

func (l *lifecycle) parts(t *testing.T, id uuid.UUID) int {
	t.Helper()
	var n int
	if err := l.admin.QueryRowContext(t.Context(), `SELECT count(*) FROM tenancy.export_part WHERE export_id = $1`, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// archive reads the stored parts of a ready export, and checks them against the size and the sum it states.
func (l *lifecycle) archive(t *testing.T, tenant string, e tenancy.StoredExport) []byte {
	t.Helper()
	var out bytes.Buffer
	for seq := range e.Parts {
		part, err := tenancy.ExportPart(t.Context(), l.app, uuid.MustParse(tenant), e.ID, seq)
		if err != nil {
			t.Fatalf("part %d: %v", seq, err)
		}
		out.Write(part)
	}
	if sum := sha256.Sum256(out.Bytes()); int64(out.Len()) != e.Bytes || !bytes.Equal(sum[:], e.SHA256) {
		t.Fatalf("the parts hold %d bytes, the export says %d, or the sum differs", out.Len(), e.Bytes)
	}
	return out.Bytes()
}

// ready asks for an export and makes it, as the API and the worker do.
func (l *lifecycle) ready(t *testing.T, tenant, recipient string) tenancy.StoredExport {
	t.Helper()
	e, err := l.start(t, tenant, recipient)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tenancy.RunStoredExport(t.Context(), l.app, uuid.MustParse(tenant), e.ID); err != nil {
		t.Fatal(err)
	}
	e, err = l.get(t, tenant, e.ID)
	if err != nil || e.State != tenancy.ExportReady {
		t.Fatalf("the export is %+v (%v), want ready", e, err)
	}
	return e
}

// expire makes every export end ago before now, and finish two days ago, so the cooldown is over.
func (l *lifecycle) expire(t *testing.T, ago string) {
	t.Helper()
	if _, err := l.admin.ExecContext(t.Context(), `
		UPDATE tenancy.export
		SET created_at = now() - interval '3 days', finished_at = CASE WHEN finished_at IS NULL THEN NULL ELSE now() - interval '2 days' END,
		    expires_at = now() - interval '`+ago+`'`); err != nil {
		t.Fatal(err)
	}
}

// age moves every export back in time by the interval, as if it had been made that long ago.
func (l *lifecycle) age(t *testing.T, by string) {
	t.Helper()
	if _, err := l.admin.ExecContext(t.Context(), `
		UPDATE tenancy.export
		SET created_at = created_at - interval '`+by+`', finished_at = finished_at - interval '`+by+`', expires_at = expires_at - interval '`+by+`'`); err != nil {
		t.Fatal(err)
	}
}

func TestAStoredExportIsTheArchiveThatRestoreReads(t *testing.T) {
	l := newLifecycle(t)
	pgtest.SeedEveryTable(t, l.app, tenantA)
	pgtest.SeedEveryTable(t, l.app, tenantB)
	l.provision(t, tenantC, "restored", nil)
	key := identity(t)

	// The seed left a ready export in tenant A that finished an hour ago. The new request replaces it, and its
	// parts stay for a download in flight.
	var old uuid.UUID
	if err := l.admin.QueryRowContext(t.Context(), `SELECT id FROM tenancy.export WHERE tenant_id = $1`, tenantA).Scan(&old); err != nil {
		t.Fatal(err)
	}
	e := l.ready(t, tenantA, key.Recipient().String())
	if e.ID == old || l.parts(t, old) != 1 {
		t.Fatalf("the request did not replace the export of the seed: %s, %d old parts", e.ID, l.parts(t, old))
	}
	archive := l.archive(t, tenantA, e)
	if bytes.Contains(archive, []byte("synthetic tenant")) {
		t.Fatal("the stored archive holds plaintext")
	}

	// It is the archive of `tenant export`: the same layout, no export table in it, and restore reads it.
	body := open(t, archive, key)
	tables, _ := body.header["tables"].([]any)
	for _, table := range tables {
		if name, _ := table.(string); name == "tenancy.export" || name == "tenancy.export_part" {
			t.Errorf("the archive lists %s", name)
		}
	}
	if body.header["format"] != tenancy.Format {
		t.Errorf("the format is %v, want %s", body.header["format"], tenancy.Format)
	}
	report, err := l.restore(archive, tenantC, key, t)
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if report.Source.String() != tenantA {
		t.Fatalf("the archive names tenant %s, want A", report.Source)
	}
	for _, table := range l.tables(t) {
		if notRestored[table] {
			continue
		}
		if got, want := l.rows(t, table, tenantC), l.rows(t, table, tenantA); strings.Join(got, "\n") != strings.Join(want, "\n") {
			t.Errorf("%s differs after the restore:\n got  %v\n want %v", table, got, want)
		}
	}
	// Tenant B's export is untouched.
	if l.count(t, "tenancy.export", tenantB) != 1 || l.count(t, "tenancy.export_part", tenantB) != 1 {
		t.Error("the export of tenant A changed the exports of tenant B")
	}
}

func TestAnExportNeedsAKeyThatParsesAndOnlyOneIsUnderWayAtATime(t *testing.T) {
	l := newStored(t)
	secret := identity(t)
	key := secret.Recipient().String()
	for name, recipient := range map[string]string{"empty": "", "private": secret.String(), "two": key + "\n" + key, "wrong sum": corrupt(key)} {
		if _, err := l.start(t, tenantA, recipient); !errors.Is(err, tenancy.ErrBadRecipient) {
			t.Errorf("%s: %v, want ErrBadRecipient", name, err)
		}
	}
	if n := l.count(t, "tenancy.export", tenantA); n != 0 {
		t.Fatalf("a refused request stored %d exports", n)
	}

	first, err := l.start(t, tenantA, key)
	if err != nil || first.State != tenancy.ExportPending || first.RequestedBy != l.person(t, tenantA) || first.FinishedAt != nil || first.Bytes != 0 || len(first.SHA256) != 0 {
		t.Fatalf("a request = %+v (%v), want pending and asked by the person", first, err)
	}
	if d := first.ExpiresAt.Sub(first.CreatedAt); d != tenancy.ExportKept {
		t.Errorf("a pending export expires after %s, want %s", d, tenancy.ExportKept)
	}
	// A second request while one is pending is refused by the unique constraint, and the first stays.
	_, err = l.start(t, tenantA, key)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" || pgErr.ConstraintName != "export_one_at_a_time" {
		t.Fatalf("a second request = %v, want a unique violation of export_one_at_a_time", err)
	}
	if got, err := l.get(t, tenantA, first.ID); err != nil || got.ID != first.ID {
		t.Fatalf("the first request is %+v (%v)", got, err)
	}
	// Tenant B has its own.
	if _, err := l.start(t, tenantB, key); err != nil {
		t.Fatalf("tenant B could not ask while tenant A has a request: %v", err)
	}
	// So does a running one.
	if _, err := l.admin.ExecContext(t.Context(), `UPDATE tenancy.export SET state = 'running' WHERE id = $1`, first.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := l.start(t, tenantA, key); !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		t.Fatalf("a request while one is running = %v, want a unique violation", err)
	}
}

func TestAFinishedExportIsReplacedAfterTheCooldownAndItsPartsStayForADownloadInFlight(t *testing.T) {
	l := newStored(t)
	key := identity(t).Recipient().String()
	tenant := uuid.MustParse(tenantA)

	done := l.ready(t, tenantA, key)
	if l.parts(t, done.ID) != done.Parts || done.Parts < 1 {
		t.Fatalf("a ready export has %d of %d parts", l.parts(t, done.ID), done.Parts)
	}
	if d := done.ExpiresAt.Sub(*done.FinishedAt); d != tenancy.ExportKept {
		t.Errorf("a ready export is kept for %s, want %s", d, tenancy.ExportKept)
	}
	// Right after it finished, another request is too soon, and nothing changes.
	_, err := l.start(t, tenantA, key)
	var soon *tenancy.TooSoonError
	if !errors.As(err, &soon) || soon.Wait <= 0 || soon.Wait > tenancy.ExportCooldown {
		t.Fatalf("a request right after a ready export = %v, want a TooSoonError within %s", err, tenancy.ExportCooldown)
	}
	if got, err := l.get(t, tenantA, done.ID); err != nil || got.State != tenancy.ExportReady {
		t.Fatalf("a refused request changed the export: %+v (%v)", got, err)
	}

	// After the cooldown the request replaces it. The old export is no longer served, and its parts stay, so a
	// download that began in time reads them to the end.
	l.age(t, "1 hour")
	next, err := l.start(t, tenantA, key)
	if err != nil || next.ID == done.ID {
		t.Fatalf("a request after the cooldown = %+v (%v), want a new one", next, err)
	}
	if _, err := l.get(t, tenantA, done.ID); !errors.Is(err, tenancy.ErrNoExport) {
		t.Errorf("the replaced export is %v, want ErrNoExport", err)
	}
	for seq := range done.Parts {
		if _, err := tenancy.ExportPart(t.Context(), l.app, tenant, done.ID, seq); err != nil {
			t.Fatalf("part %d of the replaced export: %v", seq, err)
		}
	}
	// The sweep keeps it inside the grace, and deletes it, with its parts, past it.
	if swept, err := tenancy.SweepExports(t.Context(), l.app, tenant); err != nil || swept.Deleted != 0 || l.parts(t, done.ID) != done.Parts {
		t.Fatalf("a sweep inside the grace = %+v, %d parts (%v)", swept, l.parts(t, done.ID), err)
	}
	l.age(t, "1 hour")
	if swept, err := tenancy.SweepExports(t.Context(), l.app, tenant); err != nil || swept.Deleted != 1 || l.parts(t, done.ID) != 0 {
		t.Fatalf("a sweep past the grace = %+v, %d parts (%v), want the replaced export gone", swept, l.parts(t, done.ID), err)
	}
	if got, err := l.get(t, tenantA, next.ID); err != nil || got.State != tenancy.ExportPending {
		t.Fatalf("the sweep touched the new request: %+v (%v)", got, err)
	}

	// A failed export is a finished one too: too soon at first, then deleted by the next request.
	if err := tenancy.FailExport(t.Context(), l.app, tenant, next.ID); err != nil {
		t.Fatal(err)
	}
	failed, err := l.get(t, tenantA, next.ID)
	if err != nil || failed.State != tenancy.ExportFailed || failed.FinishedAt == nil {
		t.Fatalf("a failed export is %+v (%v)", failed, err)
	}
	if _, err := l.start(t, tenantA, key); !errors.As(err, &soon) {
		t.Fatalf("a request right after a failed export = %v, want TooSoonError", err)
	}
	l.age(t, "1 hour")
	again, err := l.start(t, tenantA, key)
	if err != nil || again.ID == failed.ID {
		t.Fatalf("a request after a failed export = %+v (%v)", again, err)
	}
	if _, err := l.get(t, tenantA, failed.ID); !errors.Is(err, tenancy.ErrNoExport) || l.count(t, "tenancy.export", tenantA) != 1 {
		t.Errorf("the failed export is %v, with %d exports stored, want it deleted", err, l.count(t, "tenancy.export", tenantA))
	}

	// An export that expired but was not swept is replaced like a finished one, and its parts stay.
	if _, err := tenancy.RunStoredExport(t.Context(), l.app, tenant, again.ID); err != nil {
		t.Fatal(err)
	}
	l.expire(t, "1 minute")
	if _, err := l.get(t, tenantA, again.ID); !errors.Is(err, tenancy.ErrNoExport) {
		t.Fatalf("an expired export is %v, want ErrNoExport", err)
	}
	last, err := l.start(t, tenantA, key)
	if err != nil || last.ID == again.ID || l.parts(t, again.ID) == 0 {
		t.Fatalf("a request after an expired export = %+v (%v), %d parts of the old one", last, err, l.parts(t, again.ID))
	}
}

func TestOnlyAnExportThatWaitsCanBeMadeAndAnAttemptStartsFromNothing(t *testing.T) {
	l := newStored(t)
	key := identity(t)
	if _, err := tenancy.RunStoredExport(t.Context(), l.app, uuid.MustParse(tenantA), uuid.New()); !errors.Is(err, tenancy.ErrNoExport) {
		t.Errorf("an unknown export: %v, want ErrNoExport", err)
	}
	done := l.ready(t, tenantA, key.Recipient().String())
	if _, err := tenancy.RunStoredExport(t.Context(), l.app, uuid.MustParse(tenantA), done.ID); !errors.Is(err, tenancy.ErrNoExport) {
		t.Errorf("a ready export: %v, want ErrNoExport", err)
	}
	if got := l.archive(t, tenantA, done); len(got) == 0 {
		t.Error("a refused run changed the ready export")
	}

	// An attempt that died leaves a running export with parts. The next attempt clears them and makes the whole.
	other := newStored(t)
	e, err := other.start(t, tenantA, key.Recipient().String())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.admin.ExecContext(t.Context(), `UPDATE tenancy.export SET state = 'running' WHERE id = $1`, e.ID); err != nil {
		t.Fatal(err)
	}
	for seq := range 3 {
		if _, err := other.admin.ExecContext(t.Context(), `INSERT INTO tenancy.export_part (tenant_id, export_id, seq, data) VALUES ($1, $2, $3, 'stale'::bytea)`, tenantA, e.ID, seq); err != nil {
			t.Fatal(err)
		}
	}
	report, err := tenancy.RunStoredExport(t.Context(), other.app, uuid.MustParse(tenantA), e.ID)
	if err != nil || report.Total == 0 {
		t.Fatalf("the second attempt: %+v, %v", report, err)
	}
	got, err := other.get(t, tenantA, e.ID)
	if err != nil || got.State != tenancy.ExportReady || other.parts(t, e.ID) != got.Parts {
		t.Fatalf("the export is %+v (%v) with %d parts", got, err, other.parts(t, e.ID))
	}
	if bytes.Contains(other.archive(t, tenantA, got), []byte("stale")) {
		t.Error("a part of the dead attempt is in the archive")
	}
	if header := open(t, other.archive(t, tenantA, got), key).header; header["format"] != tenancy.Format {
		t.Errorf("the header of the archive is %v", header)
	}

	// A key that the table accepts and the parser does not fails the run with ErrBadRecipient.
	third := newStored(t)
	if _, err := third.admin.ExecContext(t.Context(), `
		INSERT INTO tenancy.export (tenant_id, requested_by, recipient, expires_at)
		VALUES ($1, $2, 'age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq', now() + interval '1 day')`, tenantA, third.person(t, tenantA)); err != nil {
		t.Fatal(err)
	}
	var id uuid.UUID
	if err := third.admin.QueryRowContext(t.Context(), `SELECT id FROM tenancy.export`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if _, err := tenancy.RunStoredExport(t.Context(), third.app, uuid.MustParse(tenantA), id); !errors.Is(err, tenancy.ErrBadRecipient) {
		t.Errorf("a key that does not parse: %v, want ErrBadRecipient", err)
	}
}

func TestFailExportLeavesAReadyExportAndAnUnknownOneAlone(t *testing.T) {
	l := newStored(t)
	key := identity(t).Recipient().String()
	done := l.ready(t, tenantA, key)
	if err := tenancy.FailExport(t.Context(), l.app, uuid.MustParse(tenantA), done.ID); err != nil {
		t.Fatal(err)
	}
	if got, err := l.get(t, tenantA, done.ID); err != nil || got.State != tenancy.ExportReady || l.parts(t, done.ID) != done.Parts {
		t.Errorf("a ready export after FailExport is %+v (%v) with %d parts", got, err, l.parts(t, done.ID))
	}
	if err := tenancy.FailExport(t.Context(), l.app, uuid.MustParse(tenantA), uuid.New()); err != nil {
		t.Errorf("failing an unknown export = %v, want nothing to do", err)
	}
}

func TestTheSweepDeletesWhatExpiredBeyondTheGraceAndNamesWhatStillWaits(t *testing.T) {
	l := newStored(t)
	key := identity(t).Recipient().String()
	done := l.ready(t, tenantA, key)
	waiting, err := l.start(t, tenantB, key)
	if err != nil {
		t.Fatal(err)
	}

	swept, err := tenancy.SweepExports(t.Context(), l.app, uuid.MustParse(tenantA))
	if err != nil || swept.Deleted != 0 || len(swept.Open) != 0 {
		t.Fatalf("a sweep of a ready export = %+v, %v", swept, err)
	}
	swept, err = tenancy.SweepExports(t.Context(), l.app, uuid.MustParse(tenantB))
	if err != nil || swept.Deleted != 0 || !slices.Equal(swept.Open, []uuid.UUID{waiting.ID}) {
		t.Fatalf("a sweep of a pending export = %+v, %v", swept, err)
	}
	// A running export waits for a job too, because the one that was making it may have died.
	if _, err := l.admin.ExecContext(t.Context(), `UPDATE tenancy.export SET state = 'running', started_at = now() WHERE id = $1`, waiting.ID); err != nil {
		t.Fatal(err)
	}
	if swept, _ = tenancy.SweepExports(t.Context(), l.app, uuid.MustParse(tenantB)); !slices.Equal(swept.Open, []uuid.UUID{waiting.ID}) {
		t.Errorf("a running export is %v, want it named", swept.Open)
	}

	// A request that waited three hours for a worker is not stuck when a job has only just claimed it.
	if _, err := l.admin.ExecContext(t.Context(), `UPDATE tenancy.export SET created_at = now() - interval '3 hours', expires_at = now() + interval '21 hours' WHERE id = $1`, waiting.ID); err != nil {
		t.Fatal(err)
	}
	if swept, err = tenancy.SweepExports(t.Context(), l.app, uuid.MustParse(tenantB)); err != nil || swept.Failed != 0 || !slices.Equal(swept.Open, []uuid.UUID{waiting.ID}) {
		t.Fatalf("an export that waited and was just claimed: %+v (%v), want it left running", swept, err)
	}
	// A running export that a job claimed over two hours ago has lost its job: it fails with its parts.
	if _, err := l.admin.ExecContext(t.Context(), `UPDATE tenancy.export SET started_at = now() - interval '3 hours' WHERE id = $1`, waiting.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := l.admin.ExecContext(t.Context(), `INSERT INTO tenancy.export_part (tenant_id, export_id, seq, data) VALUES ($1, $2, 0, 'stale'::bytea)`, tenantB, waiting.ID); err != nil {
		t.Fatal(err)
	}
	if swept, err = tenancy.SweepExports(t.Context(), l.app, uuid.MustParse(tenantB)); err != nil || swept.Failed != 1 || len(swept.Open) != 0 || l.parts(t, waiting.ID) != 0 {
		t.Fatalf("a stuck export: %+v, %d parts (%v), want it failed and not named", swept, l.parts(t, waiting.ID), err)
	}
	if got, err := l.get(t, tenantB, waiting.ID); err != nil || got.State != tenancy.ExportFailed || got.FinishedAt == nil {
		t.Fatalf("a stuck export is %+v (%v), want failed", got, err)
	}

	// Ten minutes past its expiry an export is not served, and its parts are still there for a download in flight.
	l.expire(t, "10 minutes")
	swept, err = tenancy.SweepExports(t.Context(), l.app, uuid.MustParse(tenantA))
	if err != nil || swept.Deleted != 0 || len(swept.Open) != 0 || l.parts(t, done.ID) != done.Parts {
		t.Fatalf("a sweep inside the grace = %+v, %d parts (%v)", swept, l.parts(t, done.ID), err)
	}
	if swept, _ = tenancy.SweepExports(t.Context(), l.app, uuid.MustParse(tenantB)); len(swept.Open) != 0 {
		t.Errorf("an expired export waits for a job: %v", swept.Open)
	}
	l.expire(t, "1 hour")
	swept, err = tenancy.SweepExports(t.Context(), l.app, uuid.MustParse(tenantA))
	if err != nil || swept.Deleted != 1 || l.parts(t, done.ID) != 0 || l.count(t, "tenancy.export", tenantA) != 0 {
		t.Fatalf("a sweep past the grace = %+v (%v), %d parts left", swept, err, l.parts(t, done.ID))
	}
	// The sweep of one tenant never touched the other's row, which is expired as well.
	if l.count(t, "tenancy.export", tenantB) != 1 {
		t.Error("the sweep of tenant A deleted the export of tenant B")
	}
}

func TestAnotherTenantSeesNoExportAndNoPart(t *testing.T) {
	l := newStored(t)
	done := l.ready(t, tenantA, identity(t).Recipient().String())
	if _, err := l.get(t, tenantB, done.ID); !errors.Is(err, tenancy.ErrNoExport) {
		t.Errorf("tenant B reads the export of tenant A: %v", err)
	}
	if _, err := tenancy.ExportPart(t.Context(), l.app, uuid.MustParse(tenantB), done.ID, 0); !errors.Is(err, tenancy.ErrNoExport) {
		t.Errorf("tenant B reads a part of tenant A: %v", err)
	}
	if err := tenancy.FailExport(t.Context(), l.app, uuid.MustParse(tenantB), done.ID); err != nil {
		t.Fatal(err)
	}
	if got, err := l.get(t, tenantA, done.ID); err != nil || got.State != tenancy.ExportReady {
		t.Errorf("tenant B failed the export of tenant A: %+v (%v)", got, err)
	}
}
