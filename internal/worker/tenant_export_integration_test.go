//go:build integration

package worker

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"database/sql"
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
	"github.com/ipsofacto-io/ipso-server/internal/tenancy"
)

// request records a request for an export as the API does, for the first person of the tenant, and returns
// its id. The worker finds it with its sweep, which runs when the worker starts.
func (s *stack) request(t *testing.T, tenant uuid.UUID, recipient string) uuid.UUID {
	t.Helper()
	var person, id uuid.UUID
	if err := pgtest.Scan(t.Context(), s.app, tenant.String(), `SELECT id FROM identity.principal LIMIT 1`, nil, &person); err != nil {
		t.Fatal(err)
	}
	if err := pgtest.Scan(t.Context(), s.app, tenant.String(), `
		INSERT INTO tenancy.export (tenant_id, requested_by, recipient, expires_at)
		VALUES ($1, $2, $3, now() + interval '1 day') RETURNING id`, []any{tenant, person, recipient}, &id); err != nil {
		t.Fatal(err)
	}
	return id
}

func (s *stack) exportRow(t *testing.T, tenant, id uuid.UUID) (state string, bytes int64, parts int) {
	t.Helper()
	var size sql.NullInt64
	var n sql.NullInt32
	if err := pgtest.Scan(t.Context(), s.app, tenant.String(), `SELECT state, bytes, parts FROM tenancy.export WHERE id = $1`,
		[]any{id}, &state, &size, &n); err != nil {
		t.Fatal(err)
	}
	return state, size.Int64, int(n.Int32)
}

func (s *stack) exportParts(t *testing.T, tenant, id uuid.UUID) int {
	t.Helper()
	var n int
	if err := pgtest.Scan(t.Context(), s.app, tenant.String(), `SELECT count(*) FROM tenancy.export_part WHERE export_id = $1`, []any{id}, &n); err != nil {
		t.Fatal(err)
	}
	return n
}

func newKey(t *testing.T) (*age.X25519Identity, string) {
	t.Helper()
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatal(err)
	}
	return id, id.Recipient().String()
}

func TestTheWorkerMakesAnExportReadyForItsOwnTenantOnly(t *testing.T) {
	s := newStack(t)
	identity, recipient := newKey(t)
	exportA := s.request(t, tenantA, recipient)
	exportB := s.request(t, tenantB, recipient)

	// The sweep runs when the worker starts, so the request is found at once and not a minute later.
	s.start(t, tenantA)
	eventually(t, "the export of tenant A is ready", func() bool {
		state, _, _ := s.exportRow(t, tenantA, exportA)
		return state == tenancy.ExportReady
	})
	_, size, parts := s.exportRow(t, tenantA, exportA)
	if size <= 0 || parts != s.exportParts(t, tenantA, exportA) || parts < 1 {
		t.Fatalf("the export is %d bytes in %d parts, with %d stored", size, parts, s.exportParts(t, tenantA, exportA))
	}

	// The parts are the age file of ADR-0100: only the holder of the key opens it, and it holds this tenant.
	var archive bytes.Buffer
	for seq := range parts {
		part, err := tenancy.ExportPart(t.Context(), s.app, tenantA, exportA, seq)
		if err != nil {
			t.Fatal(err)
		}
		archive.Write(part)
	}
	if int64(archive.Len()) != size {
		t.Fatalf("the parts hold %d bytes, the export says %d", archive.Len(), size)
	}
	if bytes.Contains(archive.Bytes(), []byte("synthetic tenant")) {
		t.Fatal("the stored archive holds plaintext")
	}
	if _, err := age.Decrypt(bytes.NewReader(archive.Bytes()), mustIdentity(t)); err == nil {
		t.Fatal("an archive opened with a key it was not encrypted to")
	}
	plain, err := age.Decrypt(&archive, identity)
	if err != nil {
		t.Fatalf("the holder of the key cannot open the archive: %v", err)
	}
	zr, err := gzip.NewReader(plain)
	if err != nil {
		t.Fatal(err)
	}
	header, err := bufio.NewReader(zr).ReadString('\n')
	if err != nil || !strings.Contains(header, `"format":"ipso-tenant-export/1"`) || !strings.Contains(header, tenantA.String()) || strings.Contains(header, tenantB.String()) {
		t.Fatalf("the header is %q (%v)", header, err)
	}

	// The tenant nobody serves is left alone, and no job names it.
	if state, _, _ := s.exportRow(t, tenantB, exportB); state != tenancy.ExportPending {
		t.Errorf("the export of the tenant nobody serves is %s, want pending", state)
	}
	if n := s.jobs(t, `kind = 'tenant_export' AND args->>'tenant' = $1`, tenantB.String()); n != 0 {
		t.Errorf("%d export jobs name the tenant nobody serves", n)
	}
	// River keeps the arguments of a job outside row-level security, so they are ids and never the key.
	var args string
	if err := s.app.QueryRowContext(t.Context(), `SELECT args::text FROM river.river_job WHERE kind = 'tenant_export' LIMIT 1`).Scan(&args); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(args, "age1") || !strings.Contains(args, exportA.String()) {
		t.Errorf("the job arguments are %s", args)
	}
}

func mustIdentity(t *testing.T) *age.X25519Identity {
	t.Helper()
	id, _ := newKey(t)
	return id
}

func TestAnExportForAKeyThatCannotBeReadFailsAtOnceAndItsJobIsCancelled(t *testing.T) {
	s := newStack(t)
	// The table accepts the text of a key. Only the parser knows that the checksum is wrong.
	bad := s.request(t, tenantA, "age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq")
	s.start(t, tenantA)
	eventually(t, "the export failed", func() bool {
		state, _, _ := s.exportRow(t, tenantA, bad)
		return state == tenancy.ExportFailed
	})
	if n := s.exportParts(t, tenantA, bad); n != 0 {
		t.Errorf("a failed export keeps %d parts", n)
	}
	eventually(t, "the job was cancelled", func() bool { return s.jobs(t, `kind = 'tenant_export' AND state = 'cancelled'`) == 1 })
	var errors string
	if err := s.app.QueryRowContext(t.Context(), `SELECT errors::text FROM river.river_job WHERE kind = 'tenant_export'`).Scan(&errors); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(errors, "age1") {
		t.Errorf("the job stored the key in its errors: %s", errors)
	}
}

func TestARestartDeletesAnExpiredExportWithItsPartsAndLeavesAFreshOne(t *testing.T) {
	s := newStack(t)
	_, recipient := newKey(t)
	old := s.request(t, tenantA, recipient)
	stop := s.start(t, tenantA)
	eventually(t, "the export is ready", func() bool {
		state, _, _ := s.exportRow(t, tenantA, old)
		return state == tenancy.ExportReady
	})
	stop()

	// An export is kept for a day, and its parts for half an hour more, so a download that began in time can end.
	admin := s.database.Open(t, pgtest.Admin)
	expire := func(after string) {
		t.Helper()
		if _, err := admin.ExecContext(t.Context(), `UPDATE tenancy.export SET created_at = now() - interval '3 days', expires_at = now() - interval '`+after+`'`); err != nil {
			t.Fatal(err)
		}
	}
	expire("10 minutes")
	stop2 := s.start(t, tenantA)
	eventually(t, "a sweep ran after the restart", func() bool { return s.jobs(t, `kind = 'tenant_export_sweep' AND state = 'completed'`) >= 2 })
	stop2()
	if n := s.exportParts(t, tenantA, old); n == 0 {
		t.Error("the parts of an export that expired ten minutes ago were deleted inside the grace period")
	}

	expire("1 hour")
	s.start(t, tenantA)
	eventually(t, "the expired export is gone", func() bool {
		var n int
		if err := admin.QueryRowContext(t.Context(), `SELECT count(*) FROM tenancy.export WHERE id = $1`, old).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == 0
	})
	var parts int
	if err := admin.QueryRowContext(t.Context(), `SELECT count(*) FROM tenancy.export_part WHERE export_id = $1`, old).Scan(&parts); err != nil || parts != 0 {
		t.Errorf("%d parts of a deleted export remain (%v)", parts, err)
	}
}
