//go:build integration

package registry

import (
	"encoding/hex"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
)

func fillDigest(b byte) (Fingerprint, string) {
	var f Fingerprint
	for i := range f {
		f[i] = b
	}
	return f, hex.EncodeToString(f[:])
}

func soon(t *testing.T, r registryDB) time.Time {
	t.Helper()
	var ts time.Time
	if err := r.admin.QueryRowContext(t.Context(), `SELECT clock_timestamp() + interval '1 minute'`).Scan(&ts); err != nil {
		t.Fatal(err)
	}
	return ts
}

func at(t *testing.T, r registryDB, literal string) time.Time {
	t.Helper()
	var ts time.Time
	if err := r.admin.QueryRowContext(t.Context(), `SELECT $1::timestamptz`, literal).Scan(&ts); err != nil {
		t.Fatal(err)
	}
	return ts
}

func (r registryDB) period(t *testing.T, tenant, decision uuid.UUID, valid string) {
	t.Helper()
	if _, err := r.app.ExecContext(t.Context(), `
		INSERT INTO registry.grandfather_period (tenant_id, decision_id, valid_period)
		VALUES ($1, $2, $3::text::tstzrange)`, tenant, decision, valid); err != nil {
		t.Fatalf("period: %v", err)
	}
}

func (r registryDB) baseline(t *testing.T, tenant, decision uuid.UUID, repo string, hexes []string) {
	t.Helper()
	if _, err := r.app.ExecContext(t.Context(), `
		INSERT INTO registry.baseline (tenant_id, decision_id, repo, fingerprints)
		VALUES ($1, $2, $3, (
			SELECT coalesce(array_agg(decode(h, 'hex')), '{}'::bytea[])
			FROM unnest($4::text[]) AS h
		))`, tenant, decision, repo, hexes); err != nil {
		t.Fatalf("baseline: %v", err)
	}
}

func TestBaselinedViolationsAreWaived(t *testing.T) {
	r := newRegistryDB(t)
	decision := uuid.MustParse("00000000-0000-4000-8000-0000000000d1")
	kept, keptHex := fillDigest(1)
	also, alsoHex := fillDigest(2)
	other, _ := fillDigest(3)
	r.period(t, tenantA, decision, "[2026-01-01,)")
	r.baseline(t, tenantA, decision, "acme/payments", []string{keptHex, alsoHex})

	may := at(t, r, "2026-05-01")
	got, err := Grandfather(t.Context(), r.app, tenantA, decision, "Acme/Payments", []Fingerprint{other, kept, also}, may, soon(t, r))
	if err != nil {
		t.Fatal(err)
	}
	want := []Result{Fail, WaivedBaseline, WaivedBaseline}
	if !slices.Equal(got, want) {
		t.Errorf("results = %v, want %v", got, want)
	}
}

func TestGrandfatherDeadlineAndAsKnown(t *testing.T) {
	r := newRegistryDB(t)
	decision := uuid.MustParse("00000000-0000-4000-8000-0000000000d2")
	kept, keptHex := fillDigest(4)
	may := at(t, r, "2026-05-01")
	june := at(t, r, "2026-06-01")

	before := mark(t, r.admin)
	r.period(t, tenantA, decision, "[2026-01-01,2026-06-01)")
	r.baseline(t, tenantA, decision, "acme/payments", []string{keptHex})
	after := mark(t, r.admin)

	got, err := Grandfather(t.Context(), r.app, tenantA, decision, "acme/payments", []Fingerprint{kept}, may, before)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []Result{Fail}) {
		t.Errorf("as known before the baseline = %v, want fail", got)
	}
	got, err = Grandfather(t.Context(), r.app, tenantA, decision, "acme/payments", []Fingerprint{kept}, may, after)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []Result{WaivedBaseline}) {
		t.Errorf("inside the period = %v, want waived(baseline)", got)
	}
	got, err = Grandfather(t.Context(), r.app, tenantA, decision, "acme/payments", []Fingerprint{kept}, june, after)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []Result{Fail}) {
		t.Errorf("at the deadline = %v, want fail", got)
	}
}

func TestGrandfatherMissesAnotherTenantRepoOrDecision(t *testing.T) {
	r := newRegistryDB(t)
	decision := uuid.MustParse("00000000-0000-4000-8000-0000000000d3")
	otherDecision := uuid.MustParse("00000000-0000-4000-8000-0000000000d4")
	kept, keptHex := fillDigest(5)
	may := at(t, r, "2026-05-01")
	known := soon(t, r)

	// No period at all: nothing is waived.
	got, err := Grandfather(t.Context(), r.app, tenantA, decision, "acme/payments", []Fingerprint{kept}, may, known)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []Result{Fail}) {
		t.Errorf("no period = %v, want fail", got)
	}

	r.period(t, tenantA, decision, "[2026-01-01,)")
	r.baseline(t, tenantA, decision, "acme/payments", []string{keptHex})
	r.period(t, tenantB, decision, "[2026-01-01,)")
	r.baseline(t, tenantB, decision, "acme/payments", []string{keptHex})

	cases := []struct {
		name     string
		tenant   uuid.UUID
		decision uuid.UUID
		repo     string
	}{
		{"another tenant", tenantB, decision, "acme/other"},
		{"another repository", tenantA, decision, "acme/other"},
		{"another decision", tenantA, otherDecision, "acme/payments"},
	}
	// tenant B's own baseline does waive. The "another tenant" case asks tenant B about a
	// repository it did not baseline.
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Grandfather(t.Context(), r.app, tt.tenant, tt.decision, tt.repo, []Fingerprint{kept}, may, known)
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got, []Result{Fail}) {
				t.Errorf("results = %v, want fail", got)
			}
		})
	}
	got, err = Grandfather(t.Context(), r.app, tenantB, decision, "acme/payments", []Fingerprint{kept}, may, known)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []Result{WaivedBaseline}) {
		t.Errorf("tenant B's own baseline = %v, want waived(baseline)", got)
	}
	// A period with no baseline waives nothing.
	r.period(t, tenantA, otherDecision, "[2026-01-01,)")
	got, err = Grandfather(t.Context(), r.app, tenantA, otherDecision, "acme/payments", []Fingerprint{kept}, may, known)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []Result{Fail}) {
		t.Errorf("period without a baseline = %v, want fail", got)
	}
}

func TestGrandfatherFailsClosedOnADamagedBaseline(t *testing.T) {
	r := newRegistryDB(t)
	decision := uuid.MustParse("00000000-0000-4000-8000-0000000000d5")
	r.period(t, tenantA, decision, "[2026-01-01,)")

	ctx := t.Context()
	conn, err := r.admin.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, `SET session_replication_role = replica`); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, `
		INSERT INTO registry.baseline (tenant_id, decision_id, repo, fingerprints, sys_period)
		VALUES ($1, $2, 'acme/payments', ARRAY[decode('aa', 'hex')]::bytea[], tstzrange(clock_timestamp(), NULL))`,
		tenantA, decision); err != nil {
		t.Fatal(err)
	}

	_, err = Grandfather(ctx, r.app, tenantA, decision, "acme/payments", []Fingerprint{{1}}, at(t, r, "2026-05-01"), soon(t, r))
	if !errors.Is(err, ErrDamagedBaseline) {
		t.Errorf("err = %v, want ErrDamagedBaseline", err)
	}
}

func TestResolveFollowsASupersession(t *testing.T) {
	r := newRegistryDB(t)
	org := r.scope(t, tenantA, uuid.Nil, "org", "acme")
	oldID := uuid.MustParse("00000000-0000-4000-8000-0000000000a1")
	newID := uuid.MustParse("00000000-0000-4000-8000-0000000000b1")
	r.decision(t, tenantA, oldID, "[2026-01-01,)", org)
	r.decision(t, tenantA, newID, "[2026-01-01,)", org)

	before := mark(t, r.admin)
	if _, err := r.app.ExecContext(t.Context(), `
		INSERT INTO registry.supersession (tenant_id, from_decision, to_decision, effective_at)
		VALUES ($1, $2, $3, $4::timestamptz)`, tenantA, oldID, newID, "2026-06-01"); err != nil {
		t.Fatal(err)
	}
	after := mark(t, r.admin)

	subject := Subject{Repo: "acme/payments"}
	july := at(t, r, "2026-07-01")
	march := at(t, r, "2026-03-01")
	ids := func(when string, valid, known time.Time) []uuid.UUID {
		t.Helper()
		got, err := Resolve(t.Context(), r.app, tenantA, subject, valid, known)
		if err != nil {
			t.Fatalf("%s: %v", when, err)
		}
		out := make([]uuid.UUID, len(got))
		for i, d := range got {
			out[i] = d.ID
		}
		slices.SortFunc(out, func(a, b uuid.UUID) int { return slices.Compare(a[:], b[:]) })
		return out
	}
	if got, want := ids("July as known after", july, after), []uuid.UUID{newID}; !slices.Equal(got, want) {
		t.Errorf("July as known after = %v, want %v", got, want)
	}
	if got, want := ids("July as known before", july, before), []uuid.UUID{oldID, newID}; !slices.Equal(got, want) {
		t.Errorf("July as known before = %v, want %v", got, want)
	}
	if got, want := ids("March as known after", march, after), []uuid.UUID{oldID, newID}; !slices.Equal(got, want) {
		t.Errorf("March as known after = %v, want %v", got, want)
	}
}
