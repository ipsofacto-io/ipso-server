//go:build integration

package migrate_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/ipsofacto-io/ipso-server/internal/pgtest"
)

const (
	premiseURL      = "https://example.com/platform/postgres.json"
	premisePointer  = "/major"
	premiseSHA      = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	premisesBoth    = `{"status":"verified","premises":[{"id":"postgres-major"},{"id":"backup-window"}]}`
	premisesMajor   = `{"status":"verified","premises":[{"id":"postgres-major"}]}`
	premisesNeither = `{"status":"verified","premises":[]}`
)

func (s schema) insertPremiseVersion(t *testing.T, decisionID, tenant string, version int, valid, body string) {
	t.Helper()
	if _, err := s.app.ExecContext(t.Context(), `
		INSERT INTO registry.decision_version (decision_id, version, tenant_id, body, scope_refs, valid_period)
		VALUES ($1::uuid, $2, $3::uuid, $4::jsonb, ARRAY[$5::uuid], $6::text::tstzrange)`,
		decisionID, version, tenant, body, s.orgs[tenant], valid); err != nil {
		t.Fatalf("insert premise version: %v", err)
	}
}

func (s schema) insertEvaluation(t *testing.T, tenant, decisionID, premise, result string) string {
	t.Helper()
	id, err := s.tryEvaluation(t, tenant, decisionID, premise, result, premiseURL, premisePointer, "16", premiseSHA)
	if err != nil {
		t.Fatalf("insert %s evaluation: %v", result, err)
	}
	return id
}

// tryEvaluation inserts one probe result. An error omits the observed value and
// the digest. An empty observed or hash is stored as NULL. The id is empty when
// the insert fails.
func (s schema) tryEvaluation(t *testing.T, tenant, decisionID, premise, result, url, pointer, observed, hash string) (string, error) {
	t.Helper()
	if result == "error" {
		observed = ""
		hash = ""
	}
	var id string
	err := s.app.QueryRowContext(t.Context(), `
		INSERT INTO registry.premise_evaluation
			(tenant_id, decision_id, premise_id, result, url, pointer, expected, observed, body_sha256)
		VALUES ($1::uuid, $2::uuid, $3, $4, $5, $6, '16'::jsonb,
		        nullif($7, '')::jsonb, decode(nullif($8, ''), 'hex'))
		RETURNING id::text`,
		tenant, decisionID, premise, result, url, pointer, observed, hash).Scan(&id)
	return id, err
}

func (s schema) insertReason(t *testing.T, tenant, decisionID, premise, evaluationID string) string {
	t.Helper()
	id, err := s.tryReason(t, tenant, decisionID, premise, evaluationID)
	if err != nil {
		t.Fatalf("insert reason: %v", err)
	}
	return id
}

func (s schema) tryReason(t *testing.T, tenant, decisionID, premise, evaluationID string) (string, error) {
	t.Helper()
	var id string
	err := s.app.QueryRowContext(t.Context(), `
		INSERT INTO registry.premise_reason (tenant_id, decision_id, premise_id, evaluation_id)
		VALUES ($1::uuid, $2::uuid, $3, $4::uuid)
		RETURNING id::text`,
		tenant, decisionID, premise, evaluationID).Scan(&id)
	return id, err
}

func (s schema) openReasons(t *testing.T, tenant, decisionID, premise string) int {
	t.Helper()
	return count(t, s.app, `
		SELECT count(*)
		FROM registry.premise_reason r
		WHERE r.tenant_id = $1::uuid
		  AND r.decision_id = $2::uuid
		  AND r.premise_id = $3
		  AND NOT EXISTS (
		      SELECT 1 FROM registry.premise_clearance c
		      WHERE c.tenant_id = r.tenant_id AND c.reason_id = r.id)`,
		tenant, decisionID, premise)
}

func TestPremiseObjectsExist(t *testing.T) {
	s := migrated(t)
	ctx := t.Context()
	for _, name := range []string{"premise_evaluation", "premise_reason", "premise_clearance", "premise_host_allow"} {
		var found bool
		if err := s.admin.QueryRowContext(ctx, `SELECT to_regclass($1) IS NOT NULL`, "registry."+name).Scan(&found); err != nil || !found {
			t.Errorf("registry.%s missing (err %v)", name, err)
		}
	}
	if n := count(t, s.admin, `
		SELECT count(*) FROM pg_catalog.pg_attribute
		WHERE attrelid = 'registry.premise_evaluation'::regclass
		  AND attname = 'body' AND NOT attisdropped`); n != 0 {
		t.Errorf("premise_evaluation has a body column")
	}
	if n := count(t, s.admin, `
		SELECT count(*) FROM pg_catalog.pg_attribute
		WHERE attrelid = 'registry.premise_evaluation'::regclass
		  AND attname = 'body_sha256' AND NOT attisdropped`); n != 1 {
		t.Errorf("body_sha256 columns = %d, want 1", n)
	}

	var match bool
	if err := s.app.QueryRowContext(ctx, `
		SELECT registry.premise_ids($1::jsonb) = ARRAY['backup-window', 'postgres-major']::text[]`,
		premisesBoth).Scan(&match); err != nil {
		t.Fatal(err)
	}
	if !match {
		t.Error("premise ids were not the two premise ids")
	}
	if err := s.app.QueryRowContext(ctx, `
		SELECT registry.premise_ids('{}'::jsonb) = ARRAY[]::text[]`).Scan(&match); err != nil {
		t.Fatal(err)
	}
	if !match {
		t.Error("a body with no premises key was not empty")
	}
	_, err := s.app.ExecContext(ctx, `SELECT registry.premise_ids('{"premises":{"id":"x"}}'::jsonb)`)
	requireCheck(t, err, "not an array")
}

func TestApplicationRoleCannotChangePremiseRows(t *testing.T) {
	s := migrated(t)
	ctx := t.Context()
	s.insertPremiseVersion(t, decision, tenantA, 1, "[2026-01-01,)", premisesBoth)
	evaluationID := s.insertEvaluation(t, tenantA, decision, "postgres-major", "fail")
	reasonID := s.insertReason(t, tenantA, decision, "postgres-major", evaluationID)
	if _, err := s.app.ExecContext(ctx, `
		INSERT INTO registry.premise_clearance (tenant_id, reason_id, kind)
		VALUES ($1::uuid, $2::uuid, 'human')`, tenantA, reasonID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.app.ExecContext(ctx, `
		INSERT INTO registry.premise_host_allow (tenant_id, host, allowed)
		VALUES ($1::uuid, 'example.com', true)`, tenantA); err != nil {
		t.Fatal(err)
	}

	statements := []string{
		`UPDATE registry.premise_evaluation SET result = 'pass'`,
		`DELETE FROM registry.premise_evaluation`,
		`TRUNCATE registry.premise_evaluation`,
		`UPDATE registry.premise_reason SET premise_id = 'other'`,
		`DELETE FROM registry.premise_reason`,
		`TRUNCATE registry.premise_reason`,
		`UPDATE registry.premise_clearance SET kind = 'human'`,
		`DELETE FROM registry.premise_clearance`,
		`TRUNCATE registry.premise_clearance`,
		`UPDATE registry.premise_host_allow SET allowed = false`,
		`DELETE FROM registry.premise_host_allow`,
		`TRUNCATE registry.premise_host_allow`,
		`ALTER TABLE registry.premise_evaluation DISABLE TRIGGER ALL`,
		`SELECT registry.premise_evaluation_check()`,
		`SELECT registry.premise_reason_check()`,
		`SELECT registry.premise_clearance_check()`,
		`SELECT registry.premise_host_allow_prepare()`,
		`SELECT registry.decision_version_clear_premise()`,
	}
	for _, statement := range statements {
		t.Run(statement, func(t *testing.T) {
			_, err := s.app.ExecContext(ctx, statement)
			requireSQLState(t, err, "42501")
		})
	}
	for _, table := range []string{
		"registry.premise_evaluation", "registry.premise_reason",
		"registry.premise_clearance", "registry.premise_host_allow",
	} {
		if n := count(t, s.app, `SELECT count(*) FROM `+table); n != 1 {
			t.Errorf("%s visible = %d, want 1", table, n)
		}
	}
}

func TestPremiseFunctionsAreOwnedByTheMigrationRole(t *testing.T) {
	s := migrated(t)
	functions := []struct {
		signature string
		callable  bool
	}{
		{"registry.premise_ids(jsonb)", true},
		{"registry.premise_evaluation_check()", false},
		{"registry.premise_reason_check()", false},
		{"registry.premise_clearance_check()", false},
		{"registry.premise_host_allow_prepare()", false},
		{"registry.decision_version_clear_premise()", false},
	}
	for _, f := range functions {
		t.Run(f.signature, func(t *testing.T) {
			var (
				definer bool
				owner   string
				config  string
				app     bool
				public  bool
			)
			err := s.admin.QueryRowContext(t.Context(), `
				SELECT prosecdef, pg_get_userbyid(proowner), coalesce(array_to_string(proconfig, ';'), ''),
				       has_function_privilege($2, oid, 'EXECUTE'),
				       coalesce((SELECT bool_or(grantee = 0) FROM aclexplode(proacl)), false)
				FROM pg_catalog.pg_proc WHERE oid = $1::text::regprocedure`, f.signature, pgtest.App).Scan(
				&definer, &owner, &config, &app, &public)
			if err != nil {
				t.Fatal(err)
			}
			if definer {
				t.Error("the function is SECURITY DEFINER, want the caller's rights")
			}
			if owner != pgtest.Migrate {
				t.Errorf("owner = %q, want %q", owner, pgtest.Migrate)
			}
			if want := "search_path=pg_catalog, pg_temp"; config != want {
				t.Errorf("function config = %q, want %q", config, want)
			}
			if app != f.callable || public {
				t.Errorf("EXECUTE: application role %v (want %v), PUBLIC %v", app, f.callable, public)
			}
		})
	}
}

func TestCallerCannotBackdatePremiseRows(t *testing.T) {
	s := migrated(t)
	ctx := t.Context()
	s.insertPremiseVersion(t, decision, tenantA, 1, "[2026-01-01,)", premisesBoth)
	before := dbNow(t, s.admin)

	var evaluationID string
	if err := s.app.QueryRowContext(ctx, `
		INSERT INTO registry.premise_evaluation
			(tenant_id, decision_id, premise_id, result, url, pointer, expected, observed, body_sha256, sys_period)
		VALUES ($1::uuid, $2::uuid, 'postgres-major', 'fail', $3, $4, '16'::jsonb, '15'::jsonb,
		        decode($5, 'hex'), tstzrange('2000-01-01'::timestamptz, NULL))
		RETURNING id::text`,
		tenantA, decision, premiseURL, premisePointer, premiseSHA).Scan(&evaluationID); err != nil {
		t.Fatal(err)
	}
	var reasonID string
	if err := s.app.QueryRowContext(ctx, `
		INSERT INTO registry.premise_reason
			(tenant_id, decision_id, premise_id, evaluation_id, sys_period)
		VALUES ($1::uuid, $2::uuid, 'postgres-major', $3::uuid, tstzrange('2000-01-01'::timestamptz, NULL))
		RETURNING id::text`, tenantA, decision, evaluationID).Scan(&reasonID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.app.ExecContext(ctx, `
		INSERT INTO registry.premise_clearance (tenant_id, reason_id, kind, sys_period)
		VALUES ($1::uuid, $2::uuid, 'human', tstzrange('2000-01-01'::timestamptz, NULL))`,
		tenantA, reasonID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.app.ExecContext(ctx, `
		INSERT INTO registry.premise_host_allow (tenant_id, host, allowed, sys_period)
		VALUES ($1::uuid, 'Example.COM', true, tstzrange('2000-01-01'::timestamptz, NULL))`,
		tenantA); err != nil {
		t.Fatal(err)
	}

	for _, table := range []string{
		"registry.premise_evaluation", "registry.premise_reason",
		"registry.premise_clearance", "registry.premise_host_allow",
	} {
		var opened time.Time
		var open bool
		err := s.admin.QueryRowContext(ctx, `
			SELECT lower(sys_period), upper(sys_period) IS NULL FROM `+table).Scan(&opened, &open)
		if err != nil {
			t.Fatalf("%s: %v", table, err)
		}
		if !open || opened.Before(before) {
			t.Errorf("%s sys_period opens at %v (open %v), want an open period from %v or later", table, opened, open, before)
		}
	}
	var host string
	if err := s.app.QueryRowContext(ctx, `
		SELECT host FROM registry.premise_host_allow WHERE tenant_id = $1::uuid`, tenantA).Scan(&host); err != nil {
		t.Fatal(err)
	}
	if host != "example.com" {
		t.Errorf("host = %q, want example.com", host)
	}
}

func TestPremiseReasonRules(t *testing.T) {
	s := migrated(t)
	ctx := t.Context()
	s.insertPremiseVersion(t, decision, tenantA, 1, "[2026-01-01,)", premisesBoth)

	majorFail := s.insertEvaluation(t, tenantA, decision, "postgres-major", "fail")
	windowFail := s.insertEvaluation(t, tenantA, decision, "backup-window", "fail")
	majorReason := s.insertReason(t, tenantA, decision, "postgres-major", majorFail)
	s.insertReason(t, tenantA, decision, "backup-window", windowFail)

	t.Run("a second open reason", func(t *testing.T) {
		_, err := s.tryReason(t, tenantA, decision, "postgres-major", majorFail)
		requireCheck(t, err, "already open")
	})
	t.Run("a pass does not clear", func(t *testing.T) {
		s.insertEvaluation(t, tenantA, decision, "postgres-major", "pass")
		if n := s.openReasons(t, tenantA, decision, "postgres-major"); n != 1 {
			t.Errorf("open reasons = %d, want 1", n)
		}
		if n := count(t, s.app, `SELECT count(*) FROM registry.premise_clearance`); n != 0 {
			t.Errorf("clearances = %d, want 0", n)
		}
	})
	t.Run("an error does not clear", func(t *testing.T) {
		s.insertEvaluation(t, tenantA, decision, "postgres-major", "error")
		if n := s.openReasons(t, tenantA, decision, "postgres-major"); n != 1 {
			t.Errorf("open reasons = %d, want 1", n)
		}
	})
	t.Run("a pass is not a reason", func(t *testing.T) {
		passed := s.insertEvaluation(t, tenantA, decision, "backup-window", "pass")
		_, err := s.tryReason(t, tenantA, decision, "backup-window", passed)
		requireCheck(t, err, "does not name a fail")
	})
	t.Run("a premise the version does not have", func(t *testing.T) {
		_, err := s.tryEvaluation(t, tenantA, decision, "not-on-the-version", "fail", premiseURL, premisePointer, "16", premiseSHA)
		requireCheck(t, err, "not on a current version")
	})
	t.Run("another tenant's evaluation", func(t *testing.T) {
		_, err := s.tryReason(t, tenantB, decision, "postgres-major", majorFail)
		requireCheck(t, err, "does not name a fail")
	})
	t.Run("premise-removed while the id remains", func(t *testing.T) {
		_, err := s.app.ExecContext(ctx, `
			INSERT INTO registry.premise_clearance (tenant_id, reason_id, kind)
			VALUES ($1::uuid, $2::uuid, 'premise-removed')`, tenantA, majorReason)
		requireCheck(t, err, "still on a current version")
	})

	if _, err := s.app.ExecContext(ctx, `
		INSERT INTO registry.premise_clearance (tenant_id, reason_id, kind)
		VALUES ($1::uuid, $2::uuid, 'human')`, tenantA, majorReason); err != nil {
		t.Fatal(err)
	}
	if n := s.openReasons(t, tenantA, decision, "postgres-major"); n != 0 {
		t.Errorf("cleared premise still has %d open reasons", n)
	}
	if n := s.openReasons(t, tenantA, decision, "backup-window"); n != 1 {
		t.Errorf("the other premise has %d open reasons, want 1", n)
	}
	t.Run("an older fail cannot open a reason", func(t *testing.T) {
		_, err := s.tryReason(t, tenantA, decision, "postgres-major", majorFail)
		requireCheck(t, err, "latest")
	})
	t.Run("a second clearance", func(t *testing.T) {
		_, err := s.app.ExecContext(ctx, `
			INSERT INTO registry.premise_clearance (tenant_id, reason_id, kind)
			VALUES ($1::uuid, $2::uuid, 'human')`, tenantA, majorReason)
		requireSQLState(t, err, "23505")
		if pgError(t, err).ConstraintName != "premise_clearance_reason" {
			t.Errorf("constraint = %q, want premise_clearance_reason", pgError(t, err).ConstraintName)
		}
	})
	t.Run("a later fail opens a new reason", func(t *testing.T) {
		again := s.insertEvaluation(t, tenantA, decision, "postgres-major", "fail")
		s.insertReason(t, tenantA, decision, "postgres-major", again)
		if n := s.openReasons(t, tenantA, decision, "postgres-major"); n != 1 {
			t.Errorf("open reasons = %d, want 1", n)
		}
		if s.openReasons(t, tenantA, decision, "backup-window") != 1 {
			t.Error("the other premise's reason was closed")
		}
	})
}

func TestDroppingAPremiseClearsItsOpenReason(t *testing.T) {
	s := migrated(t)
	ctx := t.Context()
	s.insertPremiseVersion(t, decision, tenantA, 1, "[2026-01-01,)", premisesBoth)
	majorFail := s.insertEvaluation(t, tenantA, decision, "postgres-major", "fail")
	windowFail := s.insertEvaluation(t, tenantA, decision, "backup-window", "fail")
	majorReason := s.insertReason(t, tenantA, decision, "postgres-major", majorFail)
	windowReason := s.insertReason(t, tenantA, decision, "backup-window", windowFail)

	var periodBefore string
	if err := s.app.QueryRowContext(ctx, `
		SELECT valid_period::text FROM registry.decision_version
		WHERE tenant_id = $1::uuid AND decision_id = $2::uuid`, tenantA, decision).Scan(&periodBefore); err != nil {
		t.Fatal(err)
	}

	tx, err := s.app.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
		UPDATE registry.decision_version
		SET body = $1::jsonb
		WHERE tenant_id = $2::uuid AND decision_id = $3::uuid`,
		premisesMajor, tenantA, decision); err != nil {
		t.Fatal(err)
	}

	var kind, periodAfter, status string
	if err := tx.QueryRowContext(ctx, `
		SELECT c.kind, d.valid_period::text, d.body->>'status'
		FROM registry.premise_clearance c
		JOIN registry.decision_version d
		  ON d.tenant_id = c.tenant_id AND d.decision_id = $3::uuid
		WHERE c.tenant_id = $1::uuid AND c.reason_id = $2::uuid`,
		tenantA, windowReason, decision).Scan(&kind, &periodAfter, &status); err != nil {
		t.Fatal(err)
	}
	if kind != "premise-removed" {
		t.Errorf("kind = %q, want premise-removed", kind)
	}
	if periodAfter != periodBefore {
		t.Errorf("valid_period = %s, want %s", periodAfter, periodBefore)
	}
	if status != "verified" {
		t.Errorf("status = %q, want verified", status)
	}
	var other int
	if err := tx.QueryRowContext(ctx, `
		SELECT count(*) FROM registry.premise_clearance
		WHERE tenant_id = $1::uuid AND reason_id = $2::uuid`, tenantA, majorReason).Scan(&other); err != nil {
		t.Fatal(err)
	}
	if other != 0 {
		t.Errorf("the premise that remains has %d clearances, want 0", other)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestDroppingAPremiseAnotherRowStillHasKeepsTheReason(t *testing.T) {
	s := migrated(t)
	ctx := t.Context()
	s.insertPremiseVersion(t, decision, tenantA, 1, "[2026-01-01,2026-06-01)", premisesBoth)
	s.insertPremiseVersion(t, decision, tenantA, 2, "[2026-06-01,)", premisesMajor)
	majorFail := s.insertEvaluation(t, tenantA, decision, "postgres-major", "fail")
	windowFail := s.insertEvaluation(t, tenantA, decision, "backup-window", "fail")
	s.insertReason(t, tenantA, decision, "postgres-major", majorFail)
	windowReason := s.insertReason(t, tenantA, decision, "backup-window", windowFail)

	if _, err := s.app.ExecContext(ctx, `
		UPDATE registry.decision_version
		SET body = $1::jsonb
		WHERE tenant_id = $2::uuid AND decision_id = $3::uuid AND version = 1`,
		premisesNeither, tenantA, decision); err != nil {
		t.Fatal(err)
	}
	if n := s.openReasons(t, tenantA, decision, "postgres-major"); n != 1 {
		t.Errorf("postgres-major open reasons = %d, want 1", n)
	}
	var kind string
	if err := s.app.QueryRowContext(ctx, `
		SELECT kind FROM registry.premise_clearance
		WHERE tenant_id = $1::uuid AND reason_id = $2::uuid`, tenantA, windowReason).Scan(&kind); err != nil {
		t.Fatal(err)
	}
	if kind != "premise-removed" {
		t.Errorf("kind = %q, want premise-removed", kind)
	}
}

func TestEvaluationLeavesTheVersionUntouched(t *testing.T) {
	s := migrated(t)
	ctx := t.Context()
	s.insertPremiseVersion(t, decision, tenantA, 1, "[2026-01-01,)", premisesBoth)

	var periodBefore string
	var sameBefore bool
	if err := s.app.QueryRowContext(ctx, `
		SELECT valid_period::text, body = $1::jsonb
		FROM registry.decision_version
		WHERE tenant_id = $2::uuid AND decision_id = $3::uuid`,
		premisesBoth, tenantA, decision).Scan(&periodBefore, &sameBefore); err != nil {
		t.Fatal(err)
	}
	if !sameBefore {
		t.Fatal("the stored body does not match the inserted premises")
	}

	failID := s.insertEvaluation(t, tenantA, decision, "postgres-major", "fail")
	reasonID := s.insertReason(t, tenantA, decision, "postgres-major", failID)
	s.insertEvaluation(t, tenantA, decision, "postgres-major", "pass")
	s.insertEvaluation(t, tenantA, decision, "backup-window", "error")
	if _, err := s.app.ExecContext(ctx, `
		INSERT INTO registry.premise_clearance (tenant_id, reason_id, kind)
		VALUES ($1::uuid, $2::uuid, 'human')`, tenantA, reasonID); err != nil {
		t.Fatal(err)
	}

	var periodAfter, status string
	var sameAfter bool
	if err := s.app.QueryRowContext(ctx, `
		SELECT valid_period::text, body = $1::jsonb, body->>'status'
		FROM registry.decision_version
		WHERE tenant_id = $2::uuid AND decision_id = $3::uuid`,
		premisesBoth, tenantA, decision).Scan(&periodAfter, &sameAfter, &status); err != nil {
		t.Fatal(err)
	}
	if !sameAfter || periodAfter != periodBefore || status != "verified" {
		t.Errorf("after evaluation: same body %v, period %s (want %s), status %q", sameAfter, periodAfter, periodBefore, status)
	}
}

func TestPremiseValueChecks(t *testing.T) {
	s := migrated(t)
	ctx := t.Context()
	s.insertPremiseVersion(t, decision, tenantA, 1, "[2026-01-01,)", premisesBoth)

	cases := []struct {
		name       string
		result     string
		url        string
		pointer    string
		observed   string
		hash       string
		constraint string
	}{
		{"http", "pass", "http://example.com/a", premisePointer, "16", premiseSHA, "premise_evaluation_url"},
		{"userinfo", "pass", "https://user@example.com/a", premisePointer, "16", premiseSHA, "premise_evaluation_url"},
		{"fragment", "pass", "https://example.com/a#x", premisePointer, "16", premiseSHA, "premise_evaluation_url"},
		{"another port", "pass", "https://example.com:8443/a", premisePointer, "16", premiseSHA, "premise_evaluation_url"},
		{"an address", "pass", "https://192.168.1.1/a", premisePointer, "16", premiseSHA, "premise_evaluation_url"},
		{"a pointer that does not start at the root", "pass", premiseURL, "major", "16", premiseSHA, "premise_evaluation_pointer"},
		{"a pass without an observed value", "pass", premiseURL, premisePointer, "", premiseSHA, "premise_evaluation_json_size"},
		{"a pass without a digest", "pass", premiseURL, premisePointer, "16", "", "premise_evaluation_hash"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.tryEvaluation(t, tenantA, decision, "postgres-major", tc.result, tc.url, tc.pointer, tc.observed, tc.hash)
			requireSQLState(t, err, "23514")
			if pgError(t, err).ConstraintName != tc.constraint {
				t.Errorf("constraint = %q, want %s", pgError(t, err).ConstraintName, tc.constraint)
			}
		})
	}
	t.Run("an observed value over 1024 bytes", func(t *testing.T) {
		_, err := s.app.ExecContext(ctx, `
			INSERT INTO registry.premise_evaluation
				(tenant_id, decision_id, premise_id, result, url, pointer, expected, observed, body_sha256)
			VALUES ($1::uuid, $2::uuid, 'postgres-major', 'pass', $3, $4, '16'::jsonb,
			        to_jsonb(repeat('x', 1023)), decode($5, 'hex'))`,
			tenantA, decision, premiseURL, premisePointer, premiseSHA)
		requireSQLState(t, err, "23514")
		if pgError(t, err).ConstraintName != "premise_evaluation_json_size" {
			t.Errorf("constraint = %q, want premise_evaluation_json_size", pgError(t, err).ConstraintName)
		}
	})
	t.Run("a premise id that is not a slug", func(t *testing.T) {
		s.insertPremiseVersion(t, oldDecision, tenantA, 1, "[2026-01-01,)", `{"status":"verified","premises":[{"id":"Not-Slug"}]}`)
		_, err := s.tryEvaluation(t, tenantA, oldDecision, "Not-Slug", "fail", premiseURL, premisePointer, "16", premiseSHA)
		requireSQLState(t, err, "23514")
		if pgError(t, err).ConstraintName != "premise_evaluation_premise_id" {
			t.Errorf("constraint = %q, want premise_evaluation_premise_id", pgError(t, err).ConstraintName)
		}
	})
	t.Run("premises that are not an array", func(t *testing.T) {
		_, err := s.app.ExecContext(ctx, `
			UPDATE registry.decision_version
			SET body = '{"status":"verified","premises":{"id":"postgres-major"}}'::jsonb
			WHERE tenant_id = $1::uuid AND decision_id = $2::uuid`, tenantA, decision)
		requireCheck(t, err, "not an array")
		var status string
		if err := s.app.QueryRowContext(ctx, `
			SELECT body->>'status' FROM registry.decision_version
			WHERE tenant_id = $1::uuid AND decision_id = $2::uuid`, tenantA, decision).Scan(&status); err != nil {
			t.Fatal(err)
		}
		if status != "verified" {
			t.Errorf("status = %q, want the update to have rolled back", status)
		}
	})
	for _, host := range []string{"localhost", "1.2.3.4", "not a host"} {
		t.Run("host "+host, func(t *testing.T) {
			_, err := s.app.ExecContext(ctx, `
				INSERT INTO registry.premise_host_allow (tenant_id, host, allowed)
				VALUES ($1::uuid, $2, true)`, tenantA, host)
			requireSQLState(t, err, "23514")
			if pgError(t, err).ConstraintName != "premise_host_allow_host" {
				t.Errorf("constraint = %q, want premise_host_allow_host", pgError(t, err).ConstraintName)
			}
		})
	}
}

func TestAllowlistKeepsEveryRowAndTheLatestWins(t *testing.T) {
	s := migrated(t)
	ctx := t.Context()
	if _, err := s.app.ExecContext(ctx, `
		INSERT INTO registry.premise_host_allow (tenant_id, host, allowed)
		VALUES ($1::uuid, 'Example.COM', true)`, tenantA); err != nil {
		t.Fatal(err)
	}
	sleep(t, s.admin)
	if _, err := s.app.ExecContext(ctx, `
		INSERT INTO registry.premise_host_allow (tenant_id, host, allowed)
		VALUES ($1::uuid, 'example.com', false)`, tenantA); err != nil {
		t.Fatal(err)
	}
	if n := count(t, s.app, `
		SELECT count(*) FROM registry.premise_host_allow
		WHERE tenant_id = $1::uuid AND host = 'example.com'`, tenantA); n != 2 {
		t.Fatalf("rows = %d, want 2", n)
	}
	var allowed bool
	if err := s.app.QueryRowContext(ctx, `
		SELECT allowed FROM registry.premise_host_allow
		WHERE tenant_id = $1::uuid AND host = 'example.com'
		ORDER BY lower(sys_period) DESC, id DESC
		LIMIT 1`, tenantA).Scan(&allowed); err != nil {
		t.Fatal(err)
	}
	if allowed {
		t.Error("the latest row still allows the host")
	}
}

func TestPremiseReasonRefusesRepeatableRead(t *testing.T) {
	s := migrated(t)
	s.insertPremiseVersion(t, decision, tenantA, 1, "[2026-01-01,)", premisesBoth)
	evaluationID := s.insertEvaluation(t, tenantA, decision, "postgres-major", "fail")

	ctx := t.Context()
	conn, err := s.app.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.ExecContext(ctx, `BEGIN ISOLATION LEVEL REPEATABLE READ`); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = conn.ExecContext(context.Background(), `ROLLBACK`) }()

	_, err = conn.ExecContext(ctx, `
		INSERT INTO registry.premise_reason (tenant_id, decision_id, premise_id, evaluation_id)
		VALUES ($1::uuid, $2::uuid, 'postgres-major', $3::uuid)`, tenantA, decision, evaluationID)
	if pgError(t, err).Code != "0A000" {
		t.Fatalf("want SQLSTATE 0A000, got %v", err)
	}
	if !strings.Contains(pgError(t, err).Message, "repeatable read") {
		t.Errorf("message = %q", pgError(t, err).Message)
	}
	if _, err := conn.ExecContext(ctx, `ROLLBACK`); err != nil {
		t.Fatal(err)
	}
	if n := s.openReasons(t, tenantA, decision, "postgres-major"); n != 0 {
		t.Errorf("a refused transaction left %d open reasons", n)
	}
}

func TestPremiseForeignKeyHoldsWhenTriggersAreOff(t *testing.T) {
	s := migrated(t)
	ctx := t.Context()
	s.insertPremiseVersion(t, decision, tenantA, 1, "[2026-01-01,)", premisesBoth)
	evaluationID := s.insertEvaluation(t, tenantA, decision, "postgres-major", "fail")
	if _, err := s.admin.ExecContext(ctx, `ALTER TABLE registry.premise_reason DISABLE TRIGGER USER`); err != nil {
		t.Fatal(err)
	}
	_, err := s.admin.ExecContext(ctx, `
		INSERT INTO registry.premise_reason (tenant_id, decision_id, premise_id, evaluation_id)
		VALUES ($1::uuid, $2::uuid, 'postgres-major', $3::uuid)`, tenantB, decision, evaluationID)
	requireSQLState(t, err, "23503")
	if pgError(t, err).ConstraintName != "premise_reason_evaluation" {
		t.Errorf("constraint = %q, want premise_reason_evaluation", pgError(t, err).ConstraintName)
	}
}
