//go:build integration

package migrate_test

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"pgregory.net/rapid"
)

// Property tests for the temporal invariants in section 9.5 of the specification.
// Each example writes as ipso_app in one transaction and rolls it back. A rejected
// statement runs in a savepoint, because a constraint failure aborts the transaction.
// The premise invariant remains IPSO-125. A recorded waiver is contained in a
// current decision version. A later supersession can shorten the decision
// without rewriting the waiver, and Apply then refuses those valid times.

const (
	propFrom  = "00000000-0000-4000-8000-0000000000e1"
	propTo    = "00000000-0000-4000-8000-0000000000e2"
	propThird = "00000000-0000-4000-8000-0000000000e3"
	propBody  = `{"statement":"synthetic"}`
)

// propEpoch is the origin of every drawn valid day. The tests pass the resulting
// date text to PostgreSQL, so the session time zone applies the same way on both sides.
var propEpoch = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

// scopeMasks are the non-empty subsets of three scopes that hold at least two ids.
var scopeMasks = []int{0b011, 0b101, 0b110, 0b111}

func TestPropertyCurrentValidPeriodsDoNotOverlap(t *testing.T) {
	s := migrated(t)
	rapid.Check(t, func(rt *rapid.T) {
		tx := propBegin(rt, s.app)
		defer func() { _ = tx.Rollback() }()

		tenant := rapid.SampledFrom([]string{tenantA, tenantB}).Draw(rt, "tenant")
		start := rapid.IntRange(0, 800).Draw(rt, "start")
		length := rapid.IntRange(1, 30).Draw(rt, "length")
		offset := rapid.IntRange(0, length-1).Draw(rt, "offset")
		overlapLen := rapid.IntRange(1, 20).Draw(rt, "overlapLen")
		abutLen := rapid.IntRange(1, 20).Draw(rt, "abutLen")

		first := propPeriod(start, start+length)
		// An identical range is still an overlap. Extend it by one day so the
		// rejected write is always a partial overlap, which is SQLSTATE 23P01.
		if offset == 0 && overlapLen == length {
			overlapLen++
		}
		overlap := propPeriod(start+offset, start+offset+overlapLen)
		abut := propPeriod(start+length, start+length+abutLen)
		scopes := pgArray([]string{s.orgs[tenant]})

		propInsert(rt, tx, propFrom, 1, tenant, propBody, scopes, first)
		assertNoOverlap(rt, tx)
		before := propRows(rt, tx, tenant, propFrom)

		err := propTry(rt, tx, `
			INSERT INTO registry.decision_version (decision_id, version, tenant_id, body, scope_refs, valid_period)
			VALUES ($1::uuid, 2, $2::uuid, $3::jsonb, $4::text[]::uuid[], $5::text::tstzrange)`,
			propFrom, tenant, propBody, scopes, overlap)
		_ = wantState(rt, err, "23P01")
		if got := propRows(rt, tx, tenant, propFrom); got != before {
			rt.Fatalf("rejected overlap changed current rows from %q to %q", before, got)
		}
		assertNoOverlap(rt, tx)

		propInsert(rt, tx, propFrom, 2, tenant, propBody, scopes, abut)
		assertNoOverlap(rt, tx)
		if n := propCount(rt, tx, `
			SELECT count(*) FROM registry.decision_version
			WHERE tenant_id = $1::uuid AND decision_id = $2::uuid AND valid_period = $3::text::tstzrange`,
			tenant, propFrom, abut); n != 1 {
			rt.Fatalf("abutting period %s is present %d times, want 1", abut, n)
		}
	})
}

func TestPropertyScopeRefsDifferAcrossVersions(t *testing.T) {
	s := migrated(t)
	scopes := map[string][]string{}
	for _, tenant := range []string{tenantA, tenantB} {
		scopes[tenant] = []string{
			s.orgs[tenant],
			s.addScope(t, tenant, s.orgs[tenant], "repo", "acme/payments"),
			s.addScope(t, tenant, s.orgs[tenant], "repo", "acme/billing"),
		}
	}

	rapid.Check(t, func(rt *rapid.T) {
		tx := propBegin(rt, s.app)
		defer func() { _ = tx.Rollback() }()

		tenant := rapid.SampledFrom([]string{tenantA, tenantB}).Draw(rt, "tenant")
		firstMask := rapid.SampledFrom(scopeMasks).Draw(rt, "firstRefs")
		secondMask := propOtherMask(rt, "secondRefs", firstMask)
		correctedMask := propOtherMask(rt, "correctedRefs", firstMask)
		start := rapid.IntRange(0, 800).Draw(rt, "start")
		firstLen := rapid.IntRange(1, 30).Draw(rt, "firstLen")
		secondLen := rapid.IntRange(1, 30).Draw(rt, "secondLen")

		firstRefs := scopesForMask(scopes[tenant], firstMask)
		secondRefs := scopesForMask(scopes[tenant], secondMask)
		correctedRefs := scopesForMask(scopes[tenant], correctedMask)
		first := propPeriod(start, start+firstLen)
		second := propPeriod(start+firstLen, start+firstLen+secondLen)
		firstDay := propDay(start)
		secondDay := propDay(start + firstLen)

		propInsert(rt, tx, propFrom, 1, tenant, propBody, pgArray(firstRefs), first)
		propInsert(rt, tx, propFrom, 2, tenant, propBody, pgArray(secondRefs), second)
		assertNoOverlap(rt, tx)
		assertScopeAt(rt, tx, tenant, firstDay, firstRefs)
		assertScopeAt(rt, tx, tenant, secondDay, secondRefs)
		known := propSysAt(rt, tx, tenant, firstDay)

		propPause(rt, tx)
		res, err := tx.ExecContext(rt.Context(), `
			UPDATE registry.decision_version
			SET scope_refs = $1::text[]::uuid[]
			WHERE tenant_id = $2::uuid AND decision_id = $3::uuid AND valid_period @> $4::date::timestamptz`,
			pgArray(correctedRefs), tenant, propFrom, firstDay)
		if err != nil {
			rt.Fatalf("correct scope_refs: %v", err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			rt.Fatalf("corrected rows = %d, want 1", n)
		}
		assertNoOverlap(rt, tx)
		assertScopeAt(rt, tx, tenant, firstDay, correctedRefs)
		assertScopeAt(rt, tx, tenant, secondDay, secondRefs)
		assertScopeAsOf(rt, tx, tenant, known, firstDay, firstRefs)
		if n := propCount(rt, tx, `
			SELECT count(*) FROM registry.decision_version
			WHERE tenant_id = $1::uuid AND decision_id = $2::uuid
			  AND valid_period @> $3::date::timestamptz
			  AND scope_refs = $4::text[]::uuid[]`,
			tenant, propFrom, firstDay, pgArray(firstRefs)); n != 0 {
			rt.Fatalf("the correction left the previous scope_refs in force at %s", firstDay)
		}
	})
}

func TestPropertyTransactionTimeMovesForward(t *testing.T) {
	s := migrated(t)
	rapid.Check(t, func(rt *rapid.T) {
		tx := propBegin(rt, s.app)
		defer func() { _ = tx.Rollback() }()

		tenant := rapid.SampledFrom([]string{tenantA, tenantB}).Draw(rt, "tenant")
		insertPast := propPast(rt, "insert")
		updatePast := propPast(rt, "update")
		if updatePast == insertPast {
			updatePast = propShiftDay(updatePast)
		}
		versionPast := propPast(rt, "version")
		if versionPast == insertPast || versionPast == updatePast {
			versionPast = propShiftDay(versionPast)
			if versionPast == insertPast || versionPast == updatePast {
				versionPast = propShiftDay(versionPast)
			}
		}
		scopes := pgArray([]string{s.orgs[tenant]})
		valid := propPeriod(0, 365)

		before := propNow(rt, tx)
		propInsertAt(rt, tx, propFrom, 1, tenant, propBody, scopes, valid, propRange(rt, "insertClosed", insertPast))
		assertClocked(rt, tx, tenant, before)
		assertNotStored(rt, tx, tenant, insertPast)
		assertSysChain(rt, tx, tenant, 1)

		propPause(rt, tx)
		before = propNow(rt, tx)
		if _, err := tx.ExecContext(rt.Context(), `
			UPDATE registry.decision_version
			SET sys_period = $1::text::tstzrange
			WHERE tenant_id = $2::uuid AND decision_id = $3::uuid`,
			propRange(rt, "updateClosed", updatePast), tenant, propFrom); err != nil {
			rt.Fatalf("update sys_period: %v", err)
		}
		assertClocked(rt, tx, tenant, before)
		assertNotStored(rt, tx, tenant, insertPast, updatePast)
		assertSysChain(rt, tx, tenant, 2)

		propPause(rt, tx)
		before = propNow(rt, tx)
		if _, err := tx.ExecContext(rt.Context(), `
			UPDATE registry.decision_version
			SET version = version + 1, sys_period = $1::text::tstzrange
			WHERE tenant_id = $2::uuid AND decision_id = $3::uuid`,
			propRange(rt, "versionClosed", versionPast), tenant, propFrom); err != nil {
			rt.Fatalf("update version and sys_period: %v", err)
		}
		assertClocked(rt, tx, tenant, before)
		assertNotStored(rt, tx, tenant, insertPast, updatePast, versionPast)
		assertSysChain(rt, tx, tenant, 3)
		assertNoOverlap(rt, tx)
	})
}

func TestPropertyAsOfReadIsStable(t *testing.T) {
	s := migrated(t)
	rapid.Check(t, func(rt *rapid.T) {
		tx := propBegin(rt, s.app)
		defer func() { _ = tx.Rollback() }()

		tenant := rapid.SampledFrom([]string{tenantA, tenantB}).Draw(rt, "tenant")
		start := rapid.IntRange(0, 800).Draw(rt, "start")
		lead := rapid.IntRange(0, 30).Draw(rt, "lead")
		statement := "changed" + rapid.StringMatching(`[a-z]{1,8}`).Draw(rt, "statement")
		scopes := pgArray([]string{s.orgs[tenant]})
		valid := propOpenPeriod(start)
		at := propDay(start + lead)

		propInsert(rt, tx, propFrom, 1, tenant, propBody, scopes, valid)
		assertNoOverlap(rt, tx)
		known := propSysLower(rt, tx, tenant, propFrom)
		validAt := propDay(start)
		snapshot := propAsOf(rt, tx, tenant, known, validAt)
		if snapshot == "" {
			rt.Fatalf("as-of %s saw no rows", known)
		}

		propPause(rt, tx)
		res, err := tx.ExecContext(rt.Context(), `
			UPDATE registry.decision_version
			SET body = jsonb_build_object('statement', $1::text)
			WHERE tenant_id = $2::uuid AND decision_id = $3::uuid`,
			statement, tenant, propFrom)
		if err != nil {
			rt.Fatalf("correct body: %v", err)
		}
		if n, _ := res.RowsAffected(); n != 1 {
			rt.Fatalf("corrected rows = %d, want 1", n)
		}
		assertNoOverlap(rt, tx)
		if got := propAsOf(rt, tx, tenant, known, validAt); got != snapshot {
			rt.Fatalf("as-of after correction\n got %q\nwant %q", got, snapshot)
		}

		propPause(rt, tx)
		propInsert(rt, tx, propTo, 1, tenant, propBody, scopes, valid)
		if err := propTry(rt, tx, `
			INSERT INTO registry.supersession (tenant_id, from_decision, to_decision, effective_at)
			VALUES ($1::uuid, $2::uuid, $3::uuid, $4::date::timestamptz)`,
			tenant, propFrom, propTo, at); err != nil {
			rt.Fatalf("supersede at %s: %v", at, err)
		}
		assertNoOverlap(rt, tx)
		if got := propAsOf(rt, tx, tenant, known, validAt); got != snapshot {
			rt.Fatalf("as-of after supersession\n got %q\nwant %q", got, snapshot)
		}
	})
}

func TestPropertySupersessionChainsAreAcyclic(t *testing.T) {
	s := migrated(t)
	rapid.Check(t, func(rt *rapid.T) {
		tx := propBegin(rt, s.app)
		defer func() { _ = tx.Rollback() }()

		tenant := rapid.SampledFrom([]string{tenantA, tenantB}).Draw(rt, "tenant")
		length := rapid.IntRange(2, 3).Draw(rt, "chain")
		start := rapid.IntRange(0, 400).Draw(rt, "start")
		// The close sits strictly after the period start, so the superseded decision still
		// covers an earlier instant. The cycle attempt uses that instant and hits the cycle check.
		closeOffset := rapid.IntRange(2, 40).Draw(rt, "closeOffset")
		cycleOffset := rapid.IntRange(0, closeOffset-1).Draw(rt, "cycleOffset")
		ids := []string{propFrom, propTo, propThird}[:length]
		scopes := pgArray([]string{s.orgs[tenant]})
		valid := propOpenPeriod(start)
		closeAt := propDay(start + closeOffset)
		cycleAt := propDay(start + cycleOffset)

		for _, id := range ids {
			propInsert(rt, tx, id, 1, tenant, propBody, scopes, valid)
		}
		assertNoOverlap(rt, tx)

		var want [][2]string
		propPause(rt, tx)
		for i := 0; i < len(ids)-1; i++ {
			if err := propTry(rt, tx, `
				INSERT INTO registry.supersession (tenant_id, from_decision, to_decision, effective_at)
				VALUES ($1::uuid, $2::uuid, $3::uuid, $4::date::timestamptz)`,
				tenant, ids[i], ids[i+1], closeAt); err != nil {
				rt.Fatalf("supersede %s -> %s at %s: %v", ids[i], ids[i+1], closeAt, err)
			}
			want = append(want, [2]string{ids[i], ids[i+1]})
			assertNoOverlap(rt, tx)
			got := propEdges(rt, tx, tenant)
			if !sameEdges(got, want) {
				rt.Fatalf("edges = %v, want %v", got, want)
			}
			assertAcyclic(rt, got)
		}

		before := propEdges(rt, tx, tenant)
		err := propTry(rt, tx, `
			INSERT INTO registry.supersession (tenant_id, from_decision, to_decision, effective_at)
			VALUES ($1::uuid, $2::uuid, $3::uuid, $4::date::timestamptz)`,
			tenant, ids[len(ids)-1], ids[0], cycleAt)
		pgErr := wantState(rt, err, "23514")
		if !strings.Contains(pgErr.Message, "already superseded") {
			rt.Fatalf("cycle message = %q, want it to say the successor is already superseded", pgErr.Message)
		}
		if got := propEdges(rt, tx, tenant); !sameEdges(got, before) {
			rt.Fatalf("rejected cycle changed edges from %v to %v", before, got)
		}
		assertAcyclic(rt, before)

		// The last decision is not a from_decision and still covers the close, so the
		// refusal is the self check.
		err = propTry(rt, tx, `
			INSERT INTO registry.supersession (tenant_id, from_decision, to_decision, effective_at)
			VALUES ($1::uuid, $2::uuid, $3::uuid, $4::date::timestamptz)`,
			tenant, ids[len(ids)-1], ids[len(ids)-1], closeAt)
		pgErr = wantState(rt, err, "23514")
		if pgErr.ConstraintName != "supersession_not_self" {
			rt.Fatalf("constraint = %q, want supersession_not_self", pgErr.ConstraintName)
		}
		if got := propEdges(rt, tx, tenant); !sameEdges(got, before) {
			rt.Fatalf("rejected self-edge changed edges from %v to %v", before, got)
		}
		assertAcyclic(rt, propEdges(rt, tx, tenant))
		assertNoOverlap(rt, tx)
	})
}

func TestPropertyWaiverNeverExtendsBeyondTheDecision(t *testing.T) {
	s := migrated(t)
	outside := map[string]string{}
	for _, tenant := range []string{tenantA, tenantB} {
		outside[tenant] = s.addScope(t, tenant, "", "org", "other")
	}

	rapid.Check(t, func(rt *rapid.T) {
		tx := propBegin(rt, s.app)
		defer func() { _ = tx.Rollback() }()

		tenant := rapid.SampledFrom([]string{tenantA, tenantB}).Draw(rt, "tenant")
		start := rapid.IntRange(10, 400).Draw(rt, "start")
		decisionLen := rapid.IntRange(150, 200).Draw(rt, "decisionLen")
		insideLen := rapid.IntRange(1, 60).Draw(rt, "insideLen")
		insideOffset := rapid.IntRange(0, decisionLen-insideLen).Draw(rt, "insideOffset")
		longLen := rapid.IntRange(91, 120).Draw(rt, "longLen")
		past := rapid.IntRange(1, 30).Draw(rt, "past")

		decision := propPeriod(start, start+decisionLen)
		inside := propPeriod(start+insideOffset, start+insideOffset+insideLen)
		tooLong := propPeriod(start, start+longLen)
		sticksOut := propPeriod(start, start+decisionLen+past)
		scope := s.orgs[tenant]

		propInsert(rt, tx, propFrom, 1, tenant, propBody, pgArray([]string{scope}), decision)
		if err := propTryWaiver(rt, tx, tenant, propFrom, scope, inside); err != nil {
			rt.Fatalf("contained waiver %s: %v", inside, err)
		}
		assertWaiversInside(rt, tx, tenant)

		before := propWaiverCount(rt, tx, tenant, propFrom)
		_ = wantState(rt, propTryWaiver(rt, tx, tenant, propFrom, scope, tooLong), "23514")
		_ = wantState(rt, propTryWaiver(rt, tx, tenant, propFrom, scope, sticksOut), "23514")
		_ = wantState(rt, propTryWaiver(rt, tx, tenant, propFrom, outside[tenant], inside), "23514")
		if got := propWaiverCount(rt, tx, tenant, propFrom); got != before {
			rt.Fatalf("rejected waivers changed the count from %d to %d", before, got)
		}
		assertWaiversInside(rt, tx, tenant)
	})
}

func propTryWaiver(rt *rapid.T, tx *sql.Tx, tenant, decision, scope, valid string) error {
	return propTry(rt, tx, `
		INSERT INTO registry.waiver
			(tenant_id, decision_id, scope_id, reason, approver, valid_period, ticket_ref)
		VALUES ($1::uuid, $2::uuid, $3::uuid, 'synthetic exception', 'team:platform',
		        $4::text::tstzrange, 'TICKET-1')`,
		tenant, decision, scope, valid)
}

func propWaiverCount(rt *rapid.T, tx *sql.Tx, tenant, decision string) int {
	return propCount(rt, tx, `
		SELECT count(*) FROM registry.waiver
		WHERE tenant_id = $1::uuid AND decision_id = $2::uuid`, tenant, decision)
}

func assertWaiversInside(rt *rapid.T, tx *sql.Tx, tenant string) {
	n := propCount(rt, tx, `
		SELECT count(*)
		FROM registry.waiver w
		WHERE w.tenant_id = $1::uuid
		  AND NOT EXISTS (
		      SELECT 1
		      FROM registry.decision_version d
		      WHERE d.tenant_id = w.tenant_id
		        AND d.decision_id = w.decision_id
		        AND d.valid_period @> w.valid_period)`, tenant)
	if n != 0 {
		rt.Fatalf("%d waivers extend beyond the decision", n)
	}
}

func propBegin(rt *rapid.T, db *sql.DB) *sql.Tx {
	tx, err := db.BeginTx(rt.Context(), nil)
	if err != nil {
		rt.Fatalf("begin: %v", err)
	}
	return tx
}

// propTry applies one statement. A failure rolls back to the savepoint so the
// example can keep writing.
func propTry(rt *rapid.T, tx *sql.Tx, query string, args ...any) error {
	if _, err := tx.ExecContext(rt.Context(), `SAVEPOINT prop_sp`); err != nil {
		rt.Fatalf("savepoint: %v", err)
	}
	_, err := tx.ExecContext(rt.Context(), query, args...)
	if err != nil {
		if _, rbErr := tx.ExecContext(rt.Context(), `ROLLBACK TO SAVEPOINT prop_sp`); rbErr != nil {
			rt.Fatalf("rollback savepoint: %v (statement: %v)", rbErr, err)
		}
	}
	if _, relErr := tx.ExecContext(rt.Context(), `RELEASE SAVEPOINT prop_sp`); relErr != nil {
		rt.Fatalf("release savepoint: %v", relErr)
	}
	return err
}

func propInsert(rt *rapid.T, tx *sql.Tx, id string, version int, tenant, body, scopes, valid string) {
	if _, err := tx.ExecContext(rt.Context(), `
		INSERT INTO registry.decision_version (decision_id, version, tenant_id, body, scope_refs, valid_period)
		VALUES ($1::uuid, $2::int, $3::uuid, $4::jsonb, $5::text[]::uuid[], $6::text::tstzrange)`,
		id, version, tenant, body, scopes, valid); err != nil {
		rt.Fatalf("insert %s %s: %v", id, valid, err)
	}
}

func propInsertAt(rt *rapid.T, tx *sql.Tx, id string, version int, tenant, body, scopes, valid, sys string) {
	if _, err := tx.ExecContext(rt.Context(), `
		INSERT INTO registry.decision_version
			(decision_id, version, tenant_id, body, scope_refs, valid_period, sys_period)
		VALUES ($1::uuid, $2::int, $3::uuid, $4::jsonb, $5::text[]::uuid[], $6::text::tstzrange, $7::text::tstzrange)`,
		id, version, tenant, body, scopes, valid, sys); err != nil {
		rt.Fatalf("insert %s at %s: %v", id, sys, err)
	}
}

func propPause(rt *rapid.T, tx *sql.Tx) {
	if _, err := tx.ExecContext(rt.Context(), `SELECT pg_sleep(0.02)`); err != nil {
		rt.Fatalf("sleep: %v", err)
	}
}

func propNow(rt *rapid.T, tx *sql.Tx) time.Time {
	var now time.Time
	if err := tx.QueryRowContext(rt.Context(), `SELECT clock_timestamp()`).Scan(&now); err != nil {
		rt.Fatalf("clock: %v", err)
	}
	return now
}

func propCount(rt *rapid.T, tx *sql.Tx, query string, args ...any) int {
	var n int
	if err := tx.QueryRowContext(rt.Context(), query, args...).Scan(&n); err != nil {
		rt.Fatalf("%s: %v", query, err)
	}
	return n
}

func propRows(rt *rapid.T, tx *sql.Tx, tenant, decision string) string {
	var rows string
	err := tx.QueryRowContext(rt.Context(), `
		SELECT coalesce(string_agg(
			version::text || '=' || valid_period::text || '=' || scope_refs::text,
			',' ORDER BY valid_period::text, version), '')
		FROM registry.decision_version
		WHERE tenant_id = $1::uuid AND decision_id = $2::uuid`, tenant, decision).Scan(&rows)
	if err != nil {
		rt.Fatalf("current rows: %v", err)
	}
	return rows
}

func assertNoOverlap(rt *rapid.T, tx *sql.Tx) {
	n := propCount(rt, tx, `
		SELECT count(*)
		FROM registry.decision_version a
		JOIN registry.decision_version b
		  ON a.tenant_id = b.tenant_id
		 AND a.decision_id = b.decision_id
		 AND a.ctid <> b.ctid
		 AND a.valid_period && b.valid_period`)
	if n != 0 {
		rt.Fatalf("%d overlapping current valid periods", n)
	}
}

func propSysAt(rt *rapid.T, tx *sql.Tx, tenant, day string) time.Time {
	var from time.Time
	err := tx.QueryRowContext(rt.Context(), `
		SELECT lower(sys_period) FROM registry.decision_version
		WHERE tenant_id = $1::uuid AND decision_id = $2::uuid
		  AND valid_period @> $3::date::timestamptz`, tenant, propFrom, day).Scan(&from)
	if err != nil {
		rt.Fatalf("sys lower at %s: %v", day, err)
	}
	return from
}

func assertScopeAsOf(rt *rapid.T, tx *sql.Tx, tenant string, known time.Time, day string, refs []string) {
	n := propCount(rt, tx, `
		SELECT count(*) FROM registry.decision_version_all
		WHERE tenant_id = $1::uuid AND decision_id = $2::uuid
		  AND sys_period @> $3::timestamptz
		  AND valid_period @> $4::date::timestamptz
		  AND scope_refs = $5::text[]::uuid[]`,
		tenant, propFrom, known, day, pgArray(refs))
	if n != 1 {
		rt.Fatalf("as-of scope_refs %s at %s matched %d rows, want 1", pgArray(refs), day, n)
	}
}

func assertScopeAt(rt *rapid.T, tx *sql.Tx, tenant, day string, refs []string) {
	n := propCount(rt, tx, `
		SELECT count(*) FROM registry.decision_version
		WHERE tenant_id = $1::uuid AND decision_id = $2::uuid
		  AND valid_period @> $3::date::timestamptz
		  AND scope_refs = $4::text[]::uuid[]`,
		tenant, propFrom, day, pgArray(refs))
	if n != 1 {
		rt.Fatalf("scope_refs %s at %s matched %d current rows, want 1", pgArray(refs), day, n)
	}
}

func assertClocked(rt *rapid.T, tx *sql.Tx, tenant string, before time.Time) {
	var from time.Time
	var open bool
	err := tx.QueryRowContext(rt.Context(), `
		SELECT lower(sys_period), upper(sys_period) IS NULL
		FROM registry.decision_version
		WHERE tenant_id = $1::uuid AND decision_id = $2::uuid`, tenant, propFrom).Scan(&from, &open)
	if err != nil {
		rt.Fatalf("sys_period: %v", err)
	}
	if !open || from.Before(before) {
		rt.Fatalf("sys_period opens at %v (open %v), want an open period from %v or later", from, open, before)
	}
}

func assertNotStored(rt *rapid.T, tx *sql.Tx, tenant string, past ...string) {
	for _, bound := range past {
		n := propCount(rt, tx, `
			SELECT count(*) FROM registry.decision_version_all
			WHERE tenant_id = $1::uuid AND decision_id = $2::uuid
			  AND lower(sys_period) = $3::timestamptz`, tenant, propFrom, bound)
		if n != 0 {
			rt.Fatalf("stored backdated sys_period %s", bound)
		}
	}
}

// assertSysChain requires one lineage: each closed sys_period ends where the next
// begins, and only the latest row is open.
func assertSysChain(rt *rapid.T, tx *sql.Tx, tenant string, want int) {
	rows, err := tx.QueryContext(rt.Context(), `
		SELECT lower(sys_period), upper(sys_period) IS NULL, coalesce(upper(sys_period), lower(sys_period))
		FROM registry.decision_version_all
		WHERE tenant_id = $1::uuid AND decision_id = $2::uuid
		ORDER BY lower(sys_period), upper(sys_period) NULLS LAST`, tenant, propFrom)
	if err != nil {
		rt.Fatalf("sys chain: %v", err)
	}
	defer func() { _ = rows.Close() }()

	type span struct {
		lower time.Time
		open  bool
		upper time.Time
	}
	var spans []span
	for rows.Next() {
		var item span
		if err := rows.Scan(&item.lower, &item.open, &item.upper); err != nil {
			rt.Fatalf("sys chain row: %v", err)
		}
		spans = append(spans, item)
	}
	if err := rows.Err(); err != nil {
		rt.Fatalf("sys chain rows: %v", err)
	}
	if len(spans) != want {
		rt.Fatalf("sys_period rows = %d, want %d", len(spans), want)
	}
	for i := 0; i < len(spans)-1; i++ {
		if spans[i].open || !spans[i].upper.Equal(spans[i+1].lower) {
			rt.Fatalf("sys_period %d ends at %v (open %v), next starts at %v", i, spans[i].upper, spans[i].open, spans[i+1].lower)
		}
	}
	if last := spans[len(spans)-1]; !last.open {
		rt.Fatalf("latest sys_period is closed at %v", last.upper)
	}
}

func propSysLower(rt *rapid.T, tx *sql.Tx, tenant, decision string) time.Time {
	var from time.Time
	err := tx.QueryRowContext(rt.Context(), `
		SELECT lower(sys_period) FROM registry.decision_version
		WHERE tenant_id = $1::uuid AND decision_id = $2::uuid`, tenant, decision).Scan(&from)
	if err != nil {
		rt.Fatalf("sys lower: %v", err)
	}
	return from
}

// propAsOf reads the belief in force at validAt as known at known. sys_period is
// omitted from the payload: archiving closes that column, and the belief itself
// is what an as-of read must keep.
func propAsOf(rt *rapid.T, tx *sql.Tx, tenant string, known time.Time, validAt string) string {
	var snapshot string
	err := tx.QueryRowContext(rt.Context(), `
		SELECT coalesce(string_agg(
			decision_id::text || '|' || version::text || '|' || body::text || '|' || scope_refs::text || '|' || valid_period::text,
			E'\n' ORDER BY decision_id::text, version, valid_period::text, scope_refs::text, body::text), '')
		FROM registry.decision_version_all
		WHERE tenant_id = $1::uuid
		  AND sys_period @> $2::timestamptz
		  AND valid_period @> $3::date::timestamptz`, tenant, known, validAt).Scan(&snapshot)
	if err != nil {
		rt.Fatalf("as-of: %v", err)
	}
	return snapshot
}

func propEdges(rt *rapid.T, tx *sql.Tx, tenant string) [][2]string {
	rows, err := tx.QueryContext(rt.Context(), `
		SELECT from_decision::text, to_decision::text
		FROM registry.supersession
		WHERE tenant_id = $1::uuid
		ORDER BY from_decision::text`, tenant)
	if err != nil {
		rt.Fatalf("edges: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var edges [][2]string
	for rows.Next() {
		var from, to string
		if err := rows.Scan(&from, &to); err != nil {
			rt.Fatalf("edge: %v", err)
		}
		edges = append(edges, [2]string{from, to})
	}
	if err := rows.Err(); err != nil {
		rt.Fatalf("edges: %v", err)
	}
	return edges
}

func assertAcyclic(rt *rapid.T, edges [][2]string) {
	next := make(map[string]string, len(edges))
	for _, edge := range edges {
		if _, ok := next[edge[0]]; ok {
			rt.Fatalf("decision %s has two successors", edge[0])
		}
		next[edge[0]] = edge[1]
	}
	for start := range next {
		seen := map[string]bool{}
		for at := start; ; {
			if seen[at] {
				rt.Fatalf("supersession cycle includes %s", at)
			}
			seen[at] = true
			to, ok := next[at]
			if !ok {
				break
			}
			at = to
		}
	}
}

func sameEdges(got, want [][2]string) bool {
	if len(got) != len(want) {
		return false
	}
	n := make(map[[2]string]int, len(got))
	for _, edge := range got {
		n[edge]++
	}
	for _, edge := range want {
		if n[edge] == 0 {
			return false
		}
		n[edge]--
	}
	return true
}

func wantState(rt *rapid.T, err error, state string) *pgconn.PgError {
	if err == nil {
		rt.Fatalf("want SQLSTATE %s, got success", state)
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != state {
		rt.Fatalf("want SQLSTATE %s, got %v", state, err)
	}
	return pgErr
}

func propOtherMask(rt *rapid.T, name string, other int) int {
	shift := rapid.IntRange(1, len(scopeMasks)-1).Draw(rt, name)
	at := 0
	for i, mask := range scopeMasks {
		if mask == other {
			at = i
			break
		}
	}
	return scopeMasks[(at+shift)%len(scopeMasks)]
}

func scopesForMask(ids []string, mask int) []string {
	var out []string
	for i, id := range ids {
		if mask&(1<<i) != 0 {
			out = append(out, id)
		}
	}
	return out
}

func propDay(offset int) string {
	return propEpoch.AddDate(0, 0, offset).Format("2006-01-02")
}

func propPeriod(start, end int) string {
	return "[" + propDay(start) + "," + propDay(end) + ")"
}

func propOpenPeriod(start int) string {
	return "[" + propDay(start) + ",)"
}

func propPast(rt *rapid.T, name string) string {
	year := rapid.IntRange(1990, 1999).Draw(rt, name+"Year")
	month := rapid.IntRange(1, 12).Draw(rt, name+"Month")
	day := rapid.IntRange(1, 28).Draw(rt, name+"Day")
	return fmt.Sprintf("%04d-%02d-%02d", year, month, day)
}

func propShiftDay(day string) string {
	parsed, err := time.Parse("2006-01-02", day)
	if err != nil {
		return "1989-01-01"
	}
	return parsed.AddDate(0, 0, 1).Format("2006-01-02")
}

func propRange(rt *rapid.T, name, lower string) string {
	if rapid.Bool().Draw(rt, name) {
		parsed, err := time.Parse("2006-01-02", lower)
		if err != nil {
			rt.Fatalf("past date %s: %v", lower, err)
		}
		return "[" + lower + "," + parsed.AddDate(0, 0, 30).Format("2006-01-02") + ")"
	}
	return "[" + lower + ",)"
}
