package registry

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// PremiseRef names one premise: the decision that carries it and its id on that decision.
type PremiseRef struct {
	Decision uuid.UUID
	ID       string
}

// Premise is what the probe of ADR-0053 needs, read from the body of a decision in force. Expected is
// the compact JSON the comparison holds: the value of equals, or the semver constraint as a JSON string.
type Premise struct {
	Ref       PremiseRef
	URL       string
	Pointer   string
	Expected  json.RawMessage
	HasEquals bool
}

// Evaluation is one probe result to record. Observed and BodySHA256 are nil for an error that read
// nothing. BodySHA256 is the 32 bytes of the digest.
type Evaluation struct {
	Ref        PremiseRef
	Result     string
	URL        string
	Pointer    string
	Expected   json.RawMessage
	Observed   json.RawMessage
	BodySHA256 []byte
}

// A premise is on the body of a decision version whose valid period holds the database clock, which is
// the decision in force now, and it is recordable when it would pass the checks of
// registry.premise_evaluation: a kebab-case id of at most 128 characters, since a job carries it, an interval of 1 to 365 days, an https URL with a name
// as its host, a JSON Pointer, and exactly one comparison of at most 1024 bytes. A premise that is not
// recordable cannot be stored, so it is counted and left alone (ADR-0098). The patterns are those of
// migration 00006. The casts run only where a pattern has matched, since a plan may evaluate the other
// conditions in any order.
//
// Due is the rule of ADR-0053: no evaluation yet, or a latest evaluation that began at least every * 24
// hours ago. The latest evaluation is the greatest (start of sys_period, id), the order the reason
// trigger uses. Days are fixed 24 hour intervals so the session time zone cannot move a premise across
// a daylight saving change. There is no next_run column. %s is an extra condition on the decision.
const premiseState = `
WITH items AS (
    SELECT d.tenant_id, d.decision_id, p.item
    FROM registry.decision_version d
    CROSS JOIN LATERAL jsonb_array_elements(
        CASE WHEN jsonb_typeof(d.body -> 'premises') = 'array' THEN d.body -> 'premises' ELSE '[]'::jsonb END
    ) AS p(item)
    WHERE d.tenant_id = ipso.current_tenant()
      AND d.valid_period @> now()
      %s
), fields AS (
    SELECT i.tenant_id, i.decision_id,
           CASE WHEN jsonb_typeof(i.item -> 'id') = 'string' THEN i.item ->> 'id' END AS premise_id,
           CASE WHEN jsonb_typeof(i.item -> 'every') = 'number' AND (i.item ->> 'every') ~ '^[0-9]{1,3}$'
                THEN (i.item ->> 'every')::int END AS every_days,
           CASE WHEN jsonb_typeof(i.item -> 'probe' -> 'url') = 'string' THEN i.item -> 'probe' ->> 'url' END AS url,
           CASE WHEN jsonb_typeof(i.item -> 'probe' -> 'pointer') = 'string' THEN i.item -> 'probe' ->> 'pointer' END AS pointer,
           coalesce(jsonb_typeof(i.item -> 'probe') = 'object' AND jsonb_exists(i.item -> 'probe', 'equals'), false) AS has_equals,
           coalesce(jsonb_typeof(i.item -> 'probe') = 'object' AND jsonb_exists(i.item -> 'probe', 'semver'), false) AS has_semver,
           i.item -> 'probe' -> 'equals' AS equals,
           i.item -> 'probe' -> 'semver' AS semver
    FROM items i
), expected AS (
    SELECT f.*,
           CASE WHEN f.has_equals AND NOT f.has_semver THEN f.equals
                WHEN f.has_semver AND NOT f.has_equals THEN f.semver END AS expected
    FROM fields f
), recordable AS (
    SELECT x.*,
           coalesce(
               x.premise_id ~ '^[a-z0-9]+(-[a-z0-9]+)*$'
               AND char_length(x.premise_id) <= 128
               AND x.every_days BETWEEN 1 AND 365
               AND char_length(x.url) BETWEEN 1 AND 2048
               AND x.url ~ '^https://[^[:space:]/:@?#]+(:443)?([/?][^[:space:]#]*)?$'
               AND x.url !~ '^https://[0-9.]+(:443)?([/?][^[:space:]#]*)?$'
               AND x.pointer ~ '^(/([^/~]|~[01])*)*$'
               AND x.expected IS NOT NULL
               AND octet_length(x.expected::text) <= 1024
               AND (NOT x.has_semver OR (jsonb_typeof(x.semver) = 'string' AND (x.semver #>> '{}') <> '')),
               false) AS recordable
    FROM expected x
), state AS (
    SELECT r.*,
           (r.recordable AND (latest.evaluated_at IS NULL OR latest.evaluated_at <= now() - r.every_days * interval '24 hours')) AS due
    FROM recordable r
    LEFT JOIN LATERAL (
        SELECT lower(e.sys_period) AS evaluated_at
        FROM registry.premise_evaluation e
        WHERE e.tenant_id = r.tenant_id
          AND e.decision_id = r.decision_id
          AND e.premise_id = r.premise_id
        ORDER BY lower(e.sys_period) DESC, e.id DESC
        LIMIT 1
    ) latest ON r.recordable
)`

const (
	// duePremises reads every premise on a decision in force that is due, and every one that cannot be
	// recorded, whose id is whatever the body holds or nothing.
	duePremises = `SELECT decision_id, premise_id, recordable FROM state WHERE due OR NOT recordable ORDER BY decision_id, premise_id`

	// duePremise reads one premise that is recordable and due.
	duePremise = `SELECT url, pointer, expected::text, has_equals FROM state WHERE due AND premise_id = $2`

	hostAllowed = `
SELECT allowed
FROM registry.premise_host_allow
WHERE tenant_id = ipso.current_tenant() AND host = $1
ORDER BY lower(sys_period) DESC, id DESC
LIMIT 1`

	// insertEvaluation stores the result. The probe limits the observed value in compact JSON, and the table
	// limits its jsonb text, which adds a space after each comma and colon and writes 1e2000 in full. A
	// value over the table's limit is stored as an error that holds no observed value, so a response like
	// that is recorded once and not probed again every hour. The stored result comes back, because only a
	// stored fail opens a reason.
	insertEvaluation = `
WITH given AS (
    SELECT $7::jsonb AS expected, $8::jsonb AS observed
), checked AS (
    SELECT g.*, (g.observed IS NOT NULL AND octet_length(g.observed::text) > 1024) AS too_big
    FROM given g
)
INSERT INTO registry.premise_evaluation
    (tenant_id, decision_id, premise_id, result, url, pointer, expected, observed, body_sha256)
SELECT $1::uuid, $2::uuid, $3::text,
       CASE WHEN c.too_big THEN 'error' ELSE $4::text END,
       $5::text, $6::text, c.expected,
       CASE WHEN c.too_big THEN NULL ELSE c.observed END,
       $9::bytea
FROM checked c
RETURNING id, result`

	// insertReason opens a reason for the evaluation unless one is open for the premise. The evaluation
	// insert holds the advisory lock of the premise until commit, so no other writer slips in between.
	insertReason = `
INSERT INTO registry.premise_reason (tenant_id, decision_id, premise_id, evaluation_id)
SELECT $1::uuid, $2::uuid, $3::text, $4::uuid
WHERE NOT EXISTS (
    SELECT 1
    FROM registry.premise_reason r
    WHERE r.tenant_id = ipso.current_tenant()
      AND r.decision_id = $2::uuid
      AND r.premise_id = $3::text
      AND NOT EXISTS (
          SELECT 1
          FROM registry.premise_clearance c
          WHERE c.tenant_id = r.tenant_id AND c.reason_id = r.id))`
)

// DuePremises returns the premises of the decisions in force that are due for a probe, ordered by
// decision and premise id, and how many premises on those decisions it left out because they cannot be
// recorded. The database clock decides what is due. The tenant must be the one this process serves,
// because DuePremises trusts it.
func DuePremises(ctx context.Context, db *sql.DB, tenant uuid.UUID) ([]PremiseRef, int, error) {
	if tenant == uuid.Nil {
		return nil, 0, fmt.Errorf("%w: no tenant", ErrInvalidQuery)
	}
	var refs []PremiseRef
	seen := map[PremiseRef]struct{}{}
	skipped := 0
	err := readTx(ctx, db, tenant, func(ctx context.Context, tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, fmt.Sprintf(premiseState, "")+duePremises)
		if err != nil {
			return fmt.Errorf("read due premises: %w", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var (
				decision   uuid.UUID
				id         sql.NullString
				recordable bool
			)
			if err := rows.Scan(&decision, &id, &recordable); err != nil {
				return fmt.Errorf("read due premises: %w", err)
			}
			if !recordable {
				skipped++
				continue
			}
			// A body can list one id twice. The first one is the one DuePremise reads, so one job is enough,
			// and a batch of unique jobs holds no key twice.
			ref := PremiseRef{Decision: decision, ID: id.String}
			if _, dup := seen[ref]; !dup {
				seen[ref] = struct{}{}
				refs = append(refs, ref)
			}
		}
		return rows.Err()
	})
	if err != nil {
		return nil, 0, err
	}
	return refs, skipped, nil
}

// DuePremise returns the premise when its decision is in force, it can be recorded, and it is due, and
// false otherwise. A probe job asks again before it fetches, so a job queued before another probe
// wrote an evaluation, or before the decision was superseded, writes nothing.
func DuePremise(ctx context.Context, db *sql.DB, tenant uuid.UUID, ref PremiseRef) (Premise, bool, error) {
	if tenant == uuid.Nil || ref.Decision == uuid.Nil || ref.ID == "" {
		return Premise{}, false, fmt.Errorf("%w: no tenant or premise", ErrInvalidQuery)
	}
	got := Premise{Ref: ref}
	found := false
	err := readTx(ctx, db, tenant, func(ctx context.Context, tx *sql.Tx) error {
		var expected string
		err := tx.QueryRowContext(ctx, fmt.Sprintf(premiseState, "AND d.decision_id = $1")+duePremise, ref.Decision, ref.ID).
			Scan(&got.URL, &got.Pointer, &expected, &got.HasEquals)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read a premise: %w", err)
		}
		got.Expected = json.RawMessage(expected)
		found = true
		return nil
	})
	if err != nil {
		return Premise{}, false, err
	}
	return got, found, nil
}

// HostAllowed reports whether the latest allowlist row of the tenant for host says allowed. An empty
// allowlist allows no host, and a host with no row is not allowed (ADR-0053). The host is the
// lowercase name the probe dials, compared exactly.
func HostAllowed(ctx context.Context, db *sql.DB, tenant uuid.UUID, host string) (bool, error) {
	if tenant == uuid.Nil || host == "" {
		return false, fmt.Errorf("%w: no tenant or host", ErrInvalidQuery)
	}
	allowed := false
	err := readTx(ctx, db, tenant, func(ctx context.Context, tx *sql.Tx) error {
		err := tx.QueryRowContext(ctx, hostAllowed, host).Scan(&allowed)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read the allowlist: %w", err)
		}
		return nil
	})
	return allowed, err
}

// RecordEvaluation inserts the evaluation and, for a fail, opens a review reason for it unless one is
// already open for the premise. It reports whether a reason was opened. An observed value that is over the
// table's limit once written as jsonb is not stored: the evaluation becomes an error without it. A pass or an error never
// opens or clears a reason, and nothing here writes a decision version, so a fail cannot change a
// valid period or a stored status. The reason trigger refuses a repeatable read transaction, so this
// one is READ COMMITTED, with ipso.tenant set for that transaction only. The tenant must be the one
// this process serves.
func RecordEvaluation(ctx context.Context, db *sql.DB, tenant uuid.UUID, ev Evaluation) (bool, error) {
	if tenant == uuid.Nil || ev.Ref.Decision == uuid.Nil || ev.Ref.ID == "" {
		return false, fmt.Errorf("%w: no tenant or premise", ErrInvalidQuery)
	}
	switch ev.Result {
	case "pass", "fail", "error":
	default:
		return false, fmt.Errorf("%w: unknown result", ErrInvalidQuery)
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return false, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('ipso.tenant', $1, true)`, tenant.String()); err != nil {
		return false, fmt.Errorf("set the tenant: %w", err)
	}
	var (
		evaluation uuid.UUID
		stored     string
	)
	if err := tx.QueryRowContext(ctx, insertEvaluation,
		tenant, ev.Ref.Decision, ev.Ref.ID, ev.Result, ev.URL, ev.Pointer,
		string(ev.Expected), nullableJSON(ev.Observed), nullableBytes(ev.BodySHA256),
	).Scan(&evaluation, &stored); err != nil {
		return false, fmt.Errorf("record an evaluation: %w", err)
	}
	opened := false
	if stored == "fail" {
		res, err := tx.ExecContext(ctx, insertReason, tenant, ev.Ref.Decision, ev.Ref.ID, evaluation)
		if err != nil {
			return false, fmt.Errorf("open a reason: %w", err)
		}
		n, err := res.RowsAffected()
		if err != nil {
			return false, fmt.Errorf("open a reason: %w", err)
		}
		opened = n == 1
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit: %w", err)
	}
	return opened, nil
}

func nullableJSON(raw json.RawMessage) any {
	if len(raw) == 0 {
		return nil
	}
	return string(raw)
}

func nullableBytes(raw []byte) any {
	if len(raw) == 0 {
		return nil
	}
	return raw
}
