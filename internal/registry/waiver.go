package registry

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// Outcome is the verdict word from ADR-0030. OutcomeFail is the zero value so a
// caller that forgets the error does not treat it as a pass.
type Outcome int

const (
	// OutcomeFail means the violations are not covered by a waiver in force.
	// It is the zero value. Fail is already the grandfather result.
	OutcomeFail Outcome = iota
	// OutcomePass means the check produced no violation. A waiver does not change it.
	OutcomePass
	// OutcomeWaived means a waiver in force covers the violations of the decision.
	OutcomeWaived
	// OutcomeError means the check did not finish. A waiver does not cover it,
	// and Apply does not read the database for it.
	OutcomeError
)

// String returns the verdict word.
func (o Outcome) String() string {
	switch o {
	case OutcomePass:
		return "pass"
	case OutcomeFail:
		return "fail"
	case OutcomeWaived:
		return "waived"
	case OutcomeError:
		return "error"
	default:
		return fmt.Sprintf("outcome(%d)", int(o))
	}
}

// waiverCovers is true when a waiver of the decision was recorded by T, is in
// force at V, names a scope the subject matches, and the decision itself covers
// V as known at T. A waiver that sticks out past a shortened decision does not
// match, because the decision row has to contain V.
const waiverCovers = `
SELECT EXISTS (
    SELECT 1
    FROM registry.waiver w
    WHERE w.tenant_id = nullif(current_setting('ipso.tenant', true), '')::uuid
      AND w.decision_id = $1
      AND w.scope_id = ANY($2::uuid[])
      AND w.valid_period @> $3::timestamptz
      AND w.sys_period @> $4::timestamptz
      AND EXISTS (
          SELECT 1
          FROM registry.decision_version_all d
          WHERE d.tenant_id = w.tenant_id
            AND d.decision_id = w.decision_id
            AND d.valid_period @> $3::timestamptz
            AND d.sys_period @> $4::timestamptz
      )
)`

// Apply reports the outcome of one check after waivers. A fail becomes waived
// when a waiver of decision covers the subject at valid time validAt, as the
// registry knew the waiver at transaction time knownAt. pass, waived, and error
// are returned unchanged. An error does not read the database, so a damaged
// waiver row cannot replace the evaluation error.
//
// The tenant must be the authenticated one, because Apply trusts it. The read
// is one read-only REPEATABLE READ transaction with ipso.tenant set, the same
// way Resolve reads. A waiver recorded after knownAt does not change the answer.
// A nil tenant or decision, a zero time, an unknown outcome, or a subject that
// breaks the selector rules is an error. The outcome is meaningful only when
// err is nil.
func Apply(ctx context.Context, db *sql.DB, tenant, decision uuid.UUID, in Subject, outcome Outcome, validAt, knownAt time.Time) (Outcome, error) {
	if tenant == uuid.Nil {
		return OutcomeFail, fmt.Errorf("%w: no tenant", ErrInvalidQuery)
	}
	if decision == uuid.Nil {
		return OutcomeFail, fmt.Errorf("%w: no decision", ErrInvalidQuery)
	}
	if validAt.IsZero() || knownAt.IsZero() {
		return OutcomeFail, fmt.Errorf("%w: the valid time and the transaction time are required", ErrInvalidQuery)
	}
	switch outcome {
	case OutcomePass, OutcomeWaived, OutcomeError:
		return outcome, nil
	case OutcomeFail:
	default:
		return OutcomeFail, fmt.Errorf("%w: unknown outcome", ErrInvalidQuery)
	}

	subject, err := newSubject(in)
	if err != nil {
		return OutcomeFail, err
	}
	var covered bool
	err = readTx(ctx, db, tenant, func(ctx context.Context, tx *sql.Tx) error {
		matched, err := matchingScopes(ctx, tx, subject, knownAt)
		if err != nil {
			return err
		}
		if len(matched) == 0 {
			return nil
		}
		scopes, err := ancestorsOf(ctx, tx, matched)
		if err != nil {
			return err
		}
		return tx.QueryRowContext(ctx, waiverCovers, decision, scopes, validAt, knownAt).Scan(&covered)
	})
	if err != nil {
		return OutcomeFail, err
	}
	if covered {
		return OutcomeWaived, nil
	}
	return OutcomeFail, nil
}

// Notify records the expiry notices that are due for tenant. A notice is one
// row for 14, 3, or 0 days before the waiver ends, and it copies ticket_ref
// from the waiver. The database clock decides what is due. A second call
// records nothing new. A waiver the current decision no longer contains is
// skipped. The count is meaningful only when err is nil.
//
// The tenant must be the authenticated one, because Notify trusts it. The write
// is one REPEATABLE READ transaction with ipso.tenant set for that transaction
// only. A nil tenant is an error and writes nothing.
func Notify(ctx context.Context, db *sql.DB, tenant uuid.UUID) (int, error) {
	if tenant == uuid.Nil {
		return 0, fmt.Errorf("%w: no tenant", ErrInvalidQuery)
	}
	var n int
	err := writeTx(ctx, db, tenant, func(ctx context.Context, tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `SELECT registry.record_waiver_notices()`).Scan(&n)
	})
	if err != nil {
		return 0, fmt.Errorf("record waiver notices: %w", err)
	}
	return n, nil
}

// writeTx runs fn in one REPEATABLE READ transaction with ipso.tenant set for
// that transaction only. A pooled connection does not keep the setting. fn's
// error is returned as it is.
func writeTx(ctx context.Context, db *sql.DB, tenant uuid.UUID, fn func(context.Context, *sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead})
	if err != nil {
		return fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `SELECT set_config('ipso.tenant', $1, true)`, tenant.String()); err != nil {
		return fmt.Errorf("set the tenant: %w", err)
	}
	if err := fn(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit: %w", err)
	}
	return nil
}
