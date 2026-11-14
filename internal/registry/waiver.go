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

// waiverEnd is the latest end among the waivers of the decision that were recorded by T, are in
// force at V, and name a scope in the given set, and it is NULL when there is none. The decision
// itself has to cover V as known at T. A waiver that sticks out past a shortened decision does
// not match, because the decision row has to contain V.
const waiverEnd = `
SELECT max(upper(w.valid_period))
FROM registry.waiver w
WHERE w.tenant_id = ipso.current_tenant()
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
  )`

// waiverEndIn reads waiverEnd. A waiver covers when the end is valid.
func waiverEndIn(ctx context.Context, tx *sql.Tx, decision uuid.UUID, scopes []uuid.UUID, validAt, knownAt time.Time) (sql.NullTime, error) {
	var end sql.NullTime
	err := tx.QueryRowContext(ctx, waiverEnd, decision, scopes, validAt, knownAt).Scan(&end)
	return end, err
}

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
	var end sql.NullTime
	err = readTx(ctx, db, tenant, func(ctx context.Context, tx *sql.Tx) error {
		scopes, err := scopesOf(ctx, tx, subject, knownAt)
		if err != nil || len(scopes) == 0 {
			return err
		}
		end, err = waiverEndIn(ctx, tx, decision, scopes, validAt, knownAt)
		return err
	})
	if err != nil {
		return OutcomeFail, err
	}
	if end.Valid {
		return OutcomeWaived, nil
	}
	return OutcomeFail, nil
}

// scopesOf returns the scopes that select the subject and every ancestor of them, as known at
// knownAt, or none when no scope selects it.
func scopesOf(ctx context.Context, tx *sql.Tx, s subject, knownAt time.Time) ([]uuid.UUID, error) {
	matched, err := matchingScopes(ctx, tx, s, knownAt)
	if err != nil || len(matched) == 0 {
		return nil, err
	}
	return ancestorsOf(ctx, tx, matched, knownAt)
}

// WaiverRead is one stored verdict to read against the waivers of its decision: the repository and
// the environment of its upload, and the valid time at which a waiver has to be in force. It has no
// path, because a report holds none (ADR-0030, ADR-0123).
type WaiverRead struct {
	Decision uuid.UUID
	Repo     string
	Env      string
	ValidAt  time.Time
}

// WaiverAnswer is the reading of one WaiverRead. Covered is true when a waiver covers the verdict, and
// ExpiresAt is then the latest end among the waivers that do, the upper bound of their periods.
type WaiverAnswer struct {
	Covered   bool
	ExpiresAt time.Time
}

// WaiverEach reports, for each read, whether a waiver of its decision covers the whole repository at
// valid time ValidAt, as the registry knew the waivers at transaction time knownAt. The answers are in
// the order of the reads. It applies the rule of Apply, with one change: a waiver covers only when its
// scope covers every path of the repository, so a scope that names a path never covers a read, and a
// scope that names an environment covers it only when the read names that environment. An
// environment that is not a registry name is read as none. The scopes are read once for the same
// repository and environment, and a waiver once for the same decision, repository, environment and
// valid time, all in one read-only REPEATABLE READ transaction.
//
// The tenant must be the authenticated one, because WaiverEach trusts it. A nil tenant or decision, a
// zero time, or a repository that is not a literal registry name is an error before the database is
// touched, and never an empty answer. The answers are meaningful only when err is nil.
func WaiverEach(ctx context.Context, db *sql.DB, tenant uuid.UUID, reads []WaiverRead, knownAt time.Time) ([]WaiverAnswer, error) {
	if tenant == uuid.Nil {
		return nil, fmt.Errorf("%w: no tenant", ErrInvalidQuery)
	}
	if knownAt.IsZero() {
		return nil, fmt.Errorf("%w: the transaction time is required", ErrInvalidQuery)
	}
	subjects := make([]subject, len(reads))
	for i, read := range reads {
		if read.Decision == uuid.Nil {
			return nil, fmt.Errorf("%w: no decision", ErrInvalidQuery)
		}
		if read.ValidAt.IsZero() {
			return nil, fmt.Errorf("%w: the valid time is required", ErrInvalidQuery)
		}
		s, err := newWholeSubject(read.Repo, read.Env)
		if err != nil {
			return nil, err
		}
		subjects[i] = s
	}
	answers := make([]WaiverAnswer, len(reads))
	if len(reads) == 0 {
		return answers, nil
	}

	type subjectKey struct{ repo, env string }
	type coverKey struct {
		decision uuid.UUID
		subject  subjectKey
		validAt  int64
	}
	err := readTx(ctx, db, tenant, func(ctx context.Context, tx *sql.Tx) error {
		scopesFor := make(map[subjectKey][]uuid.UUID)
		answered := make(map[coverKey]WaiverAnswer)
		for i, read := range reads {
			sk := subjectKey{subjects[i].repoString(), subjects[i].env}
			scopes, ok := scopesFor[sk]
			if !ok {
				var err error
				if scopes, err = scopesOf(ctx, tx, subjects[i], knownAt); err != nil {
					return err
				}
				scopesFor[sk] = scopes
			}
			if len(scopes) == 0 {
				continue
			}
			ck := coverKey{read.Decision, sk, read.ValidAt.UnixNano()}
			answer, ok := answered[ck]
			if !ok {
				end, err := waiverEndIn(ctx, tx, read.Decision, scopes, read.ValidAt, knownAt)
				if err != nil {
					return fmt.Errorf("read waivers: %w", err)
				}
				answer = WaiverAnswer{Covered: end.Valid, ExpiresAt: end.Time}
				answered[ck] = answer
			}
			answers[i] = answer
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return answers, nil
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
