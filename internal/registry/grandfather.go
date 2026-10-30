package registry

import (
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// ErrDamagedBaseline is returned when a stored fingerprint is not 32 bytes. The insert
// trigger refuses any other length, so a shorter or longer value was written around it.
// Treating it as a miss would hide the damage, and treating it as a match would waive a
// violation the baseline does not name.
var ErrDamagedBaseline = errors.New("baseline is damaged")

// Fingerprint is the SHA-256 digest of one violation, computed by the runner. Which fields
// feed the digest is fixed by the baseline command (IPSO-39) before any upload sends one.
// Within one evaluation of one decision in one repository, every violation has a distinct
// digest, and a repeat of the same rule at the same location includes its occurrence number.
type Fingerprint [32]byte

// Result is the grandfathering answer for one violation.
type Result int

const (
	// Fail means the violation is not covered by a baseline in force.
	Fail Result = iota
	// WaivedBaseline means the violation's fingerprint was recorded for this decision and
	// repository, and the grandfather period covers the valid time.
	WaivedBaseline
)

// String returns the verdict word for the result.
func (r Result) String() string {
	switch r {
	case WaivedBaseline:
		return "waived(baseline)"
	case Fail:
		return "fail"
	default:
		return fmt.Sprintf("result(%d)", int(r))
	}
}

// baselineFingerprints reads the fingerprints of the one baseline that is in force for a
// decision and repository at valid time V, as known at transaction time T. Both the baseline
// and its grandfather period have to have been recorded by T, and the period has to contain V,
// so a deadline is honored by the read and a baseline recorded later does not change an
// earlier answer. No row means nothing is waived.
const baselineFingerprints = `
SELECT encode(f, 'hex')
FROM registry.baseline b
JOIN registry.grandfather_period g
  ON g.tenant_id = b.tenant_id AND g.decision_id = b.decision_id
CROSS JOIN LATERAL unnest(b.fingerprints) AS u(f)
WHERE b.tenant_id = nullif(current_setting('ipso.tenant', true), '')::uuid
  AND b.decision_id = $1
  AND b.repo = $2
  AND b.sys_period @> $3::timestamptz
  AND g.sys_period @> $3::timestamptz
  AND g.valid_period @> $4::timestamptz`

// Grandfather reports, for each violation, whether the baseline of decision in repo waives
// it at valid time validAt, as the registry knew the baseline at transaction time knownAt.
// The result is in the same order as violations. No violation is a nil slice, and a caller
// tells that from a failure by err alone.
//
// The tenant must be the authenticated one, because Grandfather trusts it. A fingerprint
// that is not in the baseline, a baseline that was not recorded yet at knownAt, a period
// that does not cover validAt, and a decision with no grandfather period all return Fail.
// A nil tenant or decision, a zero time, a repository that is not a literal name, or a
// repeated fingerprint is an error and never an empty answer. A stored fingerprint that is
// not 32 bytes fails the call with ErrDamagedBaseline.
func Grandfather(ctx context.Context, db *sql.DB, tenant, decision uuid.UUID, repo string, violations []Fingerprint, validAt, knownAt time.Time) ([]Result, error) {
	if tenant == uuid.Nil {
		return nil, fmt.Errorf("%w: no tenant", ErrInvalidQuery)
	}
	if decision == uuid.Nil {
		return nil, fmt.Errorf("%w: no decision", ErrInvalidQuery)
	}
	if validAt.IsZero() || knownAt.IsZero() {
		return nil, fmt.Errorf("%w: the valid time and the transaction time are required", ErrInvalidQuery)
	}
	canonical, err := canonicalRepo(repo)
	if err != nil {
		return nil, err
	}
	seen := make(map[Fingerprint]struct{}, len(violations))
	for _, v := range violations {
		if _, ok := seen[v]; ok {
			return nil, fmt.Errorf("%w: a fingerprint is repeated", ErrInvalidQuery)
		}
		seen[v] = struct{}{}
	}
	if len(violations) == 0 {
		return nil, nil
	}

	var baselined map[Fingerprint]struct{}
	err = readTx(ctx, db, tenant, func(ctx context.Context, tx *sql.Tx) error {
		var err error
		baselined, err = readBaseline(ctx, tx, decision, canonical, validAt, knownAt)
		return err
	})
	if err != nil {
		return nil, err
	}
	out := make([]Result, len(violations))
	for i, v := range violations {
		if _, ok := baselined[v]; ok {
			out[i] = WaivedBaseline
		}
	}
	return out, nil
}

func readBaseline(ctx context.Context, tx *sql.Tx, decision uuid.UUID, repo string, validAt, knownAt time.Time) (map[Fingerprint]struct{}, error) {
	rows, err := tx.QueryContext(ctx, baselineFingerprints, decision, repo, knownAt, validAt)
	if err != nil {
		return nil, fmt.Errorf("read baseline: %w", err)
	}
	defer func() { _ = rows.Close() }()

	baselined := make(map[Fingerprint]struct{})
	for rows.Next() {
		var encoded string
		if err := rows.Scan(&encoded); err != nil {
			return nil, fmt.Errorf("read baseline: %w", err)
		}
		raw, err := hex.DecodeString(encoded)
		if err != nil || len(raw) != len(Fingerprint{}) {
			return nil, fmt.Errorf("decision %s: %w", decision, ErrDamagedBaseline)
		}
		var fingerprint Fingerprint
		copy(fingerprint[:], raw)
		baselined[fingerprint] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read baseline: %w", err)
	}
	return baselined, nil
}
