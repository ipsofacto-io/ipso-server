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

// periodCovers says whether the grandfather period of a decision covers valid time V, as known at transaction
// time T. A period that was not recorded by T, or does not contain V, covers nothing, so a deadline is honored by
// the read and no row means nothing is waived.
const periodCovers = `
SELECT EXISTS (
  SELECT 1 FROM registry.grandfather_period g
  WHERE g.tenant_id = ipso.current_tenant()
    AND g.decision_id = $1
    AND g.sys_period @> $2::timestamptz
    AND g.valid_period @> $3::timestamptz)`

// baselineFingerprints reads the fingerprints of the one baseline for a decision and repository that had been
// recorded by transaction time T, so a baseline recorded later does not change an earlier answer. Whether its
// grandfather period covers the valid time is asked by periodCovers, because the same baseline serves reads at
// many valid times and is large.
const baselineFingerprints = `
SELECT encode(f, 'hex')
FROM registry.baseline b
CROSS JOIN LATERAL unnest(b.fingerprints) AS u(f)
WHERE b.tenant_id = ipso.current_tenant()
  AND b.decision_id = $1
  AND b.repo = $2
  AND b.sys_period @> $3::timestamptz`

// BaselineRead is the violations of one decision in one repository, to be read against its baseline at one valid
// time. Repo is read as Grandfather reads it, and Violations hold no digest twice.
type BaselineRead struct {
	Decision   uuid.UUID
	Repo       string
	Violations []Fingerprint
	ValidAt    time.Time
}

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
	answers, err := GrandfatherEach(ctx, db, tenant, []BaselineRead{{Decision: decision, Repo: repo, Violations: violations, ValidAt: validAt}}, knownAt)
	if err != nil {
		return nil, err
	}
	return answers[0], nil
}

// GrandfatherEach answers several reads as the registry knew at knownAt, in one read-only
// REPEATABLE READ transaction, so a page of verdicts is read against one snapshot. Each answer has the
// contract of Grandfather, and the answers are in the order of the reads. An invalid read fails
// the call before the database is touched. A baseline is read once for the same decision, repository and
// valid time.
func GrandfatherEach(ctx context.Context, db *sql.DB, tenant uuid.UUID, reads []BaselineRead, knownAt time.Time) ([][]Result, error) {
	if tenant == uuid.Nil {
		return nil, fmt.Errorf("%w: no tenant", ErrInvalidQuery)
	}
	if knownAt.IsZero() {
		return nil, fmt.Errorf("%w: the valid time and the transaction time are required", ErrInvalidQuery)
	}
	repos := make([]string, len(reads))
	needsRead := false
	for i, e := range reads {
		if e.Decision == uuid.Nil {
			return nil, fmt.Errorf("%w: no decision", ErrInvalidQuery)
		}
		if e.ValidAt.IsZero() {
			return nil, fmt.Errorf("%w: the valid time and the transaction time are required", ErrInvalidQuery)
		}
		canonical, err := canonicalRepo(e.Repo)
		if err != nil {
			return nil, err
		}
		repos[i] = canonical
		seen := make(map[Fingerprint]struct{}, len(e.Violations))
		for _, v := range e.Violations {
			if _, ok := seen[v]; ok {
				return nil, fmt.Errorf("%w: a fingerprint is repeated", ErrInvalidQuery)
			}
			seen[v] = struct{}{}
		}
		needsRead = needsRead || len(e.Violations) > 0
	}
	answers := make([][]Result, len(reads))
	if !needsRead {
		return answers, nil
	}

	type periodKey struct {
		decision uuid.UUID
		validAt  int64
	}
	type baselineKey struct {
		decision uuid.UUID
		repo     string
	}
	err := readTx(ctx, db, tenant, func(ctx context.Context, tx *sql.Tx) error {
		covered := make(map[periodKey]bool)
		recorded := make(map[baselineKey]map[Fingerprint]struct{})
		for i, e := range reads {
			if len(e.Violations) == 0 {
				continue
			}
			answers[i] = make([]Result, len(e.Violations))
			pk := periodKey{e.Decision, e.ValidAt.UnixNano()}
			in, ok := covered[pk]
			if !ok {
				if err := tx.QueryRowContext(ctx, periodCovers, e.Decision, knownAt, e.ValidAt).Scan(&in); err != nil {
					return fmt.Errorf("read grandfather period: %w", err)
				}
				covered[pk] = in
			}
			if !in {
				continue
			}
			bk := baselineKey{e.Decision, repos[i]}
			baselined, ok := recorded[bk]
			if !ok {
				var err error
				if baselined, err = readBaseline(ctx, tx, e.Decision, repos[i], knownAt); err != nil {
					return err
				}
				recorded[bk] = baselined
			}
			for j, v := range e.Violations {
				if _, ok := baselined[v]; ok {
					answers[i][j] = WaivedBaseline
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return answers, nil
}

// LiteralRepo reports whether repo is a repository name that Grandfather accepts: a lowercase
// owner/name of the literal grammar of ADR-0051, which is the grammar of a recorded baseline.
func LiteralRepo(repo string) bool {
	_, err := canonicalRepo(repo)
	return err == nil
}

func readBaseline(ctx context.Context, tx *sql.Tx, decision uuid.UUID, repo string, knownAt time.Time) (map[Fingerprint]struct{}, error) {
	rows, err := tx.QueryContext(ctx, baselineFingerprints, decision, repo, knownAt)
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
