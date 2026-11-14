package verification

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/registry"
)

// MaxPage bounds one page of a list read.
const MaxPage = 100

// Filter narrows a list. An empty field matches everything.
type Filter struct {
	// Repo is owner/name. It is compared in lowercase, as the registry compares a repository.
	Repo string
	// Decision is an EDR id or a slug.
	Decision string
}

// Baseline is a verdict read against the recorded baseline of its decision and repository (ADR-0122). Result
// is waived(baseline) when the baseline holds every digest the run sent, and fail otherwise, which includes
// no recorded baseline, no decision, and a period that does not cover the time the server stored the upload.
type Baseline struct {
	Result string `json:"result"`
	// Fingerprints is the number of digests the run sent and Waived the number of them the baseline holds.
	Fingerprints int `json:"fingerprints"`
	Waived       int `json:"waived"`
}

// Item is one stored verdict with the upload it came from.
type Item struct {
	ID         uuid.UUID `json:"id"`
	UploadID   uuid.UUID `json:"upload_id"`
	DecisionID string    `json:"decision_id"`
	Slug       string    `json:"slug"`
	CheckIndex int       `json:"check_index"`
	Mode       string    `json:"mode"`
	Result     string    `json:"result"`
	Violations int       `json:"violations"`
	// Baseline is null when the run sent no digest for this verdict. Result stays what the run reported.
	Baseline *Baseline `json:"baseline"`

	Repo        string `json:"repo"`
	SHA         string `json:"sha"`
	Ref         string `json:"ref"`
	Event       string `json:"event"`
	WorkflowRef string `json:"workflow_ref"`
	RunID       int64  `json:"run_id"`
	RunAttempt  int    `json:"run_attempt"`
	// RunURL is built from the repository and the run the signed token named.
	RunURL      string          `json:"run_url"`
	Check       string          `json:"check"`
	Env         string          `json:"env"`
	IpsoVersion string          `json:"ipso_version"`
	EvaluatedAt time.Time       `json:"evaluated_at"`
	RecordedAt  time.Time       `json:"recorded_at"`
	BuildSHA256 string          `json:"build_sha256"`
	SarifSHA256 *string         `json:"sarif_sha256"`
	Evidence    json.RawMessage `json:"evidence"`
}

// List returns the tenant's verdicts, newest first, at most limit of them, starting after the verdict
// named by before (uuid.Nil for the first page), as the server knew them at transaction time known: an
// upload stored later is not listed. A verdict that has digests is read against the recorded baseline of its
// decision and repository as known at that time (ADR-0122). It reads with ipso.tenant set, so another
// tenant's rows are not visible to it.
func List(ctx context.Context, db *sql.DB, tenant uuid.UUID, f Filter, limit int, before uuid.UUID, known time.Time) ([]Item, error) {
	if db == nil || tenant == uuid.Nil || known.IsZero() {
		return nil, errors.New("list: a database, a tenant and a transaction time are required")
	}
	if limit < 1 || limit > MaxPage {
		return nil, invalid("limit is out of range")
	}
	repo := strings.ToLower(f.Repo)
	if repo != "" && !validRepo(repo) {
		return nil, invalid("repo is not owner/name")
	}
	if f.Decision != "" && !decisionID.MatchString(f.Decision) && !decisionRef.MatchString(f.Decision) {
		return nil, invalid("decision is not an EDR id or slug")
	}
	var after any
	if before != uuid.Nil {
		after = before
	}

	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, reduce("list: begin", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('ipso.tenant', $1, true)`, tenant.String()); err != nil {
		return nil, reduce("list: set the tenant", err)
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT v.id, v.upload_id, v.decision_id, v.slug, v.check_index, v.mode, v.result, v.violations,
		       (SELECT string_agg(encode(d, 'hex'), ' ' ORDER BY n) FROM unnest(v.fingerprints) WITH ORDINALITY AS t(d, n)),
		       u.repo, u.sha, u.ref, u.event_name, u.workflow_ref, u.run_id, u.run_attempt,
		       u.check_name, u.env, u.ipso_version, u.evaluated_at, lower(u.sys_period),
		       encode(u.build_sha256, 'hex'), encode(u.sarif_sha256, 'hex'), u.evidence
		FROM verification.verdict AS v
		JOIN verification.upload AS u ON u.tenant_id = v.tenant_id AND u.id = v.upload_id
		WHERE v.tenant_id = $1
		  AND ($2 = '' OR u.repo = $2)
		  AND ($3 = '' OR v.decision_id = $3 OR v.slug = $3)
		  AND ($4::uuid IS NULL OR v.id < $4::uuid)
		  AND u.sys_period @> $6::timestamptz
		ORDER BY v.id DESC
		LIMIT $5`, tenant, repo, f.Decision, after, limit, known)
	if err != nil {
		return nil, reduce("list: read", err)
	}
	defer func() { _ = rows.Close() }()
	items := []Item{}
	digests := [][]registry.Fingerprint{}
	for rows.Next() {
		var it Item
		var evidence []byte
		var joined sql.NullString
		if err := rows.Scan(&it.ID, &it.UploadID, &it.DecisionID, &it.Slug, &it.CheckIndex, &it.Mode, &it.Result, &it.Violations,
			&joined, &it.Repo, &it.SHA, &it.Ref, &it.Event, &it.WorkflowRef, &it.RunID, &it.RunAttempt,
			&it.Check, &it.Env, &it.IpsoVersion, &it.EvaluatedAt, &it.RecordedAt,
			&it.BuildSHA256, &it.SarifSHA256, &evidence); err != nil {
			return nil, reduce("list: scan", err)
		}
		it.Evidence = evidence
		it.RunURL = "https://github.com/" + it.Repo + "/actions/runs/" + strconv.FormatInt(it.RunID, 10)
		fingerprints, err := parseDigests(joined.String)
		if err != nil {
			return nil, reduce("list: read", err)
		}
		items = append(items, it)
		digests = append(digests, fingerprints)
	}
	if err := rows.Err(); err != nil {
		return nil, reduce("list: read", err)
	}
	_ = rows.Close()
	_ = tx.Rollback()
	if err := readBaselines(ctx, db, tenant, items, digests, known); err != nil {
		return nil, err
	}
	return items, nil
}

// parseDigests reads the digests of a verdict as the query joins them: lowercase hex, 32 bytes each, with a
// space between. No digest is nil. The column holds 32-byte entries, so a different length is damage.
func parseDigests(joined string) ([]registry.Fingerprint, error) {
	if joined == "" {
		return nil, nil
	}
	words := strings.Fields(joined)
	out := make([]registry.Fingerprint, len(words))
	for i, word := range words {
		raw, err := hex.DecodeString(word)
		if err != nil || len(raw) != len(registry.Fingerprint{}) {
			return nil, errors.New("a stored fingerprint is not 32 bytes")
		}
		copy(out[i][:], raw)
	}
	return out, nil
}

// readBaselines sets Baseline on every item that has digests (ADR-0122). The decision of an item is the one
// whose body holds the EDR id the runner reported, as known at known, and the valid time is the time the
// server stored the upload, never the time the runner states. An id that names no decision or several, and a
// repository that is not a literal registry name, leave nothing matched: the result is fail and no digest is
// in the baseline.
func readBaselines(ctx context.Context, db *sql.DB, tenant uuid.UUID, items []Item, digests [][]registry.Fingerprint, known time.Time) error {
	var edrIDs []string
	seen := make(map[string]bool)
	for i, item := range items {
		if len(digests[i]) > 0 && !seen[item.DecisionID] {
			seen[item.DecisionID] = true
			edrIDs = append(edrIDs, item.DecisionID)
		}
	}
	if len(edrIDs) == 0 {
		return nil
	}
	decisions, err := registry.DecisionsByEDRID(ctx, db, tenant, edrIDs, known)
	if err != nil {
		return reduce("list: read the decisions", err)
	}
	var reads []registry.BaselineRead
	var at []int
	for i := range items {
		if len(digests[i]) == 0 {
			continue
		}
		items[i].Baseline = &Baseline{Result: registry.Fail.String(), Fingerprints: len(digests[i])}
		decision, found := decisions[items[i].DecisionID]
		if !found || !registry.LiteralRepo(items[i].Repo) {
			continue
		}
		reads = append(reads, registry.BaselineRead{Decision: decision, Repo: items[i].Repo, Violations: digests[i], ValidAt: items[i].RecordedAt})
		at = append(at, i)
	}
	answers, err := registry.GrandfatherEach(ctx, db, tenant, reads, known)
	if err != nil {
		return reduce("list: read the baselines", err)
	}
	for n, i := range at {
		for _, answer := range answers[n] {
			if answer == registry.WaivedBaseline {
				items[i].Baseline.Waived++
			}
		}
		if items[i].Baseline.Waived == items[i].Baseline.Fingerprints {
			items[i].Baseline.Result = registry.WaivedBaseline.String()
		}
	}
	return nil
}

// validRepo holds for owner/name in the form GitHub allows, already lowercase.
func validRepo(repo string) bool {
	owner, name, found := strings.Cut(repo, "/")
	if !found || len(repo) > 140 || owner == "" || name == "" || strings.Contains(name, "/") {
		return false
	}
	for _, part := range []string{owner, name} {
		for _, c := range part {
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' && c != '.' {
				return false
			}
		}
	}
	return true
}
