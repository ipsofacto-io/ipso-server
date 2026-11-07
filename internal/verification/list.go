package verification

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
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
// named by before (uuid.Nil for the first page). It reads in one read-only transaction with ipso.tenant
// set, so another tenant's rows are not visible to it.
func List(ctx context.Context, db *sql.DB, tenant uuid.UUID, f Filter, limit int, before uuid.UUID) ([]Item, error) {
	if db == nil || tenant == uuid.Nil {
		return nil, errors.New("list: a database and a tenant are required")
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
		       u.repo, u.sha, u.ref, u.event_name, u.workflow_ref, u.run_id, u.run_attempt,
		       u.check_name, u.env, u.ipso_version, u.evaluated_at, lower(u.sys_period),
		       encode(u.build_sha256, 'hex'), encode(u.sarif_sha256, 'hex'), u.evidence
		FROM verification.verdict AS v
		JOIN verification.upload AS u ON u.tenant_id = v.tenant_id AND u.id = v.upload_id
		WHERE v.tenant_id = $1
		  AND ($2 = '' OR u.repo = $2)
		  AND ($3 = '' OR v.decision_id = $3 OR v.slug = $3)
		  AND ($4::uuid IS NULL OR v.id < $4::uuid)
		ORDER BY v.id DESC
		LIMIT $5`, tenant, repo, f.Decision, after, limit)
	if err != nil {
		return nil, reduce("list: read", err)
	}
	defer func() { _ = rows.Close() }()
	items := []Item{}
	for rows.Next() {
		var it Item
		var evidence []byte
		if err := rows.Scan(&it.ID, &it.UploadID, &it.DecisionID, &it.Slug, &it.CheckIndex, &it.Mode, &it.Result, &it.Violations,
			&it.Repo, &it.SHA, &it.Ref, &it.Event, &it.WorkflowRef, &it.RunID, &it.RunAttempt,
			&it.Check, &it.Env, &it.IpsoVersion, &it.EvaluatedAt, &it.RecordedAt,
			&it.BuildSHA256, &it.SarifSHA256, &evidence); err != nil {
			return nil, reduce("list: scan", err)
		}
		it.Evidence = evidence
		it.RunURL = "https://github.com/" + it.Repo + "/actions/runs/" + strconv.FormatInt(it.RunID, 10)
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		return nil, reduce("list: read", err)
	}
	return items, nil
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
