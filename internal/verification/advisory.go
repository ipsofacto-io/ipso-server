package verification

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/registry"
)

// Assessments are the words an advisory verdict can hold (ADR-0174).
const (
	Complies = "complies"
	Deviates = "deviates"
	Unclear  = "unclear"
)

// MaxCited is the most places an advisory verdict names, MaxReasonRunes the longest reason, and
// maxCitedBytes the longest JSON the places take, as the table bounds them.
const (
	MaxCited       = 10
	MaxReasonRunes = 300
	maxCitedBytes  = 8192
)

// ErrInvalidAdvisory means a verdict breaks a rule of the table, so it is not written. A caller can tell it
// from a database that cannot answer.
var ErrInvalidAdvisory = errors.New("advisory: the verdict breaks a rule of the table")

var (
	advisoryRepo = regexp.MustCompile(`^[a-z0-9_.-]+/[a-z0-9_.-]+$`)
	advisorySHA  = regexp.MustCompile(`^[0-9a-f]{40}([0-9a-f]{24})?$`)
	controlChars = regexp.MustCompile(`[\x00-\x1f\x7f]`)
)

// AdvisoryCheck names one llm-advisory check of one decision version on one head commit of a pull request.
type AdvisoryCheck struct {
	RepositoryID    int64
	PullNumber      int
	HeadSHA         string
	DecisionID      uuid.UUID
	DecisionVersion int
	CheckIndex      int
}

// Place is a range of lines on the head side of one file of a pull request.
type Place struct {
	Path      string `json:"path"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
}

// AdvisoryVerdict is what a model said about an AdvisoryCheck. It has no result and no mode: the table
// fixes them to advisory and advise and refuses any other value, so no caller can store a pass, a fail or a
// block from the llm-advisory engine (ADR-0005, ADR-0152 decision 5). Cited holds places the server built
// from its own hunks. PromptSHA256 is nil when the check names no prompt file.
type AdvisoryVerdict struct {
	AdvisoryCheck
	Repo          string
	BaseSHA       string
	Assessment    string
	Cited         []Place
	Reason        string
	ModelID       string
	PromptVersion string
	InputSHA256   [32]byte
	PromptSHA256  []byte
}

func (c AdvisoryCheck) validate() error {
	switch {
	case c.RepositoryID <= 0 || c.PullNumber <= 0:
		return errors.New("a repository and a pull request are required")
	case !advisorySHA.MatchString(c.HeadSHA):
		return errors.New("the head commit is not a SHA")
	case c.DecisionID == uuid.Nil || c.DecisionVersion < 1 || c.CheckIndex < 0:
		return errors.New("a decision version and a check index are required")
	}
	return nil
}

func (v AdvisoryVerdict) validate() error {
	if err := v.AdvisoryCheck.validate(); err != nil {
		return err
	}
	switch {
	case len(v.Repo) > 140 || !advisoryRepo.MatchString(v.Repo):
		return errors.New("the repository is not a lowercase owner/name")
	case !advisorySHA.MatchString(v.BaseSHA):
		return errors.New("the base commit is not a SHA")
	case v.Assessment != Complies && v.Assessment != Deviates && v.Assessment != Unclear:
		return errors.New("the assessment is not complies, deviates or unclear")
	case len(v.Cited) > MaxCited:
		return errors.New("too many places")
	case v.Assessment == Deviates && len(v.Cited) == 0:
		return errors.New("a deviation names no place")
	case v.Reason == "" || utf8.RuneCountInString(v.Reason) > MaxReasonRunes || controlChars.MatchString(v.Reason):
		return errors.New("the reason is empty, too long or holds a control character")
	case v.ModelID == "" || len(v.ModelID) > 200 || controlChars.MatchString(v.ModelID):
		return errors.New("the model id is empty, too long or holds a control character")
	case v.PromptVersion == "" || len(v.PromptVersion) > 100 || controlChars.MatchString(v.PromptVersion):
		return errors.New("the prompt version is empty, too long or holds a control character")
	case v.PromptSHA256 != nil && len(v.PromptSHA256) != 32:
		return errors.New("the prompt digest is not SHA-256")
	}
	for _, p := range v.Cited {
		if p.Path == "" || p.StartLine < 1 || p.EndLine < p.StartLine {
			return errors.New("a place has no path or no line range")
		}
	}
	return nil
}

// StoreAdvisory writes one advisory verdict as the application role, with ipso.tenant set to tenant. A
// verdict is unique per check: a repeat inserts nothing and reports false. The tenant must come from the
// installation mapping (ADR-0101), because StoreAdvisory trusts it.
func StoreAdvisory(ctx context.Context, db *sql.DB, tenant uuid.UUID, v AdvisoryVerdict) (bool, error) {
	if db == nil || tenant == uuid.Nil {
		return false, errors.New("advisory: a database and a tenant are required")
	}
	if err := v.validate(); err != nil {
		return false, fmt.Errorf("%w: %w", ErrInvalidAdvisory, err)
	}
	cited := v.Cited
	if cited == nil {
		cited = []Place{}
	}
	places, err := json.Marshal(cited)
	if err != nil {
		return false, err
	}
	// PostgreSQL prints jsonb with a space after each colon and comma, and the table bounds that text.
	if len(places)+separators(places) > maxCitedBytes {
		return false, fmt.Errorf("%w: the places are over %d bytes", ErrInvalidAdvisory, maxCitedBytes)
	}
	created := false
	err = inTenant(ctx, db, tenant, func(tx *sql.Tx) error {
		var id uuid.UUID
		err := tx.QueryRowContext(ctx, `
			INSERT INTO verification.advisory_verdict
				(tenant_id, repository_id, repo, pull_number, head_sha, base_sha, decision_id, decision_version,
				 check_index, assessment, cited, reason, model_id, prompt_version, input_sha256, prompt_sha256)
			VALUES (ipso.current_tenant(), $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15)
			ON CONFLICT ON CONSTRAINT advisory_verdict_once DO NOTHING
			RETURNING id`,
			v.RepositoryID, v.Repo, v.PullNumber, v.HeadSHA, v.BaseSHA, v.DecisionID, v.DecisionVersion,
			v.CheckIndex, v.Assessment, places, v.Reason, v.ModelID, v.PromptVersion, v.InputSHA256[:], v.PromptSHA256,
		).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		created = true
		return nil
	})
	if err != nil {
		return false, reduce("advisory: insert", err)
	}
	return created, nil
}

// separators counts the colons and commas of places, an upper bound on the spaces jsonb adds when it prints.
func separators(places []byte) int {
	n := 0
	for _, b := range places {
		if b == ':' || b == ',' {
			n++
		}
	}
	return n
}

// HasAdvisory reports whether the check already has a verdict.
func HasAdvisory(ctx context.Context, db *sql.DB, tenant uuid.UUID, c AdvisoryCheck) (bool, error) {
	if db == nil || tenant == uuid.Nil {
		return false, errors.New("advisory: a database and a tenant are required")
	}
	if err := c.validate(); err != nil {
		return false, fmt.Errorf("advisory: %w", err)
	}
	var found bool
	err := inTenant(ctx, db, tenant, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM verification.advisory_verdict
				WHERE tenant_id = ipso.current_tenant() AND repository_id = $1 AND pull_number = $2 AND head_sha = $3
				  AND decision_id = $4 AND decision_version = $5 AND check_index = $6)`,
			c.RepositoryID, c.PullNumber, c.HeadSHA, c.DecisionID, c.DecisionVersion, c.CheckIndex,
		).Scan(&found)
	})
	if err != nil {
		return false, reduce("advisory: read", err)
	}
	return found, nil
}

// ReuseAdvisory copies the latest verdict of the same check on an earlier head of the same pull request to
// this head, when that head sent the same input under the same prompt version and the same check prompt
// file. It reports whether it wrote a row, so a push that does not touch what the check sees costs no model
// call. The copy keeps the answer, the places, the model id and the prompt version it was made with.
func ReuseAdvisory(ctx context.Context, db *sql.DB, tenant uuid.UUID, c AdvisoryCheck, baseSHA, promptVersion string, input [32]byte, prompt []byte) (bool, error) {
	if db == nil || tenant == uuid.Nil {
		return false, errors.New("advisory: a database and a tenant are required")
	}
	if err := c.validate(); err != nil {
		return false, fmt.Errorf("advisory: %w", err)
	}
	if !advisorySHA.MatchString(baseSHA) || promptVersion == "" || (prompt != nil && len(prompt) != 32) {
		return false, errors.New("advisory: a base commit, a prompt version and SHA-256 digests are required")
	}
	reused := false
	err := inTenant(ctx, db, tenant, func(tx *sql.Tx) error {
		var id uuid.UUID
		err := tx.QueryRowContext(ctx, `
			INSERT INTO verification.advisory_verdict
				(tenant_id, repository_id, repo, pull_number, head_sha, base_sha, decision_id, decision_version,
				 check_index, assessment, cited, reason, model_id, prompt_version, input_sha256, prompt_sha256)
			SELECT tenant_id, repository_id, repo, pull_number, $3, $7, decision_id, decision_version,
			       check_index, assessment, cited, reason, model_id, prompt_version, input_sha256, prompt_sha256
			FROM verification.advisory_verdict
			WHERE tenant_id = ipso.current_tenant() AND repository_id = $1 AND pull_number = $2 AND head_sha <> $3
			  AND decision_id = $4 AND decision_version = $5 AND check_index = $6
			  AND prompt_version = $8 AND input_sha256 = $9 AND prompt_sha256 IS NOT DISTINCT FROM $10
			ORDER BY id DESC
			LIMIT 1
			ON CONFLICT ON CONSTRAINT advisory_verdict_once DO NOTHING
			RETURNING id`,
			c.RepositoryID, c.PullNumber, c.HeadSHA, c.DecisionID, c.DecisionVersion, c.CheckIndex,
			baseSHA, promptVersion, input[:], prompt,
		).Scan(&id)
		if errors.Is(err, sql.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		reused = true
		return nil
	})
	if err != nil {
		return false, reduce("advisory: reuse", err)
	}
	return reused, nil
}

// inTenant runs fn in a transaction with ipso.tenant set to tenant.
func inTenant(ctx context.Context, db *sql.DB, tenant uuid.UUID, fn func(*sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('ipso.tenant', $1, true)`, tenant.String()); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// AdvisoryFilter narrows a list of stored advisory verdicts. An empty or zero field matches everything.
type AdvisoryFilter struct {
	Repo       string
	Decision   uuid.UUID
	PullNumber int
	Assessment string
}

// StoredAdvisoryVerdict is one stored advisory verdict read from verification.advisory_verdict, enriched with
// the non-sensitive decision title of its stored version and a server-built pull request link (IPSO-162).
// Mode is always "advise" and Result is always "advisory". No field names a person.
type StoredAdvisoryVerdict struct {
	ID              uuid.UUID `json:"id"`
	Repo            string    `json:"repo"`
	PullNumber      int       `json:"pull_number"`
	PullURL         string    `json:"pull_url"`
	HeadSHA         string    `json:"head_sha"`
	BaseSHA         string    `json:"base_sha"`
	DecisionID      uuid.UUID `json:"decision_id"`
	DecisionVersion int       `json:"decision_version"`
	DecisionTitle   string    `json:"decision_title,omitempty"`
	CheckIndex      int       `json:"check_index"`
	Mode            string    `json:"mode"`
	Result          string    `json:"result"`
	Assessment      string    `json:"assessment"`
	Cited           []Place   `json:"cited"`
	Reason          string    `json:"reason"`
	ModelID         string    `json:"model_id"`
	PromptVersion   string    `json:"prompt_version"`
	RecordedAt      time.Time `json:"recorded_at"`
}

const advisorySelectColumns = `id, repo, pull_number, head_sha, base_sha, decision_id, decision_version, check_index,
	mode, result, assessment, cited, reason, model_id, prompt_version, lower(sys_period)`

// ListAdvisoryForHead returns all stored advisory verdicts for one head commit of a pull request, ordered
// deterministically by decision_id, decision_version, and check_index, with non-sensitive decision titles.
func ListAdvisoryForHead(ctx context.Context, db *sql.DB, tenant uuid.UUID, repositoryID int64, pullNumber int, headSHA string) ([]StoredAdvisoryVerdict, error) {
	if db == nil || tenant == uuid.Nil {
		return nil, errors.New("advisory: a database and a tenant are required")
	}
	if repositoryID <= 0 || pullNumber <= 0 || !advisorySHA.MatchString(headSHA) {
		return nil, invalid("repository_id, pull_number and head_sha are required")
	}
	var items []StoredAdvisoryVerdict
	err := inTenantReadOnly(ctx, db, tenant, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT `+advisorySelectColumns+`
			FROM verification.advisory_verdict
			WHERE tenant_id = ipso.current_tenant()
			  AND repository_id = $1 AND pull_number = $2 AND head_sha = $3
			ORDER BY decision_id ASC, decision_version ASC, check_index ASC`,
			repositoryID, pullNumber, headSHA)
		if err != nil {
			return err
		}
		items, err = scanAdvisoryVerdicts(rows)
		return err
	})
	if err != nil {
		return nil, reduce("advisory: list for head", err)
	}
	if err := enrichAdvisoryTitles(ctx, db, tenant, items); err != nil {
		return nil, err
	}
	return items, nil
}

// ListAdvisory returns the tenant's advisory verdicts, newest first, at most limit of them, starting after
// the verdict named by before (uuid.Nil for the first page).
func ListAdvisory(ctx context.Context, db *sql.DB, tenant uuid.UUID, f AdvisoryFilter, limit int, before uuid.UUID) ([]StoredAdvisoryVerdict, error) {
	if db == nil || tenant == uuid.Nil {
		return nil, errors.New("advisory: a database and a tenant are required")
	}
	if limit < 1 || limit > MaxPage {
		return nil, invalid("limit is out of range")
	}
	repo := strings.ToLower(f.Repo)
	if repo != "" && !validRepo(repo) {
		return nil, invalid("repo is not owner/name")
	}
	if f.PullNumber < 0 {
		return nil, invalid("pull_number must be positive")
	}
	if f.Assessment != "" && f.Assessment != Complies && f.Assessment != Deviates && f.Assessment != Unclear {
		return nil, invalid("assessment is not complies, deviates or unclear")
	}
	var decision any
	if f.Decision != uuid.Nil {
		decision = f.Decision
	}
	var after any
	if before != uuid.Nil {
		after = before
	}
	var items []StoredAdvisoryVerdict
	err := inTenantReadOnly(ctx, db, tenant, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT `+advisorySelectColumns+`
			FROM verification.advisory_verdict
			WHERE tenant_id = ipso.current_tenant()
			  AND ($1 = '' OR repo = $1)
			  AND ($2::uuid IS NULL OR decision_id = $2::uuid)
			  AND ($3 = 0 OR pull_number = $3)
			  AND ($4 = '' OR assessment = $4)
			  AND ($5::uuid IS NULL OR id < $5::uuid)
			ORDER BY id DESC
			LIMIT $6`,
			repo, decision, f.PullNumber, f.Assessment, after, limit)
		if err != nil {
			return err
		}
		items, err = scanAdvisoryVerdicts(rows)
		return err
	})
	if err != nil {
		return nil, reduce("advisory: list", err)
	}
	if err := enrichAdvisoryTitles(ctx, db, tenant, items); err != nil {
		return nil, err
	}
	return items, nil
}

func inTenantReadOnly(ctx context.Context, db *sql.DB, tenant uuid.UUID, fn func(*sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('ipso.tenant', $1, true)`, tenant.String()); err != nil {
		return err
	}
	return fn(tx)
}

func scanAdvisoryVerdicts(rows *sql.Rows) ([]StoredAdvisoryVerdict, error) {
	defer func() { _ = rows.Close() }()
	items := []StoredAdvisoryVerdict{}
	for rows.Next() {
		var it StoredAdvisoryVerdict
		var citedRaw []byte
		if err := rows.Scan(&it.ID, &it.Repo, &it.PullNumber, &it.HeadSHA, &it.BaseSHA,
			&it.DecisionID, &it.DecisionVersion, &it.CheckIndex,
			&it.Mode, &it.Result, &it.Assessment, &citedRaw, &it.Reason,
			&it.ModelID, &it.PromptVersion, &it.RecordedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal(citedRaw, &it.Cited); err != nil {
			return nil, err
		}
		if it.Cited == nil {
			it.Cited = []Place{}
		}
		it.PullURL = "https://github.com/" + it.Repo + "/pull/" + strconv.Itoa(it.PullNumber)
		items = append(items, it)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

func enrichAdvisoryTitles(ctx context.Context, db *sql.DB, tenant uuid.UUID, items []StoredAdvisoryVerdict) error {
	if len(items) == 0 {
		return nil
	}
	keys := make([]registry.DecisionVersionKey, 0, len(items))
	for _, it := range items {
		keys = append(keys, registry.DecisionVersionKey{ID: it.DecisionID, Version: it.DecisionVersion})
	}
	titles, err := registry.DecisionTitlesByVersion(ctx, db, tenant, keys)
	if err != nil {
		return reduce("advisory: read decision titles", err)
	}
	for i := range items {
		items[i].DecisionTitle = titles[registry.DecisionVersionKey{ID: items[i].DecisionID, Version: items[i].DecisionVersion}]
	}
	return nil
}
