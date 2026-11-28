package verification

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"unicode/utf8"

	"github.com/google/uuid"
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
