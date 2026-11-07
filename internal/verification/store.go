package verification

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// Run is the CI run an upload came from. The signed CI token names it and the body never does, so
// whoever uploads cannot attribute a verdict to another repository, commit or run. Repo is the
// repository name in lowercase, as the registry keeps it.
type Run struct {
	Installation int64
	RepositoryID int64
	Repo         string
	RunID        int64
	RunAttempt   int
	SHA          string
	Ref          string
	Event        string
	WorkflowRef  string
}

// Stored says what Store did.
type Stored struct {
	ID       uuid.UUID
	Verdicts int
	// Created is false when the same run had already uploaded the same content, and nothing was added.
	Created bool
}

// Store writes one upload and its verdicts in one transaction as the application role, with ipso.tenant
// set to tenant, so row-level security lets it write that tenant's rows and no other's. The upload is
// unique by tenant, repository, run, attempt and content digest: a repeat inserts nothing and returns
// the first upload. The tenant must come from the installation mapping (ADR-0101), because Store trusts it.
func Store(ctx context.Context, db *sql.DB, tenant uuid.UUID, run Run, up Upload) (Stored, error) {
	if db == nil || tenant == uuid.Nil {
		return Stored{}, errors.New("store: a database and a tenant are required")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return Stored{}, reduce("store: begin", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('ipso.tenant', $1, true)`, tenant.String()); err != nil {
		return Stored{}, reduce("store: set the tenant", err)
	}

	var id uuid.UUID
	err = tx.QueryRowContext(ctx, `
		INSERT INTO verification.upload
		  (tenant_id, installation_id, repository_id, repo, run_id, run_attempt, sha, ref, event_name, workflow_ref,
		   check_name, env, ipso_version, evaluated_at, build_sha256, sarif_sha256, evidence, content_sha256)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17::jsonb, $18)
		ON CONFLICT ON CONSTRAINT upload_once DO NOTHING
		RETURNING id`,
		tenant, run.Installation, run.RepositoryID, run.Repo, run.RunID, run.RunAttempt, run.SHA, run.Ref, run.Event,
		run.WorkflowRef, up.Check, up.Env, up.IpsoVersion, up.EvaluatedAt, up.BuildSHA256, up.SarifSHA256,
		string(up.Evidence), up.Digest).Scan(&id)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// A new statement under read committed sees the row that made the insert wait and conflict.
		if err := tx.QueryRowContext(ctx, `
			SELECT id FROM verification.upload
			WHERE tenant_id = $1 AND repository_id = $2 AND run_id = $3 AND run_attempt = $4 AND content_sha256 = $5`,
			tenant, run.RepositoryID, run.RunID, run.RunAttempt, up.Digest).Scan(&id); err != nil {
			return Stored{}, reduce("store: read the first upload", err)
		}
		return Stored{ID: id, Verdicts: len(up.Verdicts)}, nil
	case err != nil:
		return Stored{}, reduce("store: insert the upload", err)
	}

	if len(up.Verdicts) > 0 {
		n := len(up.Verdicts)
		decisions, slugs, indexes := make([]string, n), make([]string, n), make([]int32, n)
		modes, results, violations := make([]string, n), make([]string, n), make([]int32, n)
		for i, v := range up.Verdicts {
			decisions[i], slugs[i], indexes[i] = v.DecisionID, v.Slug, int32(v.CheckIndex)
			modes[i], results[i], violations[i] = v.Mode, v.Result, int32(v.Violations)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO verification.verdict (tenant_id, upload_id, decision_id, slug, check_index, mode, result, violations)
			SELECT $1::uuid, $2::uuid, t.decision_id, t.slug, t.check_index, t.mode, t.result, t.violations
			FROM unnest($3::text[], $4::text[], $5::int4[], $6::text[], $7::text[], $8::int4[])
			     WITH ORDINALITY AS t(decision_id, slug, check_index, mode, result, violations, ord)
			ORDER BY t.ord`,
			tenant, id, decisions, slugs, indexes, modes, results, violations); err != nil {
			return Stored{}, reduce("store: insert the verdicts", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return Stored{}, reduce("store: commit", err)
	}
	return Stored{ID: id, Verdicts: len(up.Verdicts), Created: true}, nil
}

// reduce keeps the operation and the class of the cause and drops the rest of err's text. A database
// message can quote the value that failed it, and an upload is content from a runner. The table and the
// constraint are names of the schema and are kept.
func reduce(operation string, err error) error {
	var pgErr *pgconn.PgError
	switch {
	case errors.As(err, &pgErr):
		out := fmt.Sprintf("%s: SQLSTATE %s", operation, pgErr.Code)
		if pgErr.TableName != "" {
			out += " on " + pgErr.SchemaName + "." + pgErr.TableName
		}
		if pgErr.ConstraintName != "" {
			out += " (" + pgErr.ConstraintName + ")"
		}
		return errors.New(out)
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("%s: timed out", operation)
	case errors.Is(err, context.Canceled):
		return fmt.Errorf("%s: canceled", operation)
	default:
		return fmt.Errorf("%s: failed", operation)
	}
}
