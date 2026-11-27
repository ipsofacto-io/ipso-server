package llmgw

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ErrOptInRequired indicates the tenant has not enabled the requested LLM capability in llm.tenant_policy.
var ErrOptInRequired = errors.New("llm: tenant opt-in is required")

// MaxAdvisoryRepositories is the longest list of repositories a tenant opts in to llm-advisory checks.
const MaxAdvisoryRepositories = 100

// advisoryRepository is a GitHub owner/name in lowercase, as llm.tenant_policy keeps it.
var advisoryRepository = regexp.MustCompile(`^[a-z0-9_.-]{1,39}/[a-z0-9_.-]{1,100}$`)

// TenantPolicy records per-tenant opt-in switches for authoring assistance, engine: llm evaluation, the
// relation annotation of agent proposals (ADR-0172), and the repositories whose pull requests send diff
// hunks for llm-advisory checks (ADR-0173). AdvisoryRepositories is never nil, so a response always holds
// a list.
type TenantPolicy struct {
	AllowAuthoringAssist        bool      `json:"allow_authoring_assist"`
	AllowCheckEval              bool      `json:"allow_check_eval"`
	AllowAgentProposalRelations bool      `json:"allow_agent_proposal_relations"`
	AdvisoryRepositories        []string  `json:"advisory_repositories"`
	UpdatedAt                   time.Time `json:"updated_at,omitzero"`
}

// NormalizeAdvisoryRepositories lowercases, sorts and deduplicates a list of owner/name repositories, and
// refuses an entry that is not one or a list longer than MaxAdvisoryRepositories.
func NormalizeAdvisoryRepositories(repos []string) ([]string, error) {
	out := make([]string, 0, len(repos))
	for _, repo := range repos {
		lower := strings.ToLower(repo)
		if !advisoryRepository.MatchString(lower) {
			return nil, fmt.Errorf("llm policy: %q is not an owner/name repository", repo)
		}
		out = append(out, lower)
	}
	slices.Sort(out)
	out = slices.Compact(out)
	if len(out) > MaxAdvisoryRepositories {
		return nil, fmt.Errorf("llm policy: at most %d advisory repositories", MaxAdvisoryRepositories)
	}
	return out, nil
}

// AdvisesRepository reports whether the tenant opted repo in to llm-advisory checks. The name is compared
// in lowercase. A missing policy row opts in nothing.
func AdvisesRepository(ctx context.Context, db *sql.DB, tenant uuid.UUID, repo string) (bool, error) {
	pol, err := GetTenantPolicy(ctx, db, tenant)
	if err != nil {
		return false, err
	}
	return slices.Contains(pol.AdvisoryRepositories, strings.ToLower(repo)), nil
}

// GetTenantPolicy reads the tenant's LLM opt-in settings, each false when unset.
func GetTenantPolicy(ctx context.Context, db *sql.DB, tenant uuid.UUID) (TenantPolicy, error) {
	if db == nil || tenant == uuid.Nil {
		return TenantPolicy{}, errors.New("llm policy: database and tenant are required")
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return TenantPolicy{}, err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('ipso.tenant', $1, true)`, tenant.String()); err != nil {
		return TenantPolicy{}, err
	}
	var out TenantPolicy
	var repos []byte
	err = tx.QueryRowContext(ctx, `
		SELECT allow_authoring_assist, allow_check_eval, allow_agent_proposal_relations, to_jsonb(advisory_repositories), updated_at
		FROM llm.tenant_policy
		WHERE tenant_id = ipso.current_tenant()`).Scan(&out.AllowAuthoringAssist, &out.AllowCheckEval, &out.AllowAgentProposalRelations, &repos, &out.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return TenantPolicy{AdvisoryRepositories: []string{}}, nil
	}
	if err != nil {
		return TenantPolicy{}, err
	}
	if out.AdvisoryRepositories, err = repositoryList(repos); err != nil {
		return TenantPolicy{}, err
	}
	return out, nil
}

// repositoryList reads the JSON form of advisory_repositories, and is never nil.
func repositoryList(raw []byte) ([]string, error) {
	repos := []string{}
	if err := json.Unmarshal(raw, &repos); err != nil {
		return nil, fmt.Errorf("llm policy: read the advisory repositories: %w", err)
	}
	if repos == nil {
		repos = []string{}
	}
	return repos, nil
}

// SetTenantPolicy replaces the tenant's LLM opt-in settings with those of policy, inside the caller's READ
// COMMITTED tenant transaction. The advisory repositories are normalized first, and a bad one refuses the
// whole policy. UpdatedAt is ignored.
func SetTenantPolicy(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, policy TenantPolicy) (TenantPolicy, error) {
	if tenant == uuid.Nil {
		return TenantPolicy{}, errors.New("llm policy: tenant is required")
	}
	repos, err := NormalizeAdvisoryRepositories(policy.AdvisoryRepositories)
	if err != nil {
		return TenantPolicy{}, err
	}
	var out TenantPolicy
	var stored []byte
	err = tx.QueryRowContext(ctx, `
		INSERT INTO llm.tenant_policy
			(tenant_id, allow_authoring_assist, allow_check_eval, allow_agent_proposal_relations, advisory_repositories, updated_at)
		VALUES ($1, $2, $3, $4, $5::text[], clock_timestamp())
		ON CONFLICT (tenant_id) DO UPDATE
		SET allow_authoring_assist = EXCLUDED.allow_authoring_assist,
		    allow_check_eval = EXCLUDED.allow_check_eval,
		    allow_agent_proposal_relations = EXCLUDED.allow_agent_proposal_relations,
		    advisory_repositories = EXCLUDED.advisory_repositories,
		    updated_at = clock_timestamp()
		RETURNING allow_authoring_assist, allow_check_eval, allow_agent_proposal_relations, to_jsonb(advisory_repositories), updated_at`,
		tenant, policy.AllowAuthoringAssist, policy.AllowCheckEval, policy.AllowAgentProposalRelations, repos).
		Scan(&out.AllowAuthoringAssist, &out.AllowCheckEval, &out.AllowAgentProposalRelations, &stored, &out.UpdatedAt)
	if err != nil {
		return TenantPolicy{}, err
	}
	if out.AdvisoryRepositories, err = repositoryList(stored); err != nil {
		return TenantPolicy{}, err
	}
	return out, nil
}
