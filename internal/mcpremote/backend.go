package mcpremote

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso/pkg/mcptools"

	"github.com/ipsofacto-io/ipso-server/internal/identity"
	"github.com/ipsofacto-io/ipso-server/internal/registry"
)

const (
	sensitiveTag      = "sensitive"
	maxProposalTitle  = 200
	maxProposalText   = 8000
	maxLoggedSubject  = 200
	proposalsLocation = "the decision proposal inbox"
)

// Backend answers the tools from the registry, for one caller. Every call writes an action log entry
// first, and a call that cannot be logged does not run, so the log names the sponsor of each one.
type Backend struct {
	DB     *sql.DB
	Caller Caller
	Now    func() time.Time
}

var _ mcptools.Backend = (*Backend)(nil)

func (b *Backend) log(ctx context.Context, action, subject string) error {
	if _, err := identity.RecordAction(ctx, b.DB, b.Caller.Tenant, b.Caller.Principal, action, cleanSubject(subject)); err != nil {
		return errors.New("the call could not be logged, so it did not run")
	}
	return nil
}

// cleanSubject keeps a log entry to one bounded line of what the caller named.
func cleanSubject(subject string) string {
	cleaned := strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, subject)
	if runes := []rune(cleaned); len(runes) > maxLoggedSubject {
		return string(runes[:maxLoggedSubject])
	}
	return cleaned
}

// Applicable resolves once per path, because an omitted path widens the answer and one path cannot
// speak for another (ADR-0051).
func (b *Backend) Applicable(ctx context.Context, in mcptools.ApplicableInput) (mcptools.ApplicableOutput, error) {
	if err := b.log(ctx, mcptools.ToolApplicable, in.Repo); err != nil {
		return mcptools.ApplicableOutput{}, err
	}
	now := b.Now()
	paths := in.Paths
	if len(paths) == 0 {
		paths = []string{""}
	}
	out := mcptools.ApplicableOutput{Decisions: []mcptools.Decision{}}
	seen := map[uuid.UUID]bool{}
	for _, path := range paths {
		found, err := registry.Resolve(ctx, b.DB, b.Caller.Tenant, registry.Subject{Repo: strings.ToLower(in.Repo), Path: path, Env: in.Env}, now, now)
		if err != nil {
			return mcptools.ApplicableOutput{}, publicError(err)
		}
		for _, item := range found {
			if seen[item.ID] {
				continue
			}
			seen[item.ID] = true
			out.Decisions = append(out.Decisions, toolDecision(item))
		}
	}
	return out, nil
}

// Get reads one decision. A registry can answer both times, which the local server cannot.
func (b *Backend) Get(ctx context.Context, in mcptools.GetInput) (mcptools.GetOutput, error) {
	if in.Ref == "" {
		return mcptools.GetOutput{}, errors.New("ref is required")
	}
	if err := b.log(ctx, mcptools.ToolGet, in.Ref); err != nil {
		return mcptools.GetOutput{}, err
	}
	validAt, knownAt := b.Now(), b.Now()
	if in.AsOfValid != "" {
		parsed, err := time.Parse("2006-01-02", in.AsOfValid)
		if err != nil {
			return mcptools.GetOutput{}, errors.New("as_of_valid must be YYYY-MM-DD")
		}
		validAt = parsed
	}
	if in.AsOfTx != "" {
		parsed, err := time.Parse(time.RFC3339, in.AsOfTx)
		if err != nil {
			return mcptools.GetOutput{}, errors.New("as_of_tx must be an RFC 3339 time")
		}
		knownAt = parsed
	}
	found, err := registry.Lookup(ctx, b.DB, b.Caller.Tenant, in.Ref, validAt, knownAt)
	if err != nil {
		return mcptools.GetOutput{}, publicError(err)
	}
	switch len(found) {
	case 0:
		return mcptools.GetOutput{}, errors.New("no decision has that id or slug at those times")
	case 1:
		return mcptools.GetOutput{Decision: toolDecision(found[0]), InForce: true}, nil
	default:
		return mcptools.GetOutput{}, errors.New("more than one decision has that slug, so use its id")
	}
}

// Evaluate refuses, because ipso evaluates where the code is (ADR-0006). The tool stays listed so one
// contract covers both servers, and the error says where to run it.
func (b *Backend) Evaluate(ctx context.Context, _ mcptools.EvaluateInput) (mcptools.EvaluateOutput, error) {
	if err := b.log(ctx, mcptools.ToolEvaluate, "refused"); err != nil {
		return mcptools.EvaluateOutput{}, err
	}
	return mcptools.EvaluateOutput{}, errors.New("checks.evaluate runs on your machine so code stays there: use ipso mcp, or ipso check in CI")
}

// Propose stores a proposal that can only be pending. Nothing in the input reaches the status.
func (b *Backend) Propose(ctx context.Context, in mcptools.ProposeInput) (mcptools.ProposeOutput, error) {
	if err := checkProposal(in); err != nil {
		return mcptools.ProposeOutput{}, err
	}
	if err := b.log(ctx, mcptools.ToolPropose, in.Title); err != nil {
		return mcptools.ProposeOutput{}, err
	}
	payload, err := json.Marshal(in)
	if err != nil {
		return mcptools.ProposeOutput{}, err
	}
	tx, err := b.DB.BeginTx(ctx, nil)
	if err != nil {
		return mcptools.ProposeOutput{}, errors.New("the proposal could not be stored")
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('ipso.tenant', $1, true)`, b.Caller.Tenant.String()); err != nil {
		return mcptools.ProposeOutput{}, errors.New("the proposal could not be stored")
	}
	var id uuid.UUID
	err = tx.QueryRowContext(ctx, `
		INSERT INTO proposals.agent_proposal (tenant_id, principal_id, payload)
		VALUES ($1, $2, $3::jsonb) RETURNING id`, b.Caller.Tenant, b.Caller.Principal, payload).Scan(&id)
	if err != nil || tx.Commit() != nil {
		return mcptools.ProposeOutput{}, errors.New("the proposal could not be stored")
	}
	return mcptools.ProposeOutput{ProposalID: id.String(), Status: "proposed", Location: proposalsLocation}, nil
}

func checkProposal(in mcptools.ProposeInput) error {
	title := strings.TrimSpace(in.Title)
	if title == "" || len(title) > maxProposalTitle || strings.ContainsFunc(title, unicode.IsControl) {
		return fmt.Errorf("title must be 1 to %d characters on one line", maxProposalTitle)
	}
	if strings.TrimSpace(in.Statement) == "" || strings.TrimSpace(in.Rationale) == "" {
		return errors.New("statement and rationale are required")
	}
	for _, text := range []string{in.Statement, in.Rationale, in.Verification, in.SessionRef} {
		if len(text) > maxProposalText {
			return fmt.Errorf("a field is longer than %d bytes", maxProposalText)
		}
		if strings.ContainsFunc(text, func(r rune) bool { return unicode.IsControl(r) && r != '\n' && r != '\t' }) {
			return errors.New("a field has a control character")
		}
	}
	return nil
}

// publicError keeps a client-facing message from carrying database detail. A bad subject is the
// caller's to fix, so it says so.
func publicError(err error) error {
	if errors.Is(err, registry.ErrInvalidSubject) || errors.Is(err, registry.ErrInvalidQuery) {
		return errors.New("repo must be owner/name, and a path and an env must be valid")
	}
	return errors.New("the registry could not answer")
}

// decisionBody is what the tools read from a stored version. A field a version does not hold stays
// empty, and the answer says less rather than failing.
type decisionBody struct {
	Slug        string   `json:"slug"`
	Title       string   `json:"title"`
	Status      string   `json:"status"`
	Criticality string   `json:"criticality"`
	Statement   string   `json:"statement"`
	Tags        []string `json:"tags"`
	Sources     []struct {
		URL string `json:"url"`
	} `json:"sources"`
	Scope []struct {
		Paths []string `json:"paths"`
	} `json:"scope"`
	Checks []struct {
		Engine string `json:"engine"`
		Target string `json:"target"`
		Mode   string `json:"mode"`
	} `json:"checks"`
}

// toolDecision applies the rule of ADR-0072: a sensitive decision has no title, text, or sources.
func toolDecision(item registry.Decision) mcptools.Decision {
	var body decisionBody
	_ = json.Unmarshal(item.Body, &body)
	decision := mcptools.Decision{
		ID:          item.ID.String(),
		Slug:        body.Slug,
		Status:      body.Status,
		State:       brandState(body.Status),
		Criticality: body.Criticality,
		Record:      fmt.Sprintf("registry decision %s version %d", item.ID, item.Version),
		Sources:     []string{},
		Paths:       []string{},
		Checks:      []mcptools.Check{},
		Sensitive:   slices.Contains(body.Tags, sensitiveTag),
	}
	wide := len(body.Scope) == 0
	for _, scope := range body.Scope {
		wide = wide || len(scope.Paths) == 0
		decision.Paths = append(decision.Paths, scope.Paths...)
	}
	if wide {
		decision.Paths = []string{}
	}
	for _, check := range body.Checks {
		decision.Checks = append(decision.Checks, mcptools.Check{Engine: check.Engine, Target: check.Target, Mode: check.Mode})
	}
	if decision.Sensitive {
		return decision
	}
	decision.Title = body.Title
	decision.Statement = body.Statement
	for _, source := range body.Sources {
		decision.Sources = append(decision.Sources, source.URL)
	}
	return decision
}

// brandState is the word section 2.2 shows for an internal state.
func brandState(status string) string {
	switch status {
	case "verified":
		return "Verified"
	case "needs-review":
		return "Needs review"
	default:
		return "Under verification"
	}
}
