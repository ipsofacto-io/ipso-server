// Package authz is the role policy of ADR-0108: seven roles, bindings to the whole tenant or to one
// scope and its subtree, and an embedded Rego policy that decides each action. Go gathers the facts,
// the principal's kind and bindings and the ancestor chains of the scopes an action names, and the
// policy only decides. Every doubt is a refusal: no binding, an action the policy does not know, a
// scoped action with no target, and an evaluation that fails.
package authz

import (
	"context"
	"database/sql"
	_ "embed"
	"errors"
	"fmt"
	"slices"

	"github.com/google/uuid"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"

	"github.com/ipsofacto-io/ipso-server/internal/identity"
)

// Action is what a route or a tool asks the policy for.
type Action string

// The actions of the policy. The routes of internal/api name the read actions and the writes of
// IPSO-134 (ADR-0109), and the remote MCP tools name the read actions and proposal.create.
// principal.manage and tenant.export are the writes that IPSO-137, IPSO-142 and IPSO-147 serve.
const (
	// Member is what an unknown route and the MCP handshake ask: that the principal holds any role.
	Member            Action = "member"
	RegistryRead      Action = "registry.read"
	ProposalsRead     Action = "proposals.read"
	VerdictsRead      Action = "verdicts.read"
	AuditRead         Action = "audit.read"
	ProposalCreate    Action = "proposal.create"
	DecisionApprove   Action = "decision.approve"
	WaiverRecord      Action = "waiver.record"
	DecisionSupersede Action = "decision.supersede"
	PremiseWrite      Action = "premise.write"
	ScopeWrite        Action = "scope.write"
	AllowlistWrite    Action = "allowlist.write"
	PrincipalManage   Action = "principal.manage"
	TenantExport      Action = "tenant.export"
)

// Actions is every action the policy grants to some role.
var Actions = []Action{
	Member, RegistryRead, ProposalsRead, VerdictsRead, AuditRead, ProposalCreate,
	DecisionApprove, WaiverRecord, DecisionSupersede, PremiseWrite, ScopeWrite,
	AllowlistWrite, PrincipalManage, TenantExport,
}

// MaxTargets bounds the scopes one question to the policy names. A decision names at most 100 (ADR-0051), so
// a call that names more asks in chunks of this size.
const MaxTargets = 100

// scoped are the actions that name the scopes they act on, the same set as policy.rego. A test checks that
// the two agree.
var scoped = map[Action]bool{
	DecisionApprove: true, WaiverRecord: true, DecisionSupersede: true, PremiseWrite: true, ScopeWrite: true,
}

// Scoped reports whether the action names the scopes it acts on, so a binding covers it only inside its
// subtree and a call needs at least one target.
func Scoped(a Action) bool { return scoped[a] }

//go:embed policy.rego
var policySource string

// builtins are the only functions the policy may call. None of them reads the clock, the network or
// randomness, so a decision depends on its input alone.
var builtins = []string{"eq", "equal", "neq", "gt", "count", "internal.member_2"}

// Input is one question to the policy.
type Input struct {
	// Kind is the principal's kind, identity.KindHuman or identity.KindAgent.
	Kind string
	// Grants are the principal's role bindings.
	Grants []identity.Grant
	Action Action
	// Targets holds, for a scoped action, one chain per scope the action names: the scope and every
	// ancestor of it, as Targets reads them. It is empty for a tenant-wide action.
	Targets [][]uuid.UUID
}

// Policy is the compiled role policy. It is safe for concurrent use.
type Policy struct {
	allow   rego.PreparedEvalQuery
	mayTake rego.PreparedEvalQuery
}

// New compiles the embedded policy. A policy that does not compile is an error, so a process that
// cannot decide does not start.
func New(ctx context.Context) (*Policy, error) {
	module, err := ast.ParseModuleWithOpts("policy.rego", policySource, ast.ParserOptions{RegoVersion: ast.RegoV1})
	if err != nil {
		return nil, fmt.Errorf("parse the role policy: %w", err)
	}
	compiler := ast.NewCompiler().
		WithStrict(true).
		WithDefaultRegoVersion(ast.RegoV1).
		WithCapabilities(capabilities())
	compiler.Compile(map[string]*ast.Module{"policy.rego": module})
	if compiler.Failed() {
		return nil, fmt.Errorf("compile the role policy: %w", compiler.Errors)
	}
	prepare := func(rule string) (rego.PreparedEvalQuery, error) {
		return rego.New(
			rego.Compiler(compiler),
			rego.Query("data.ipso.authz."+rule),
			rego.StrictBuiltinErrors(true),
		).PrepareForEval(ctx)
	}
	allow, err := prepare("allow")
	if err != nil {
		return nil, fmt.Errorf("prepare the role policy: %w", err)
	}
	mayTake, err := prepare("may_take")
	if err != nil {
		return nil, fmt.Errorf("prepare the role policy: %w", err)
	}
	return &Policy{allow: allow, mayTake: mayTake}, nil
}

func capabilities() *ast.Capabilities {
	caps := ast.CapabilitiesForThisVersion(ast.CapabilitiesRegoVersion(ast.RegoV1))
	kept := make([]*ast.Builtin, 0, len(builtins))
	for _, b := range caps.Builtins {
		if slices.Contains(builtins, b.Name) {
			kept = append(kept, b)
		}
	}
	caps.Builtins = kept
	// An empty allow list means no host at all.
	caps.AllowNet = []string{}
	return caps
}

// Allow reports whether the policy grants the action. An error means no decision was made, and the
// caller refuses the request.
func (p *Policy) Allow(ctx context.Context, in Input) (bool, error) {
	if p == nil {
		return false, errors.New("no role policy")
	}
	if in.Action == "" || len(in.Grants) == 0 {
		return false, nil
	}
	if len(in.Targets) > MaxTargets {
		return false, fmt.Errorf("an action names at most %d scopes", MaxTargets)
	}
	return p.eval(ctx, p.allow, in)
}

// MayTake reports whether the principal could take the action on some scope: a binding of a role that
// grants it, held by a principal of a kind that may take it. It ignores the targets, so it is the cheap
// question a guard asks before it reads the body of a scoped call. A yes decides nothing, and Allow still
// has to cover every target.
func (p *Policy) MayTake(ctx context.Context, in Input) (bool, error) {
	if p == nil {
		return false, errors.New("no role policy")
	}
	if in.Action == "" || len(in.Grants) == 0 {
		return false, nil
	}
	in.Targets = nil
	return p.eval(ctx, p.mayTake, in)
}

func (p *Policy) eval(ctx context.Context, query rego.PreparedEvalQuery, in Input) (bool, error) {
	grants := make([]any, 0, len(in.Grants))
	for _, g := range in.Grants {
		scope := ""
		if g.Scope != uuid.Nil {
			scope = g.Scope.String()
		}
		grants = append(grants, map[string]any{"role": g.Role, "scope": scope})
	}
	targets := make([]any, 0, len(in.Targets))
	for _, chain := range in.Targets {
		ids := make([]any, 0, len(chain))
		for _, id := range chain {
			ids = append(ids, id.String())
		}
		targets = append(targets, ids)
	}
	rs, err := query.Eval(ctx, rego.EvalInput(map[string]any{
		"kind":    in.Kind,
		"action":  string(in.Action),
		"grants":  grants,
		"targets": targets,
	}))
	if err != nil {
		return false, fmt.Errorf("evaluate the role policy: %w", err)
	}
	if len(rs) != 1 || len(rs[0].Expressions) != 1 {
		return false, errors.New("the role policy gave no single answer")
	}
	allowed, ok := rs[0].Expressions[0].Value.(bool)
	if !ok {
		return false, errors.New("the role policy did not answer with a boolean")
	}
	return allowed, nil
}

// Targets reads, for each scope an action names, the chain the policy covers it with: the scope and
// every ancestor of it, from registry.scope_closure as it is now. The chains are in the order of
// scopes. A scope the tenant does not have gets an empty chain, which only a binding over the whole
// tenant covers. The tenant must be the authenticated one, because Targets trusts it.
func Targets(ctx context.Context, db *sql.DB, tenant uuid.UUID, scopes []uuid.UUID) ([][]uuid.UUID, error) {
	if tenant == uuid.Nil || len(scopes) == 0 || len(scopes) > MaxTargets {
		return nil, fmt.Errorf("a tenant and 1 to %d scopes are required", MaxTargets)
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT set_config('ipso.tenant', $1, true)`, tenant.String()); err != nil {
		return nil, fmt.Errorf("set the tenant: %w", err)
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT descendant_id, ancestor_id
		FROM registry.scope_closure
		WHERE tenant_id = ipso.current_tenant() AND descendant_id = ANY($1::uuid[])`, scopes)
	if err != nil {
		return nil, fmt.Errorf("read the scope closure: %w", err)
	}
	defer func() { _ = rows.Close() }()
	chains := make(map[uuid.UUID][]uuid.UUID, len(scopes))
	for rows.Next() {
		var descendant, ancestor uuid.UUID
		if err := rows.Scan(&descendant, &ancestor); err != nil {
			return nil, fmt.Errorf("read the scope closure: %w", err)
		}
		chains[descendant] = append(chains[descendant], ancestor)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("read the scope closure: %w", err)
	}
	out := make([][]uuid.UUID, len(scopes))
	for i, scope := range scopes {
		out[i] = chains[scope]
	}
	return out, nil
}
