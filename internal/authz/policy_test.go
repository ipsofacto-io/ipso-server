package authz

import (
	"slices"
	"testing"

	"github.com/google/uuid"
	"github.com/open-policy-agent/opa/v1/ast"

	"github.com/ipsofacto-io/ipso-server/internal/identity"
)

// reads are the actions every role holds.
var reads = []Action{Member, RegistryRead, ProposalsRead, VerdictsRead}

// granted is the role matrix of ADR-0108, written here apart from the policy, so a change to one fails
// until the other says the same.
var granted = map[string][]Action{
	identity.RoleViewer:        reads,
	identity.RoleContributor:   append(slices.Clone(reads), ProposalCreate),
	identity.RoleDecisionOwner: append(slices.Clone(reads), ProposalCreate, DecisionApprove, WaiverRecord, DecisionSupersede, PremiseWrite, ScopeWrite),
	identity.RoleApprover:      append(slices.Clone(reads), ProposalCreate, DecisionApprove, WaiverRecord),
	identity.RoleAdmin:         append(slices.Clone(reads), AuditRead, ScopeWrite, AllowlistWrite, PrincipalManage, TenantExport),
	identity.RoleAuditor:       append(slices.Clone(reads), AuditRead),
	identity.RoleAgent:         append(slices.Clone(reads), ProposalCreate),
}

// scopedActions name the scopes they act on.
var scopedActions = []Action{DecisionApprove, WaiverRecord, DecisionSupersede, PremiseWrite, ScopeWrite}

// scopableRoles may be bound to one scope. The others are bound to the whole tenant only.
var scopableRoles = []string{identity.RoleContributor, identity.RoleDecisionOwner, identity.RoleApprover, identity.RoleAgent}

// A small tree: root above parent, parent above target and sibling, target above child.
var (
	root    = uuid.MustParse("00000000-0000-4000-8000-000000000001")
	parent  = uuid.MustParse("00000000-0000-4000-8000-000000000002")
	target  = uuid.MustParse("00000000-0000-4000-8000-000000000003")
	sibling = uuid.MustParse("00000000-0000-4000-8000-000000000004")
	child   = uuid.MustParse("00000000-0000-4000-8000-000000000005")
	other   = uuid.MustParse("00000000-0000-4000-8000-000000000006")
)

// chainOf is what Targets reads for a scope of the tree: itself and every ancestor.
var chainOf = map[uuid.UUID][]uuid.UUID{
	target:  {target, parent, root},
	sibling: {sibling, parent, root},
	child:   {child, target, parent, root},
	other:   {other},
}

func newPolicy(t *testing.T) *Policy {
	t.Helper()
	p, err := New(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func kindOf(role string) string {
	if role == identity.RoleAgent {
		return identity.KindAgent
	}
	return identity.KindHuman
}

func isScoped(a Action) bool { return slices.Contains(scopedActions, a) }

func ask(t *testing.T, p *Policy, in Input) bool {
	t.Helper()
	ok, err := p.Allow(t.Context(), in)
	if err != nil {
		t.Fatalf("%+v: %v", in, err)
	}
	return ok
}

// targetsFor names the target scope for a scoped action and nothing for a tenant-wide one.
func targetsFor(a Action) [][]uuid.UUID {
	if isScoped(a) {
		return [][]uuid.UUID{chainOf[target]}
	}
	return nil
}

func TestTheMatrixNamesEveryRoleAndEveryAction(t *testing.T) {
	if len(granted) != len(identity.Roles) {
		t.Fatalf("the matrix has %d roles, section 13.2 has %d", len(granted), len(identity.Roles))
	}
	seen := map[Action]bool{}
	for _, role := range identity.Roles {
		actions, ok := granted[role]
		if !ok {
			t.Fatalf("the matrix has no row for %q", role)
		}
		for _, a := range actions {
			seen[a] = true
		}
	}
	for _, a := range Actions {
		if !seen[a] {
			t.Errorf("no role holds %q, so the action is dead", a)
		}
		delete(seen, a)
	}
	for a := range seen {
		t.Errorf("the matrix grants %q, which Actions does not list", a)
	}
}

func TestEveryRoleOnEveryActionOverTheWholeTenant(t *testing.T) {
	p := newPolicy(t)
	for _, role := range identity.Roles {
		for _, action := range Actions {
			got := ask(t, p, Input{
				Kind:    kindOf(role),
				Grants:  []identity.Grant{{Role: role}},
				Action:  action,
				Targets: targetsFor(action),
			})
			if want := slices.Contains(granted[role], action); got != want {
				t.Errorf("%s over the tenant, %s: allowed %v, want %v", role, action, got, want)
			}
		}
	}
}

// A scoped binding covers a scoped action only at its scope or below it. A tenant-wide action does not
// name a scope, so any binding of a role that grants it counts.
func TestAScopedBindingCoversItsSubtreeOnly(t *testing.T) {
	p := newPolicy(t)
	for _, role := range scopableRoles {
		for _, at := range []struct {
			name   string
			scope  uuid.UUID
			covers bool
		}{
			{"at the target", target, true},
			{"at an ancestor", parent, true},
			{"at the root", root, true},
			{"at a descendant", child, false},
			{"at a sibling", sibling, false},
			{"in another tree", other, false},
		} {
			for _, action := range Actions {
				want := slices.Contains(granted[role], action)
				if isScoped(action) {
					want = want && at.covers
				}
				got := ask(t, p, Input{
					Kind:    kindOf(role),
					Grants:  []identity.Grant{{Role: role, Scope: at.scope}},
					Action:  action,
					Targets: targetsFor(action),
				})
				if got != want {
					t.Errorf("%s %s, %s: allowed %v, want %v", role, at.name, action, got, want)
				}
			}
		}
	}
}

// A decision names up to 100 scopes, and approving it needs every one of them covered.
func TestEveryTargetMustBeCovered(t *testing.T) {
	p := newPolicy(t)
	approver := []identity.Grant{{Role: identity.RoleApprover, Scope: parent}}
	both := [][]uuid.UUID{chainOf[target], chainOf[sibling]}
	if !ask(t, p, Input{Kind: identity.KindHuman, Grants: approver, Action: DecisionApprove, Targets: both}) {
		t.Error("a binding above both targets does not cover them")
	}
	oneOutside := [][]uuid.UUID{chainOf[target], chainOf[other]}
	if ask(t, p, Input{Kind: identity.KindHuman, Grants: approver, Action: DecisionApprove, Targets: oneOutside}) {
		t.Error("a decision with one scope outside the binding was approved")
	}
	// Two bindings may cover the two targets between them.
	split := []identity.Grant{{Role: identity.RoleApprover, Scope: target}, {Role: identity.RoleApprover, Scope: other}}
	if !ask(t, p, Input{Kind: identity.KindHuman, Grants: split, Action: DecisionApprove, Targets: oneOutside}) {
		t.Error("two bindings that cover one target each do not cover both")
	}
	// A binding of a role that does not grant the action does not help cover a target.
	mixed := []identity.Grant{{Role: identity.RoleApprover, Scope: target}, {Role: identity.RoleContributor, Scope: other}}
	if ask(t, p, Input{Kind: identity.KindHuman, Grants: mixed, Action: DecisionApprove, Targets: oneOutside}) {
		t.Error("a contributor binding covered a target of an approval")
	}
}

func TestEveryDoubtIsARefusal(t *testing.T) {
	p := newPolicy(t)
	admin := []identity.Grant{{Role: identity.RoleAdmin}}
	owner := []identity.Grant{{Role: identity.RoleDecisionOwner}}
	for _, c := range []struct {
		name string
		in   Input
	}{
		{"no binding", Input{Kind: identity.KindHuman, Action: RegistryRead}},
		{"no action", Input{Kind: identity.KindHuman, Grants: admin}},
		{"an action the policy does not know", Input{Kind: identity.KindHuman, Grants: admin, Action: "registry.write"}},
		{"a role the policy does not know", Input{Kind: identity.KindHuman, Grants: []identity.Grant{{Role: "owner"}}, Action: RegistryRead}},
		{"a kind the policy does not know", Input{Kind: "service", Grants: admin, Action: RegistryRead}},
		{"no kind", Input{Grants: admin, Action: RegistryRead}},
		{"a scoped action with no target", Input{Kind: identity.KindHuman, Grants: owner, Action: DecisionSupersede}},
		{"an agent that holds a person's role", Input{Kind: identity.KindAgent, Grants: admin, Action: RegistryRead}},
		{"a person that holds the agent role", Input{Kind: identity.KindHuman, Grants: []identity.Grant{{Role: identity.RoleAgent}}, Action: RegistryRead}},
		{"an agent that holds a person's role asks to approve", Input{Kind: identity.KindAgent, Grants: owner, Action: DecisionApprove, Targets: [][]uuid.UUID{chainOf[target]}}},
		{"a scoped binding on a scope the tenant does not have", Input{Kind: identity.KindHuman, Grants: []identity.Grant{{Role: identity.RoleApprover, Scope: target}}, Action: WaiverRecord, Targets: [][]uuid.UUID{nil}}},
	} {
		if ask(t, p, c.in) {
			t.Errorf("%s was allowed", c.name)
		}
	}
	// A binding over the whole tenant covers a scope the closure does not know: the write then fails on
	// its own foreign key, not here.
	if !ask(t, p, Input{Kind: identity.KindHuman, Grants: owner, Action: WaiverRecord, Targets: [][]uuid.UUID{nil}}) {
		t.Error("a tenant-wide binding does not cover an unknown scope")
	}
}

func TestANilPolicyAndTooManyTargetsAreErrors(t *testing.T) {
	var none *Policy
	if ok, err := none.Allow(t.Context(), Input{Kind: identity.KindHuman, Grants: []identity.Grant{{Role: identity.RoleAdmin}}, Action: RegistryRead}); ok || err == nil {
		t.Errorf("a nil policy answered %v, %v", ok, err)
	}
	p := newPolicy(t)
	many := make([][]uuid.UUID, MaxTargets+1)
	if ok, err := p.Allow(t.Context(), Input{Kind: identity.KindHuman, Grants: []identity.Grant{{Role: identity.RoleDecisionOwner}}, Action: DecisionApprove, Targets: many}); ok || err == nil {
		t.Errorf("%d targets answered %v, %v", len(many), ok, err)
	}
}

// The policy can call only the builtins it needs, and none of them reaches the network, the clock or
// randomness.
func TestThePolicyCannotReachTheNetworkOrTheClock(t *testing.T) {
	caps := capabilities()
	var names []string
	for _, b := range caps.Builtins {
		names = append(names, b.Name)
	}
	slices.Sort(names)
	want := slices.Clone(builtins)
	slices.Sort(want)
	if !slices.Equal(names, want) {
		t.Errorf("builtins %v, want %v", names, want)
	}
	if caps.AllowNet == nil || len(caps.AllowNet) != 0 {
		t.Errorf("AllowNet %v, want an empty list", caps.AllowNet)
	}
	for _, src := range []string{
		`package p
x := http.send({"method": "GET", "url": "https://example.com"})`,
		`package p
x := time.now_ns()`,
		`package p
x := rand.intn("a", 10)`,
		`package p
x := opa.runtime()`,
	} {
		module, err := ast.ParseModuleWithOpts("p.rego", src, ast.ParserOptions{RegoVersion: ast.RegoV1})
		if err != nil {
			t.Fatal(err)
		}
		compiler := ast.NewCompiler().WithCapabilities(capabilities())
		compiler.Compile(map[string]*ast.Module{"p.rego": module})
		if !compiler.Failed() {
			t.Errorf("a policy compiled with a forbidden builtin:\n%s", src)
		}
	}
}

func mayTake(t *testing.T, p *Policy, in Input) bool {
	t.Helper()
	ok, err := p.MayTake(t.Context(), in)
	if err != nil {
		t.Fatalf("%+v: %v", in, err)
	}
	return ok
}

// MayTake asks whether a role could take the action somewhere, so a scoped binding answers the same as a
// binding over the whole tenant, whatever its scope and whatever targets are passed.
func TestMayTakeNamesNoTarget(t *testing.T) {
	p := newPolicy(t)
	for _, role := range identity.Roles {
		for _, action := range Actions {
			want := slices.Contains(granted[role], action)
			if got := mayTake(t, p, Input{Kind: kindOf(role), Grants: []identity.Grant{{Role: role}}, Action: action}); got != want {
				t.Errorf("%s over the tenant, %s: may take %v, want %v", role, action, got, want)
			}
			if slices.Contains(scopableRoles, role) {
				scoped := []identity.Grant{{Role: role, Scope: other}}
				if got := mayTake(t, p, Input{Kind: kindOf(role), Grants: scoped, Action: action, Targets: [][]uuid.UUID{chainOf[target]}}); got != want {
					t.Errorf("%s on a scope, %s: may take %v, want %v", role, action, got, want)
				}
			}
		}
	}
}

func TestMayTakeRefusesEveryDoubt(t *testing.T) {
	p := newPolicy(t)
	admin := []identity.Grant{{Role: identity.RoleAdmin}}
	owner := []identity.Grant{{Role: identity.RoleDecisionOwner}}
	for _, c := range []struct {
		name string
		in   Input
	}{
		{"no binding", Input{Kind: identity.KindHuman, Action: DecisionApprove}},
		{"no action", Input{Kind: identity.KindHuman, Grants: owner}},
		{"an action the policy does not know", Input{Kind: identity.KindHuman, Grants: owner, Action: "registry.write"}},
		{"a role that does not grant the action", Input{Kind: identity.KindHuman, Grants: admin, Action: DecisionApprove}},
		{"a kind the policy does not know", Input{Kind: "service", Grants: owner, Action: DecisionApprove}},
		{"no kind", Input{Grants: owner, Action: DecisionApprove}},
		{"an agent that holds a person's role", Input{Kind: identity.KindAgent, Grants: owner, Action: DecisionApprove}},
		{"an agent that holds the agent role", Input{Kind: identity.KindAgent, Grants: []identity.Grant{{Role: identity.RoleAgent}}, Action: ScopeWrite}},
		{"a person that holds the agent role", Input{Kind: identity.KindHuman, Grants: []identity.Grant{{Role: identity.RoleAgent}}, Action: ProposalCreate}},
	} {
		if mayTake(t, p, c.in) {
			t.Errorf("%s may take the action", c.name)
		}
	}
	var none *Policy
	if ok, err := none.MayTake(t.Context(), Input{Kind: identity.KindHuman, Grants: owner, Action: DecisionApprove}); ok || err == nil {
		t.Errorf("a nil policy answered %v, %v", ok, err)
	}
}

// Scoped is written in Go and in policy.rego. The policy refuses a scoped action that names no target to
// every principal, so the two agree when the holder of the action is refused exactly for the scoped ones.
func TestScopedAgreesWithThePolicy(t *testing.T) {
	p := newPolicy(t)
	for _, action := range Actions {
		var holder string
		for _, role := range identity.Roles {
			if slices.Contains(granted[role], action) && role != identity.RoleAgent {
				holder = role
				break
			}
		}
		if holder == "" {
			holder = identity.RoleAgent
		}
		in := Input{Kind: kindOf(holder), Grants: []identity.Grant{{Role: holder}}, Action: action}
		if refused := !ask(t, p, in); refused != Scoped(action) {
			t.Errorf("%s: the policy refuses a call with no target %v, Scoped says %v", action, refused, Scoped(action))
		}
		if Scoped(action) != isScoped(action) {
			t.Errorf("%s: Scoped says %v, the test matrix says %v", action, Scoped(action), isScoped(action))
		}
	}
}
