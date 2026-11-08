# The role policy of ADR-0108. It decides one thing: whether a principal of one kind, holding these role
# bindings, may take this action on these targets. Go gathers the facts and this file only decides, so
# it reads nothing but its input and calls no network.
#
# input.kind     "human" or "agent"
# input.action   one of the keys of roles below
# input.grants   [{"role": "...", "scope": "<uuid>" or ""}], "" for a binding over the whole tenant
# input.targets  for a scoped action, one chain per target scope: the scope itself and every ancestor
package ipso.authz

# The roles that grant each action. An action missing here is refused to everyone.
roles := {
	"member": {"viewer", "contributor", "decision-owner", "approver", "admin", "auditor", "agent"},
	"registry.read": {"viewer", "contributor", "decision-owner", "approver", "admin", "auditor", "agent"},
	"proposals.read": {"viewer", "contributor", "decision-owner", "approver", "admin", "auditor", "agent"},
	"verdicts.read": {"viewer", "contributor", "decision-owner", "approver", "admin", "auditor", "agent"},
	"audit.read": {"auditor", "admin"},
	"proposal.create": {"contributor", "decision-owner", "approver", "agent"},
	"decision.approve": {"approver", "decision-owner"},
	"waiver.record": {"approver", "decision-owner"},
	"decision.supersede": {"decision-owner"},
	"premise.write": {"decision-owner"},
	"scope.write": {"decision-owner", "admin"},
	"allowlist.write": {"admin"},
	"principal.manage": {"admin"},
	"tenant.export": {"admin"},
}

# The actions that name the scopes they act on. A binding to a scope covers them only inside its subtree.
scoped := {"decision.approve", "waiver.record", "decision.supersede", "premise.write", "scope.write"}

# The actions only a person takes (ADR-0076). An agent is refused them whatever it holds.
human_only := {
	"decision.approve", "waiver.record", "decision.supersede", "premise.write", "scope.write",
	"allowlist.write", "principal.manage", "tenant.export",
}

default allow := false

# A tenant-wide action: any binding of a role that grants it, wherever the binding is scoped.
allow if {
	not scoped[input.action]
	kind_may_act
	some grant in input.grants
	counts(grant)
}

# A scoped action: every target is covered by a binding of a role that grants it, and there is at least
# one target, so an action that names no scope is refused.
allow if {
	scoped[input.action]
	kind_may_act
	count(input.targets) > 0
	every target in input.targets {
		some grant in input.grants
		counts(grant)
		covers(grant, target)
	}
}

kind_may_act if {
	input.kind == "human"
}

kind_may_act if {
	input.kind == "agent"
	not human_only[input.action]
}

# A binding counts when its role grants the action and suits the principal's kind: an agent's only role
# is agent, and a person never holds it. The database refuses any other pair, and this is the second line.
counts(grant) if {
	grant.role in roles[input.action]
	(grant.role == "agent") == (input.kind == "agent")
}

# A binding over the whole tenant covers every scope. A scoped binding covers its scope and every scope
# below it, which is when its scope is in the target's chain of ancestors.
covers(grant, _) if {
	grant.scope == ""
}

covers(grant, target) if {
	grant.scope != ""
	grant.scope in target
}
