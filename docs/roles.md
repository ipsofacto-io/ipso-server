# Roles

Every route of the control plane API and every call of remote MCP asks a role policy before it runs ([ADR-0108](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0108-role-policy.md)). The policy is Rego, embedded in the binary from [internal/authz/policy.rego](../internal/authz/policy.rego) and compiled when the process starts, with no network and no clock. A policy that does not compile stops the process. Authentication still decides who calls. The policy decides what that principal may do.

A principal holds a role through a row of `identity.role_binding`. A principal with no binding is refused every route with 403 `{"error":"forbidden"}`, the same answer as a token that speaks for no principal, and the answer says nothing about the resource. The server logs one line with the tenant, the principal, the operation and the action.

## The seven roles

| Role | Reads the registry, queues and verdicts | Reads the audit routes | Proposes | Approves, waives | Supersedes, writes premises | Writes scopes | Allowlist, people, export |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `viewer` | yes | | | | | | |
| `contributor` | yes | | yes | | | | |
| `decision-owner` | yes | | yes | yes | yes | yes | |
| `approver` | yes | | yes | yes | | | |
| `admin` | yes | yes | | | | yes | yes |
| `auditor` | yes | yes | | | | | |
| `agent` | yes | | yes | | | | |

The write routes of the table are served ([ADR-0109](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0109-control-plane-write-routes.md), and [ADR-0116](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0116-check-proposal-approval.md) for a drafted check), apart from managing people, which comes with IPSO-137, and so is the export ([ADR-0111]({adr})). The five `GET /v1/audit/*` routes need `auditor` or `admin`. Every other read, and the MCP tools, need any role. Proposing over MCP needs `contributor`, `decision-owner`, `approver` or `agent`.

An admin manages people and structure and does not approve or waive, so the person who grants a role is not the person who approves a decision.

## Agents

A principal of kind `agent` holds the `agent` role and nothing else, and a person never holds it. The database refuses any other binding, and the policy also refuses an agent every action that needs a person, whatever it holds.

## Scopes

A binding has no scope, which covers the whole tenant, or one scope, which covers that node of the scope tree and every node below it. When a scope moves under another parent, its coverage moves with it.

Only `contributor`, `decision-owner`, `approver` and `agent` may be bound to a scope. Reads, audit and administration are tenant-wide, so a scope on a `viewer`, an `auditor` or an `admin` would promise a narrowing the server does not enforce, and the database refuses it.

A scoped action, such as approving a decision, is allowed only when every scope the decision names is covered by a binding of a role that grants it. A decision with one scope outside the binding is refused whole.

A scope that is still bound cannot be retired, and the API answers 409. Remove the bindings on it first.

## The write routes

Every write is an action only a person takes, so an agent is refused all of them whatever it holds. A binding to a scope covers the scoped actions only at that scope and below it, and a call that names several scopes needs every one of them covered. The scopes a call names are the ones in this table, and a decision the tenant has no row for is covered only by a binding over the whole tenant.

| Route | Action | Roles | Scopes the binding must cover |
| --- | --- | --- | --- |
| `POST /v1/scopes` | `scope.write` | decision-owner, admin | the parent, or the whole tenant for an org |
| `PUT /v1/scopes/{id}/parent` | `scope.write` | decision-owner, admin | the scope and its new parent |
| `DELETE /v1/scopes/{id}` | `scope.write` | decision-owner, admin | the scope |
| `POST /v1/supersessions` | `decision.supersede` | decision-owner | every scope of both decisions |
| `POST /v1/decisions/{decisionID}/grandfather-period` | `decision.supersede` | decision-owner | every scope of the decision |
| `POST /v1/decisions/{decisionID}/baselines` | `decision.supersede` | decision-owner | every scope of the decision |
| `POST /v1/waivers` | `waiver.record` | approver, decision-owner | the waiver's one scope |
| `POST /v1/decisions/{decisionID}/premises/{premiseID}/clearance` | `premise.write` | decision-owner | every scope of the decision |
| `POST /v1/premise-hosts` | `allowlist.write` | admin | none, the action is tenant-wide |
| `POST /v1/proposals/{id}/approval` and `POST /v1/agent-proposals/{id}/approval` | `decision.approve` | approver, decision-owner | an approval: every scope of the decision it writes. A rejection: the whole tenant |
| `POST /v1/decisions/{decisionID}/check-proposals/{id}/approval` | `decision.approve` | approver, decision-owner | every scope of the decision the check is for, for an approval and a rejection alike |

The approver of a waiver or an approval is the authenticated person and is never in the body. An approval writes the first version of the decision in the same transaction, so a decision version exists only through the approval of a person. The answer to a drafted check writes no decision and leaves the check pending in its table, and a scoped approver may give it, a rejection too, for a decision inside its scope. A premise evaluation, a review reason and a waiver notice are not routes: the worker writes them. Each write is logged with the person's id in the same transaction, in `identity.action_log`, which the audit log of IPSO-68 builds on.

## The export routes

Only an `admin` who is a person takes the action `tenant.export` ([ADR-0111](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0111-tenant-export-through-the-api.md)). It is tenant-wide and names no scope, so a binding to a scope never covers it, and every other role, an agent included, is refused with the same plain 403. A refusal stores nothing and logs nothing.

| Route | Action | Roles |
| --- | --- | --- |
| `POST /v1/exports` | `tenant.export` | admin |
| `GET /v1/exports/{id}` | `tenant.export` | admin |
| `GET /v1/exports/{id}/archive` | `tenant.export` | admin |

Starting an export and downloading one are logged with the person's id in `identity.action_log`. How an export is made and kept is in [docs/tenants.md](tenants.md#export-through-the-api).

## Bind and revoke

`ipso-server tenant create --person …` binds the first person of a tenant as `admin` ([docs/tenants.md](tenants.md)). Until IPSO-137 adds the routes, an operator binds and revokes other roles with SQL as the application role:

```sql
BEGIN;
SELECT set_config('ipso.tenant', '<tenant id>', true);
-- A role over the whole tenant.
INSERT INTO identity.role_binding (tenant_id, principal_id, role) VALUES ('<tenant id>', '<principal id>', 'viewer');
-- A role on one scope and every scope below it.
INSERT INTO identity.role_binding (tenant_id, principal_id, role, scope_id) VALUES ('<tenant id>', '<principal id>', 'approver', '<scope id>');
COMMIT;
```

```sql
BEGIN;
SELECT set_config('ipso.tenant', '<tenant id>', true);
DELETE FROM identity.role_binding WHERE principal_id = '<principal id>' AND role = 'approver';
COMMIT;
```

A binding is never updated: change a role by removing one binding and adding another. The server reads the bindings on every request, so a change applies to the next call.
