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

Today the API has read routes only, so most of the table waits for its routes: approving, waiving and the decision writes come with IPSO-134, and managing people with IPSO-137. The five `GET /v1/audit/*` routes need `auditor` or `admin`. Every other read, and the MCP tools, need any role. Proposing over MCP needs `contributor`, `decision-owner`, `approver` or `agent`.

An admin manages people and structure and does not approve or waive, so the person who grants a role is not the person who approves a decision.

## Agents

A principal of kind `agent` holds the `agent` role and nothing else, and a person never holds it. The database refuses any other binding, and the policy also refuses an agent every action that needs a person, whatever it holds.

## Scopes

A binding has no scope, which covers the whole tenant, or one scope, which covers that node of the scope tree and every node below it. When a scope moves under another parent, its coverage moves with it.

Only `contributor`, `decision-owner`, `approver` and `agent` may be bound to a scope. Reads, audit and administration are tenant-wide, so a scope on a `viewer`, an `auditor` or an `admin` would promise a narrowing the server does not enforce, and the database refuses it.

A scoped action, such as approving a decision, is allowed only when every scope the decision names is covered by a binding of a role that grants it. A decision with one scope outside the binding is refused whole.

A scope that is still bound cannot be retired. Remove the bindings on it first.

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
