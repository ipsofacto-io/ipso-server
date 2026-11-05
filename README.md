# ipso-server

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/ipsofacto-io/ipso-server/badge)](https://scorecard.dev/viewer/?uri=github.com/ipsofacto-io/ipso-server)

Source-available ipso control plane: bitemporal decision registry, API, web app and PR checks.

> Status: early. The binary has five commands. `ipso-server --role=api` serves the control plane API ([ADR-0094](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0094-the-api-role.md)), `ipso-server --role=worker` works its jobs on River, starting with the hourly waiver notice sweep and the premise sweep ([ADR-0097](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0097-the-worker-role.md)), and [docs/local-stack.md](docs/local-stack.md) runs both on a laptop with one Compose command. `ipso-server migrate` applies the PostgreSQL 18 schema. `ipso-server webhooks` serves the GitHub App webhook, holds no tenant data, and opens no database connection ([ADR-0061](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0061-github-app.md)). `ipso-server runtasks` serves an HCP Terraform run task on the same terms ([ADR-0065](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0065-hcp-terraform-run-task.md)).

One Go modular monolith ships the registry API, the web SPA, the entitlement contract, the Helm chart and the Compose bundle, plus a separate Python worker for LLM extraction. The binary is `ipso-server`. `--role=api` starts the control plane and `--role=worker` works its jobs today, and the `all` role is not built yet.

Module rule: `go.mod` may require `ipso`. Enterprise features register from `ipso-ee` through the `ee` build tag. Each release converts to Apache-2.0 two years after publication. Enterprise builds use the same version number: EE vX.Y.Z matches server vX.Y.Z.

## Local stack

`cp .env.example .env && docker compose up --build` starts PostgreSQL 18, applies the migrations, seeds a tenant, serves the control plane with Dex as the OIDC provider behind a front that limits each client, and runs the worker. [docs/local-stack.md](docs/local-stack.md) shows how to get a token and call the API. `ci / compose` starts the stack from a clean checkout and runs a smoke test against it ([ADR-0095](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0095-local-compose-stack.md)).

## Database schema

The primary store is PostgreSQL 18 ([ADR-0003](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0003-bitemporal-store-on-postgresql-18.md)). Migrations are goose v3.29.0 files embedded in the binary and applied by one command ([ADR-0050](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0050-schema-migrations-with-goose.md)):

```sh
IPSO_MIGRATE_DATABASE_URL=postgres://ipso_migrate:...@db.example/ipso ipso-server migrate
```

The command reads the connection string from the `IPSO_MIGRATE_DATABASE_URL` environment variable only, applies the pending versions, and exits. Migrations have an Up section and no Down section: a bad migration is fixed by a new version. The command connects to the database directly, never through a transaction-mode pooler, because goose holds a session advisory lock.

An administrator prepares the database once, before the first run, because creating a role needs `CREATEROLE` and neither role has it:

- `ipso_migrate`: a login role that is not a superuser and has neither `BYPASSRLS` nor `CREATEROLE`. It owns the database, the schemas, the tables, the views and the `SECURITY DEFINER` functions.
- `ipso_app`: a login role with the same restrictions. It owns nothing and holds only the grants the migrations write.
- An empty database owned by `ipso_migrate`.
- `ipso.current_tenant()`, created by that same superuser. Only a superuser can mark a function leakproof, and the migration role is not one. The policies call it so the planner can use indexes. Its body is `nullif(current_setting('ipso.tenant', true), '')::uuid`.

```sql
CREATE SCHEMA ipso;
CREATE FUNCTION ipso.current_tenant() RETURNS uuid
    LANGUAGE sql STABLE LEAKPROOF
    SET search_path = pg_catalog, pg_temp
AS $$ SELECT nullif(current_setting('ipso.tenant', true), '')::uuid $$;
REVOKE ALL ON FUNCTION ipso.current_tenant() FROM PUBLIC;
GRANT USAGE ON SCHEMA ipso TO ipso_app, ipso_migrate;
GRANT EXECUTE ON FUNCTION ipso.current_tenant() TO ipso_app, ipso_migrate;
```

`ipso-server migrate` exits non-zero before it runs a statement when its session role or its current role is a superuser or has `BYPASSRLS`. PostgreSQL providers must allow `btree_gist` for the database owner. If yours does not, an administrator creates the extension before the first run.

The registry schema holds the bitemporal decision tables, the scope tree and its closure table. `internal/registry` resolves the decisions in force for a repo, path and environment from them ([ADR-0051](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0051-scope-model-and-resolution.md)). It also records a supersession, which closes the prior decision, and applies a baseline of violation fingerprints for one decision and repository ([ADR-0052](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0052-supersession-and-grandfathering.md)). It records a scoped waiver of at most 90 days and turns a fail into waived while the waiver and the decision both cover the valid time. `Notify` writes a `ticket_ref` notice at 14, 3, and 0 days before the waiver ends ([ADR-0054](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0054-waivers-with-expiry.md)). `internal/audit` answers the five audit questions as `GET /v1/audit/*`, which the control plane API mounts with the tenant from the token ([ADR-0055](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0055-audit-query-api.md)).

## Agent identities

`identity.principal` holds people and AI coding agents, and an agent must have a person in the same tenant as its sponsor. The database refuses an agent as the approver of a waiver or a proposal, so no route can forget the rule. `identity.action_log` records what a principal did, and the database writes the person responsible, whatever the caller sent ([ADR-0076](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0076-agent-identities.md)). `internal/identity` reads and writes these, and it trusts the tenant it is given. `identity.login` binds the subject of an OIDC issuer to a principal, and `identity.PrincipalFor` is the one way a verified token becomes a principal ([ADR-0093](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0093-single-tenant-token-mapping.md)). The API and the remote MCP handler call it, and no route writes a principal yet.

## Control plane API

`internal/api` is the control plane HTTP API, and [api/openapi.yaml](api/openapi.yaml) describes it in OpenAPI 3.1 ([ADR-0090](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0090-control-plane-api.md)). Every route reads. `POST /v1/resolve` answers a check request with each decision in force once, and names that decision by id on each changed path ([ADR-0092](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0092-resolve-answer-once.md)). `GET /v1/decisions`, `/v1/decisions/{ref}`, `/v1/scopes`, and `/v1/waivers` read the registry as in force at `valid` and as known at `known`, which default to now and are echoed in the answer. The three review queues list pending proposals, and the five audit routes answer section 2.3. No route writes before authorization exists (IPSO-66).

A request needs a bearer token in the `Authorization` header. `internal/authn` checks its signature, issuer, audience, and expiry, the same checks remote MCP makes. The tenant and the principal come from the token only, so a query key `tenant` or `tenant_id` is 400. A token that speaks for no principal of the tenant is 403, and an unknown route is 404 only after that, so routes cannot be listed without a token. An agent's call is logged with its human sponsor before it runs, and a call that cannot be logged does not run. Each request has a 10 second deadline, a 1 MiB body cap, and a 4 MiB answer cap. An answer over the cap is refused whole with 500 and never sent cut short. Each tenant may make 10 requests a second, with a burst of 20, on each process.

`ipso-server --role=api` serves it ([ADR-0094](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0094-the-api-role.md)). Row-level security is forced on every tenant table, and `internal/rls.Check` refuses a superuser, a `BYPASSRLS` role, the owner of a table, or a `tenant_id` table that is not forced (IPSO-61, ADR-0050). The role runs that check, then looks for the tenant's row in `tenancy.tenant`, then reads the issuer's metadata over https, and serves nothing before all three pass. It also refuses to start when `IPSO_MIGRATE_DATABASE_URL` is in its environment. The API connection, like `migrate`, has to be a session connection and not a transaction-mode pooler, because `ipso.tenant` is set for one transaction. A token maps to a tenant and a principal only through a stored login for its issuer and subject, and the tenant is the one the process was started for (`IPSO_TENANT_ID`). `GET /healthz` answers 204 when the database answers, outside the guard and outside the OpenAPI document. A request limit per client belongs to the front of a deployment, as ADR-0090 says, and the Compose stack has one.

The contract tests check that the document is valid OpenAPI 3.1, that it lists exactly the routes `internal/api` mounts, that every route but `POST /v1/resolve` is a GET, and that every request and answer of the integration tests matches it. [api/pacts/ipso-web-ipso-server.json](api/pacts/ipso-web-ipso-server.json) is the pact of the web app, consumer `ipso-web`. A pact-go consumer test writes it, and `ci / pact` verifies it against the handler on PostgreSQL and fails when the committed file differs ([ADR-0091](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0091-api-contract-tests-and-pact.md)).

## Remote MCP

`internal/mcpremote` serves the MCP tools over Streamable HTTP as an OAuth 2.1 resource server, with the tool contract from `ipso`'s `pkg/mcptools`. It answers MCP 2026-07-28 statelessly, publishes Protected Resource Metadata (RFC 9728), checks a signed token's issuer, audience, and expiry, and asks for separate scopes to read and to propose. At start it refuses an authorization server that does not offer PKCE with S256 and Client ID Metadata Documents, because registering a client is that server's job. Every call writes an action log entry that names the agent's human sponsor, and a call that cannot be logged does not run. `checks.evaluate` refuses here, because code stays on the client's machine ([ADR-0006](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0006-local-first-evaluation.md)). `--role=api` mounts it when `IPSO_MCP_ISSUER` and `IPSO_MCP_RESOURCE_URL` are both set, after the same start checks as the API, with the principal of the login for the token's issuer and subject. It answers within 10 seconds and lets one tenant make 10 calls a second with a burst of 20 on each process, and the API keeps a bucket of its own. A token that names both audiences is refused by both handlers, so a token minted for one is refused by the other ([ADR-0077](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0077-remote-mcp.md), [ADR-0094](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0094-the-api-role.md)). The Compose stack leaves it off, because Dex offers no Client ID Metadata Documents.

## Worker

`ipso-server --role=worker` works the jobs of the control plane on River, in the registry's PostgreSQL, with no queue or workflow service of its own ([ADR-0096](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0096-river-job-runtime.md), [ADR-0097](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0097-the-worker-role.md)). `internal/worker` starts it under the checks of the api role: `internal/rls.Check` refuses a superuser, a `BYPASSRLS` role, or the owner of a table, the tenant of `IPSO_TENANT_ID` needs a row, River's tables have to exist, and the process refuses to start when `IPSO_MIGRATE_DATABASE_URL` is in its environment. It opens no listener, so a probe has nothing to ask. It serves one tenant, and a job that names another tenant is cancelled before it runs. A job carries the tenant id and nothing else, and a failure is stored as an operation and an SQLSTATE class, so no row content reaches `river.river_job`. Like the API connection, the worker's has to be a session connection, because River listens for notifications.

The first job is `waiver_notices`. It runs every hour and once when a worker starts, is unique for its tenant while it waits or runs, and calls `registry.Notify`, which records each due 14, 3, and 0 day notice once ([ADR-0054](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0054-waivers-with-expiry.md)). Two workers, or a restart, record nothing twice. River's tables are in schema `river`, made by migrations 00015 to 00021 from River's own SQL for the pinned version, and `ipso_app` can read and write only `river_job`, `river_leader`, and `river_queue` there. A River upgrade adds a migration file, and a test fails until it does. The application role owns nothing, so River's reindexer is off, and reindexing and vacuuming `river_job` are operations work. River is MPL-2.0 and is used as an unmodified module. `ci / licenses` allows that license for River alone.

The premise jobs re-check the facts a decision rests on ([ADR-0053](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0053-decision-premises.md), [ADR-0098](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0098-the-premise-sweep.md)). `premise_sweep` runs every hour and once when a worker starts. It reads the decisions in force and queues one `premise_probe` job for each premise with no evaluation, or whose latest evaluation is older than its `every` days. A probe job asks again whether the premise is still due, checks the host against the tenant allowlist, runs the probe of `ipso premise check` through `pkg/premisecheck`, and records an evaluation. A host that is not on the allowlist, an empty allowlist, a revoked host, a redirect, a private address, and any other probe error are recorded as `error` and open no reason. A `fail` opens one review reason when none is open, and a `pass` clears nothing. The worker sends no `Authorization` header and no cookie, stores the observed value and the digest of the body and never the body, and changes no decision version, so `valid_period` and the stored status stay as they were. Probes run in their own queue with four workers. The allowlist has no API yet: a person adds a host with an insert into `registry.premise_host_allow`, and no route runs or records a premise until the role policy of IPSO-66 exists.

## GitHub App

`ipso-server webhooks` receives `pull_request` and `push` webhooks and validates the decision files of the change with the rules of `ipso check`. It reports a check run named `ipso / decisions` with an annotation on each invalid file. At start it reads the registered App and refuses to run unless its permissions are exactly `checks:write`, `contents:read`, `metadata:read`, and `pull_requests:write`. [docs/github-app.md](docs/github-app.md) covers registering the App and installing it in a sandbox organization.

## HCP Terraform run task

`ipso-server runtasks` receives run task requests from HCP Terraform or Terraform Enterprise, checks their signature, reads the plan, and evaluates it against one signed policy bundle with the rules of `ipso check plan`. A blocking violation reports `failed`, which stops the apply when the task's enforcement level is mandatory. A warning reports `passed` with an outcome that shows it. The plan stays in memory for that job, and the log holds only its hash and counts. [docs/hcp-terraform-run-task.md](docs/hcp-terraform-run-task.md) covers the bundle, the task settings, and a validation on a real workspace.

## LLM gateway

`internal/llmgw` is the one way ipso calls a model ([ADR-0081](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0081-llm-gateway.md)). It reads a JSON configuration of routes, each a provider and a model with its key in an `IPSO_LLM_*` environment variable. The operator's routes must be EU-resident: Mistral at `api.mistral.ai`, Amazon Bedrock in an EU region with a model id that is not a non-EU cross-region profile, or an Azure OpenAI resource in an EU region with a Standard or Data Zone deployment ([ADR-0014](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0014-eu-only-llm-routes-by-default.md)). A tenant can bring its own key (BYOK), including an OpenAI-compatible endpoint or an open-weight server on the same machine over plain http to loopback, and a route the gateway cannot place in the EU needs `allow_non_eu` on that tenant's route. Each call reserves its largest cost against the tenant's monthly token budget in `llm.usage` before anything is sent, and settles to what the provider reports. Secrets, email addresses, and the operator's own patterns are redacted from every prompt. Every prompt asks for one JSON object, so a chat completions route is asked for JSON mode; Bedrock has none, and the callers check every answer ([ADR-0087](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0087-json-mode-on-chat-routes.md)). Each pipeline bounds the tokens of its answer, and a route waits 90 seconds unless it sets `timeout_seconds`, up to 600, for a model served on CPU ([ADR-0088](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0088-answer-and-wait-bounds.md)). Routes are tried in order on a timeout, a rate limit, or a server error, and a redirect is never followed. The log holds the tenant, route, model, and token counts, never a prompt or an answer. The binary does not build the gateway yet: the control plane wires it once row-level security exists.

## Decision proposals

`internal/proposals` turns the discussion of a merged pull request into decision proposals in four stages: classify, extract, dedupe, propose. It sends only comments that read as a decision, keeps text from outsiders and text with an injection marker away from the LLM, redacts secrets before any call, puts a random canary in the system prompt, checks the answer strictly, refuses an answer that repeats the canary and a title that shares no word with its statement, drops a proposal that restates a decision in force for the repository or a pending proposal of the tenant, and stores rows that can only be `pending` ([ADR-0062](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0062-pr-decision-proposals.md), [ADR-0085](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0085-decision-extraction-pipeline.md)). `GET /v1/proposals` is the inbox, and `GET /v1/agent-proposals` lists what coding agents proposed over MCP. The control plane API mounts both. The binary does not call this package yet: that waits for row-level security, with the LLM gateway.

It also drafts an agent-edit check for a decision in force from edits a person wrote for it, some to deny and some to allow. The model answers with up to three candidate rules as data, the server writes the Rego of each and compiles it with `pkg/rulecheck` of ipso, the way `ipso compile` does, and the first candidate that passes every edit is proposed, after at most one repair. `proposals.check_proposal` refuses a rule that failed one, and `GET /v1/check-proposals` is its review queue ([ADR-0086](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0086-llm-drafted-agent-edit-checks.md)).

## LLM evals

`internal/evals` scores each LLM pipeline on synthetic golden datasets in `internal/evals/testdata` ([ADR-0082](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0082-go-eval-harness.md)). `go test ./...` replays the recorded answers in `cassette.json` and fails when a score drops more than 3 points below `baseline.json` or under its floor, such as the 0.8 precision and 0.6 recall that decision extraction must keep. The red-team suite runs the synthetic attacks of `redteam.json`, with benign controls, through the pull request pipeline and tracks how many the screen keeps from the model, how many benign comments it lets through, how many attacks the model resists, and whether it ever repeats the canary ([ADR-0084](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0084-prompt-injection-red-team.md)). The check suite drafts a rule for each decision of `check-decisions.json` and tracks the share proposed, which must stay at 0.9 or more, the share proposed without the repair, and the share that also passes edits the model never saw. The `evals` workflow records fresh answers through the gateway against a pinned open-weight model that llama.cpp serves on the runner, and keeps them as an artifact. To accept a run, copy its `cassette.json` into `internal/evals/testdata` and write the new baseline:

```sh
go test ./internal/evals -run '^TestEvals$' -update
```

## Development

```sh
go build ./...
go test ./...
go test -tags integration -count=1 ./...
```

The smoke test of the Compose stack runs in CI with `-tags compose`, against a running stack.

The integration tests start PostgreSQL 18 with Testcontainers, so they need a Docker-compatible socket. They use synthetic rows only.

The Pact tests link the Pact FFI 0.5 (`libpact_ffi`), so they need it on the linker path. `ci / pact` installs a pinned release and runs them:

```sh
go test -tags pact -run TestPactConsumer -count=1 ./internal/api
go test -tags 'integration pact' -run TestPactProvider -count=1 ./internal/api
```

## License

Functional Source License, Version 1.1, Apache 2.0 future license (FSL-1.1-ALv2). See [LICENSE](LICENSE).

Copyright 2026 Luca Bertelli.

## Contributing

Follow the contributor terms in [ipsofacto-io/.github](https://github.com/ipsofacto-io/.github/blob/main/CONTRIBUTING.md).
