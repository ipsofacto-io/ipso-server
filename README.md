# ipso-server

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/ipsofacto-io/ipso-server/badge)](https://scorecard.dev/viewer/?uri=github.com/ipsofacto-io/ipso-server)

Source-available ipso control plane: bitemporal decision registry, API, web app and PR checks.

> Status: early. The binary has three commands. `ipso-server migrate` applies the PostgreSQL 18 schema. `ipso-server webhooks` serves the GitHub App webhook, holds no tenant data, and opens no database connection ([ADR-0061](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0061-github-app.md)). `ipso-server runtasks` serves an HCP Terraform run task on the same terms ([ADR-0065](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0065-hcp-terraform-run-task.md)). Audit query handlers for the five questions in section 2.3 exist and are not served until the control plane mounts them ([ADR-0055](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0055-audit-query-api.md)).

One Go modular monolith ships the registry API, the web SPA, the entitlement contract, the Helm chart and the Compose bundle, plus a separate Python worker for LLM extraction. The binary is `ipso-server`, which will start with `--role` once the control plane lands.

Module rule: `go.mod` may require `ipso`. Enterprise features register from `ipso-ee` through the `ee` build tag. Each release converts to Apache-2.0 two years after publication. Enterprise builds use the same version number: EE vX.Y.Z matches server vX.Y.Z.

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

`ipso-server migrate` exits non-zero before it runs a statement when its session role or its current role is a superuser or has `BYPASSRLS`. PostgreSQL providers must allow `btree_gist` for the database owner. If yours does not, an administrator creates the extension before the first run.

The registry schema holds the bitemporal decision tables, the scope tree and its closure table. `internal/registry` resolves the decisions in force for a repo, path and environment from them ([ADR-0051](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0051-scope-model-and-resolution.md)). It also records a supersession, which closes the prior decision, and applies a baseline of violation fingerprints for one decision and repository ([ADR-0052](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0052-supersession-and-grandfathering.md)). It records a scoped waiver of at most 90 days and turns a fail into waived while the waiver and the decision both cover the valid time. `Notify` writes a `ticket_ref` notice at 14, 3, and 0 days before the waiver ends ([ADR-0054](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0054-waivers-with-expiry.md)). `internal/audit` answers the five audit questions as `GET /v1/audit/*`. The binary does not serve those routes. The control plane mounts that handler with the tenant from the token ([ADR-0055](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0055-audit-query-api.md)).

## Agent identities

`identity.principal` holds people and AI coding agents, and an agent must have a person in the same tenant as its sponsor. The database refuses an agent as the approver of a waiver or a proposal, so no route can forget the rule. `identity.action_log` records what a principal did, and the database writes the person responsible, whatever the caller sent ([ADR-0076](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0076-agent-identities.md)). `internal/identity` reads and writes these, and it trusts the tenant it is given. The binary neither calls this package nor serves a route for it, because no request can carry a principal until the control plane, login, and roles exist.

## Remote MCP

`internal/mcpremote` serves the MCP tools over Streamable HTTP as an OAuth 2.1 resource server, with the tool contract from `ipso`'s `pkg/mcptools`. It answers MCP 2026-07-28 statelessly, publishes Protected Resource Metadata (RFC 9728), checks a signed token's issuer, audience, and expiry, and asks for separate scopes to read and to propose. At start it refuses an authorization server that does not offer PKCE with S256 and Client ID Metadata Documents, because registering a client is that server's job. Every call writes an action log entry that names the agent's human sponsor, and a call that cannot be logged does not run. `checks.evaluate` refuses here, because code stays on the client's machine ([ADR-0006](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0006-local-first-evaluation.md)). The binary does not mount this handler, because it needs a tenant from the token and no deployment may serve a tenant before row-level security ([ADR-0077](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0077-remote-mcp.md)).

## GitHub App

`ipso-server webhooks` receives `pull_request` and `push` webhooks and validates the decision files of the change with the rules of `ipso check`. It reports a check run named `ipso / decisions` with an annotation on each invalid file. At start it reads the registered App and refuses to run unless its permissions are exactly `checks:write`, `contents:read`, `metadata:read`, and `pull_requests:write`. [docs/github-app.md](docs/github-app.md) covers registering the App and installing it in a sandbox organization.

## HCP Terraform run task

`ipso-server runtasks` receives run task requests from HCP Terraform or Terraform Enterprise, checks their signature, reads the plan, and evaluates it against one signed policy bundle with the rules of `ipso check plan`. A blocking violation reports `failed`, which stops the apply when the task's enforcement level is mandatory. A warning reports `passed` with an outcome that shows it. The plan stays in memory for that job, and the log holds only its hash and counts. [docs/hcp-terraform-run-task.md](docs/hcp-terraform-run-task.md) covers the bundle, the task settings, and a validation on a real workspace.

## LLM gateway

`internal/llmgw` is the one way ipso calls a model ([ADR-0081](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0081-llm-gateway.md)). It reads a JSON configuration of routes, each a provider and a model with its key in an `IPSO_LLM_*` environment variable. The operator's routes must be EU-resident: Mistral at `api.mistral.ai`, Amazon Bedrock in an EU region with a model id that is not a non-EU cross-region profile, or an Azure OpenAI resource in an EU region with a Standard or Data Zone deployment ([ADR-0014](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0014-eu-only-llm-routes-by-default.md)). A tenant can bring its own key (BYOK), including an OpenAI-compatible endpoint or an open-weight server on the same machine over plain http to loopback, and a route the gateway cannot place in the EU needs `allow_non_eu` on that tenant's route. Each call reserves its largest cost against the tenant's monthly token budget in `llm.usage` before anything is sent, and settles to what the provider reports. Secrets, email addresses, and the operator's own patterns are redacted from every prompt. Routes are tried in order on a timeout, a rate limit, or a server error, and a redirect is never followed. The log holds the tenant, route, model, and token counts, never a prompt or an answer. The binary does not build the gateway yet: the control plane wires it once row-level security exists.

## Decision proposals

`internal/proposals` turns the discussion of a merged pull request into decision proposals. It keeps text from outsiders and text with an injection marker away from the LLM, redacts secrets before any call, puts a random canary in the system prompt, checks the answer strictly, refuses an answer that repeats the canary and a title that shares no word with its statement, and stores rows that can only be `pending` ([ADR-0062](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0062-pr-decision-proposals.md)). `GET /v1/proposals` is the inbox. The binary neither calls this package nor serves that route. The control plane wires both, with the LLM gateway, once row-level security exists.

## LLM evals

`internal/evals` scores each LLM pipeline on synthetic golden datasets in `internal/evals/testdata` ([ADR-0082](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0082-go-eval-harness.md)). `go test ./...` replays the recorded answers in `cassette.json` and fails when a score drops more than 3 points below `baseline.json` or under its floor. The red-team suite runs the synthetic attacks of `redteam.json`, with benign controls, through the pull request pipeline and tracks how many the screen keeps from the model, how many benign comments it lets through, how many attacks the model resists, and whether it ever repeats the canary ([ADR-0084](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0084-prompt-injection-red-team.md)). The `evals` workflow records fresh answers through the gateway against a pinned open-weight model that llama.cpp serves on the runner, and keeps them as an artifact. To accept a run, copy its `cassette.json` into `internal/evals/testdata` and write the new baseline:

```sh
go test ./internal/evals -run '^TestEvals$' -update
```

## Development

```sh
go build ./...
go test ./...
go test -tags integration -count=1 ./...
```

The integration tests start PostgreSQL 18 with Testcontainers, so they need a Docker-compatible socket. They use synthetic rows only.

## License

Functional Source License, Version 1.1, Apache 2.0 future license (FSL-1.1-ALv2). See [LICENSE](LICENSE).

Copyright 2026 Luca Bertelli.

## Contributing

Follow the contributor terms in [ipsofacto-io/.github](https://github.com/ipsofacto-io/.github/blob/main/CONTRIBUTING.md).
