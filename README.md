# ipso-server

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/ipsofacto-io/ipso-server/badge)](https://scorecard.dev/viewer/?uri=github.com/ipsofacto-io/ipso-server)

Source-available control plane for [ipso](https://github.com/ipsofacto-io/ipso): a bitemporal engineering decision registry, HTTP API, web app, remote MCP server, background worker, and PR/Terraform enforcement services.

> Status: early release. One Go modular monolith ships the API, embedded web SPA, background worker, GitHub App webhooks, HCP Terraform run tasks, Helm chart, and Docker Compose bundle. The combined `all` role is not built yet.

## Quick start (local stack)

Run the full control plane locally (PostgreSQL 18, migrations, seeded tenant, Dex OIDC provider, API, worker, and rate-limited nginx front) with Docker Compose:

```sh
cp .env.example .env
docker compose up --build
```

- See [docs/local-stack.md](docs/local-stack.md) for obtaining a token, calling the API, and signing in via browser (`ci / compose` smoke-tests this stack on every change).
- For production deployments, use the supported Helm chart or Compose bundle in [docs/install.md](docs/install.md).

## Commands and runtime roles

| Command | Role / purpose |
| --- | --- |
| `ipso-server --role=api` | Serves the control-plane HTTP API ([OpenAPI 3.1](api/openapi.yaml)), embedded web app, browser OIDC login, and optional remote MCP server |
| `ipso-server --role=worker` | Runs background jobs on PostgreSQL via River: hourly waiver expiry notices, premise probes, and Slack/Teams digests |
| `ipso-server migrate` | Applies embedded goose PostgreSQL 18 migrations using `IPSO_MIGRATE_DATABASE_URL` |
| `ipso-server webhooks` | Handles GitHub App `pull_request` and `push` checks (`ipso / decisions`) and optional LLM decision extraction on merged PRs |
| `ipso-server runtasks` | Evaluates HCP Terraform / Terraform Enterprise run tasks against a signed policy bundle |
| `ipso-server probe` | Health probe for the worker heartbeat file (used by the Helm chart) |
| `ipso-server tenant ...` | Tenant administration (`create`, `export`, `restore`, `offboard`, `bind-installation`; see [docs/tenants.md](docs/tenants.md)) |
| `ipso-server audit-log verify` | Verifies the per-tenant hash-chained action log ([docs/audit-log.md](docs/audit-log.md)) |
| `ipso-server proposals acceptance` | Reports proposal approval rates by prompt version and model (never by person) |

## Core capabilities

- **Bitemporal decision registry:** Stores decision versions, hierarchical scopes, supersessions, baselines, and time-bounded waivers (up to 90 days) in PostgreSQL 18 with forced row-level security.
- **Control-plane API and web app:** OpenAPI 3.1 HTTP API paired with an embedded React/Vite/TypeScript SPA ([web/](web), [docs/web-app.md](docs/web-app.md)) protected by OIDC bearer tokens or `__Host-ipso-session` browser cookies and embedded Rego RBAC ([docs/roles.md](docs/roles.md)).
- **Agent identities and hash-chained audit log:** AI coding agents require a human sponsor in the same tenant, cannot approve waivers or proposals, and every agent call or write is recorded transactionally in a tamper-evident hash chain ([docs/audit-log.md](docs/audit-log.md)).
- **Remote MCP server:** Stateless Streamable HTTP OAuth 2.1 resource server sharing the `pkg/mcptools` contract from `ipso` (mounted when `IPSO_MCP_ISSUER` and `IPSO_MCP_RESOURCE_URL` are set).
- **Automated PR and Terraform checks:** GitHub App check runs ([docs/github-app.md](docs/github-app.md)) and HCP Terraform run tasks ([docs/hcp-terraform-run-task.md](docs/hcp-terraform-run-task.md)).
- **EU-first LLM gateway and evals:** Optional proposal extraction from merged PR discussions and agent-edit check drafting behind an EU-resident default LLM gateway with secret redaction, monthly token budgets, prompt-injection screening, and golden/red-team eval suites ([docs/evals.md](docs/evals.md)).
- **OpenTelemetry:** Optional OTLP/HTTP traces and metrics (enabled only when `OTEL_EXPORTER_OTLP_ENDPOINT` is set) with strict attribute allowlists and Grafana dashboards in `deploy/telemetry` ([docs/telemetry.md](docs/telemetry.md)).

See [docs/architecture.md](docs/architecture.md) for the full internal package guide and ADR map.

## Database prerequisites

`ipso-server` requires PostgreSQL 18 with strict role separation and forced row-level security (no superuser, no `BYPASSRLS`, no transaction-mode pooler):

- `ipso_migrate`: non-superuser login role (no `BYPASSRLS`, no `CREATEROLE`) that owns the database, schemas, tables, and migrations.
- `ipso_app`: non-superuser login role that owns nothing and holds only least-privilege grants written by migrations.
- `ipso.current_tenant()`: leakproof helper function created once by a superuser so RLS policies can use indexes.

See [docs/database.md](docs/database.md) for the exact bootstrap SQL, `btree_gist` and `session_replication_role` requirements, and migration rules.

## Documentation

| Guide | Topic |
| --- | --- |
| [docs/local-stack.md](docs/local-stack.md) | Running and calling the local Docker Compose stack |
| [docs/install.md](docs/install.md) | Production Helm chart and Docker Compose bundle install |
| [docs/database.md](docs/database.md) | PostgreSQL 18 role bootstrap SQL, RLS checks, and goose migrations |
| [docs/architecture.md](docs/architecture.md) | Internal package architecture, security invariants, and ADR map |
| [docs/login.md](docs/login.md) | OIDC/GitHub browser sign-in and user invitations |
| [docs/roles.md](docs/roles.md) | Roles and route permissions |
| [docs/tenants.md](docs/tenants.md) | Tenant lifecycle, export, restore, offboarding, and crypto-shredding |
| [docs/audit-log.md](docs/audit-log.md) | Hash-chained action log and verification |
| [docs/verdicts.md](docs/verdicts.md) | CI verdict uploads and baseline reads |
| [docs/web-app.md](docs/web-app.md) | Embedded React web SPA |
| [docs/github-app.md](docs/github-app.md) | GitHub App registration, permissions, and PR checks |
| [docs/hcp-terraform-run-task.md](docs/hcp-terraform-run-task.md) | HCP Terraform / Terraform Enterprise run tasks |
| [docs/evals.md](docs/evals.md) | LLM extraction, red-team, and check-drafting eval suites |
| [docs/telemetry.md](docs/telemetry.md) | OpenTelemetry metrics, traces, and local Grafana stack |
| [api/openapi.yaml](api/openapi.yaml) | OpenAPI 3.1 HTTP API specification |

## Module boundary and enterprise builds

- `go.mod` may require `ipso` (`pkg/*` shared libraries).
- Enterprise features register from `ipso-ee` via the `ee` build tag; community builds never depend on `ipso-ee`.
- Enterprise versions stay in lockstep with `ipso-server` (`EE vX.Y.Z` matches server `vX.Y.Z`).

## Development and testing

Build and run unit and integration tests (integration tests start PostgreSQL 18 via Testcontainers and require a Docker-compatible socket):

```sh
go build ./...
go test ./...
go test -tags integration -count=1 ./...
```

Build and test the embedded web app (requires Node 24; `go build` works without it and serves a placeholder at `/`):

```sh
cd web && npm ci && npm test && npm run build
```

Additional targeted suites:

- **Compose smoke test:** runs in CI with `-tags compose` against the running stack.
- **Resolve latency budget (unloaded runner):** `go test -tags integration -count=1 -v -run '^TestResolveP95UnderBudgetAt10kDecisions$' ./internal/registry`
- **Pact contract tests (requires `libpact_ffi` 0.5 on linker path):**

```sh
(cd web && npm run test:pact)
go test -tags 'integration pact' -run TestPactProvider -count=1 ./internal/api
```

## License

Functional Source License, Version 1.1, Apache 2.0 future license (FSL-1.1-ALv2). Each release converts to Apache-2.0 two years after publication. See [LICENSE](LICENSE).

Copyright 2026 Luca Bertelli.

## Contributing

Follow the contributor guidelines in [ipsofacto-io/.github](https://github.com/ipsofacto-io/.github/blob/main/CONTRIBUTING.md).
