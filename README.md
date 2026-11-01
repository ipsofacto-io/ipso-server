# ipso-server

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/ipsofacto-io/ipso-server/badge)](https://scorecard.dev/viewer/?uri=github.com/ipsofacto-io/ipso-server)

Source-available ipso control plane: bitemporal decision registry, API, web app and PR checks.

> Status: early. The binary has two commands. `ipso-server migrate` applies the PostgreSQL 18 schema. `ipso-server webhooks` serves the GitHub App webhook, holds no tenant data, and opens no database connection ([ADR-0061](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0061-github-app.md)). Audit query handlers for the five questions in section 2.3 exist and are not served until the control plane mounts them ([ADR-0055](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0055-audit-query-api.md)).

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

## GitHub App

`ipso-server webhooks` receives `pull_request` and `push` webhooks and validates the decision files of the change with the rules of `ipso check`. It reports a check run named `ipso / decisions` with an annotation on each invalid file. At start it reads the registered App and refuses to run unless its permissions are exactly `checks:write`, `contents:read`, `metadata:read`, and `pull_requests:write`. [docs/github-app.md](docs/github-app.md) covers registering the App and installing it in a sandbox organization.

## Decision proposals

`internal/proposals` turns the discussion of a merged pull request into decision proposals. It keeps text from outsiders and text with an injection marker away from the LLM, redacts secrets before any call, checks the answer strictly, and stores rows that can only be `pending` ([ADR-0062](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0062-pr-decision-proposals.md)). `GET /v1/proposals` is the inbox. The binary neither calls this package nor serves that route. The control plane wires both once the LLM gateway and row-level security exist.

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
