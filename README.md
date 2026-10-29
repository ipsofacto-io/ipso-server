# ipso-server

[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/ipsofacto-io/ipso-server/badge)](https://scorecard.dev/viewer/?uri=github.com/ipsofacto-io/ipso-server)

Source-available ipso control plane: bitemporal decision registry, API, web app and PR checks.

> Status: early. The binary has one command, `ipso-server migrate`, which applies the PostgreSQL 18 schema. The registry API and the rest of the control plane land in later changes.

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

The registry schema holds the bitemporal decision tables, the scope tree and its closure table. `internal/registry` resolves the decisions in force for a repo, path and environment from them ([ADR-0051](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0051-scope-model-and-resolution.md)).

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
