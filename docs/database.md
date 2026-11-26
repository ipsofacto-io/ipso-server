# Database setup and migrations

`ipso-server` stores its bitemporal decision registry, identity tables, and River job queue in **PostgreSQL 18** ([ADR-0003](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0003-bitemporal-store-on-postgresql-18.md)).

## One-time administrator bootstrap

Because neither runtime role has `CREATEROLE` or superuser privileges, a database administrator prepares the database once before the first migration:

1. Create two non-superuser login roles with neither `BYPASSRLS` nor `CREATEROLE`:
   - `ipso_migrate`: owns the database, schemas, tables, views, and `SECURITY DEFINER` functions.
   - `ipso_app`: owns nothing and receives only least-privilege grants created by migrations.
2. Create an empty database owned by `ipso_migrate`.
3. Ensure `btree_gist` is available to `ipso_migrate` (if your managed provider restricts extension creation, create `btree_gist` as a superuser before the first run).
4. Optional (PostgreSQL 15+): grant `session_replication_role` to `ipso_migrate` for `ipso-server tenant restore` and `tenant offboard` ([ADR-0100](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0100-tenant-lifecycle-and-crypto-shredding.md)). `ipso_app` never gets this grant; providers that refuse it can still run every other command:

   ```sql
   GRANT SET ON PARAMETER session_replication_role TO ipso_migrate;
   ```

5. Create the leakproof tenant helper function as a superuser (required so PostgreSQL's planner can use indexes inside RLS policies):

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

## Running migrations

Migrations are embedded goose v3.29.0 SQL files applied by one command ([ADR-0050](https://github.com/ipsofacto-io/ipso-spec/blob/main/docs/adr/0050-schema-migrations-with-goose.md)):

```sh
IPSO_MIGRATE_DATABASE_URL=postgres://ipso_migrate:...@db.example/ipso ipso-server migrate
```

- **Environment variable only:** `migrate` reads the DSN exclusively from `IPSO_MIGRATE_DATABASE_URL`, applies pending migrations, and exits.
- **Forward-only:** Migrations have `Up` sections only; mistakes are fixed with a new migration version.
- **Session connection required:** Connect directly to PostgreSQL (never through a transaction-mode pooler) because goose holds a session advisory lock. The API and worker roles also require session connections (`SET LOCAL ipso.tenant` and River `LISTEN`).
- **Fail-closed privilege checks:** `migrate` exits non-zero before running any statement if its session or current role is a superuser or has `BYPASSRLS`. Both `--role=api` and `--role=worker` also refuse to start if `IPSO_MIGRATE_DATABASE_URL` is present in their environment.

## Row-level security enforcement

Row-level security is forced on every tenant table. At startup, `internal/rls.Check` refuses to start if the connected role is a superuser, has `BYPASSRLS`, owns any table, or if any `tenant_id` table lacks `FORCE ROW LEVEL SECURITY`.
