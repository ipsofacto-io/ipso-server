#!/bin/sh
# Prepares the database once, the way an administrator does before the first migrate (README,
# "Database schema"): two login roles that are not superusers and have neither BYPASSRLS nor
# CREATEROLE, an empty database owned by the migration role, and ipso.current_tenant().
# The image runs this on first start only, as the superuser.
set -eu

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
    -v migrate_password="$IPSO_MIGRATE_PASSWORD" -v app_password="$IPSO_APP_PASSWORD" <<'SQL'
CREATE ROLE ipso_migrate LOGIN PASSWORD :'migrate_password';
CREATE ROLE ipso_app LOGIN PASSWORD :'app_password';
CREATE DATABASE ipso OWNER ipso_migrate;
SQL

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname ipso <<'SQL'
CREATE SCHEMA ipso;
CREATE FUNCTION ipso.current_tenant() RETURNS uuid
    LANGUAGE sql STABLE LEAKPROOF
    SET search_path = pg_catalog, pg_temp
AS $$ SELECT nullif(current_setting('ipso.tenant', true), '')::uuid $$;
REVOKE ALL ON FUNCTION ipso.current_tenant() FROM PUBLIC;
GRANT USAGE ON SCHEMA ipso TO ipso_app, ipso_migrate;
GRANT EXECUTE ON FUNCTION ipso.current_tenant() TO ipso_app, ipso_migrate;
SQL
