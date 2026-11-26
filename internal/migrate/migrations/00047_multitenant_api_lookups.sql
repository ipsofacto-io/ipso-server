-- +goose Up
-- Multi-tenant API credential lookups (IPSO-187, ADR-0170).
--
-- In multi-tenant mode (IPSO_MULTI_TENANT=true), one ipso-server --role=api process serves every
-- tenant of its database. Every request's tenant comes strictly from a verified credential or stored
-- mapping, never from a query, header, or body.
--
-- On the pattern of tenancy.installation_tenant (ADR-0101) and integrations.tracker_binding_for_webhook
-- (ADR-0133), this migration adds:
--   1. Global uniqueness constraints on cryptographic credential hashes of five non-exported tables
--      (session, cli_session, invitation, scim_token, agent_pin), plus a partial btree index on
--      open logins in identity.login.
--   2. A no-tenant arm on migrate_select (and never on migrate_delete, migrate_insert, or any app_*
--      policy) for those six tables, while keeping FORCE ROW LEVEL SECURITY enabled on every table.
--   3. Six narrow SECURITY DEFINER single-key lookup functions owned by ipso_migrate and executable
--      only by ipso_app. Each caller clears ipso.tenant before invoking the lookup, then performs all
--      actual credential checks, reads, and writes in normal ipso_app transactions with ipso.tenant set.

ALTER TABLE identity.session
    ADD CONSTRAINT session_token_global UNIQUE (token_sha256);

ALTER TABLE identity.cli_session
    ADD CONSTRAINT cli_session_token_global UNIQUE (token_sha256);

ALTER TABLE identity.invitation
    ADD CONSTRAINT invitation_token_global UNIQUE (token_sha256);

ALTER TABLE identity.scim_token
    ADD CONSTRAINT scim_token_global UNIQUE (token_sha256);

ALTER TABLE verification.agent_pin
    ADD CONSTRAINT agent_pin_global UNIQUE (pin_sha256);

CREATE INDEX login_by_issuer_subject
    ON identity.login (issuer, subject)
    WHERE closed_at IS NULL;

-- Extend migrate_select so the SECURITY DEFINER lookups below can resolve a single key when no
-- tenant is set. migrate_delete, migrate_insert, and every app_* policy keep strict single-tenant
-- predicates.
ALTER POLICY migrate_select ON identity.login
    USING (tenant_id = ipso.current_tenant() OR ipso.current_tenant() IS NULL);

ALTER POLICY migrate_select ON identity.session
    USING (tenant_id = ipso.current_tenant() OR ipso.current_tenant() IS NULL);

ALTER POLICY migrate_select ON identity.cli_session
    USING (tenant_id = ipso.current_tenant() OR ipso.current_tenant() IS NULL);

ALTER POLICY migrate_select ON identity.invitation
    USING (tenant_id = ipso.current_tenant() OR ipso.current_tenant() IS NULL);

ALTER POLICY migrate_select ON identity.scim_token
    USING (tenant_id = ipso.current_tenant() OR ipso.current_tenant() IS NULL);

ALTER POLICY migrate_select ON verification.agent_pin
    USING (tenant_id = ipso.current_tenant() OR ipso.current_tenant() IS NULL);

-- +goose StatementBegin
CREATE FUNCTION identity.login_tenants(p_issuer text, p_subject text)
    RETURNS TABLE (tenant_id uuid)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
AS $$
    SELECT l.tenant_id
    FROM identity.login AS l
    WHERE l.issuer = p_issuer
      AND l.subject = p_subject
      AND l.closed_at IS NULL
    ORDER BY l.tenant_id
    LIMIT 2
$$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION identity.login_tenants(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.login_tenants(text, text) TO ipso_app;

-- +goose StatementBegin
CREATE FUNCTION identity.session_tenant(p_token_sha256 bytea) RETURNS uuid
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
AS $$
    SELECT s.tenant_id
    FROM identity.session AS s
    WHERE s.token_sha256 = p_token_sha256
$$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION identity.session_tenant(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.session_tenant(bytea) TO ipso_app;

-- +goose StatementBegin
CREATE FUNCTION identity.cli_session_tenant(p_token_sha256 bytea) RETURNS uuid
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
AS $$
    SELECT s.tenant_id
    FROM identity.cli_session AS s
    WHERE s.token_sha256 = p_token_sha256
$$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION identity.cli_session_tenant(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.cli_session_tenant(bytea) TO ipso_app;

-- +goose StatementBegin
CREATE FUNCTION identity.invitation_tenant(p_token_sha256 bytea) RETURNS uuid
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
AS $$
    SELECT i.tenant_id
    FROM identity.invitation AS i
    WHERE i.token_sha256 = p_token_sha256
      AND i.expires_at > clock_timestamp()
$$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION identity.invitation_tenant(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.invitation_tenant(bytea) TO ipso_app;

-- +goose StatementBegin
CREATE FUNCTION identity.scim_token_tenant(p_token_sha256 bytea) RETURNS uuid
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
AS $$
    SELECT t.tenant_id
    FROM identity.scim_token AS t
    WHERE t.token_sha256 = p_token_sha256
$$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION identity.scim_token_tenant(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.scim_token_tenant(bytea) TO ipso_app;

-- +goose StatementBegin
CREATE FUNCTION verification.agent_pin_tenant(p_pin_sha256 bytea) RETURNS uuid
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
AS $$
    SELECT p.tenant_id
    FROM verification.agent_pin AS p
    WHERE p.pin_sha256 = p_pin_sha256
$$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION verification.agent_pin_tenant(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION verification.agent_pin_tenant(bytea) TO ipso_app;
