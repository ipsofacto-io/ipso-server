-- +goose Up
-- Tenant choice at sign-in in multi-tenant API mode (IPSO-138, ADR-0171).
--
-- Extends migration 00047 so an interactive browser or CLI sign-in whose verified IdP subject
-- holds open human logins in two or more tenants can list those tenants with their display names
-- and hold a 5-minute, single-use server-side pending choice across multiple API replicas.
--
-- Security posture:
--   1. migrate_select on tenancy.tenant and identity.principal gains the no-tenant arm matching
--      migration 00047 while migrate_delete, migrate_insert, and every app_* policy stay strictly
--      single-tenant under FORCE ROW LEVEL SECURITY.
--   2. identity.login_choice has no tenant_id column (it precedes tenant selection and is excluded
--      from tenant exports and offboarding) and grants zero direct table privileges to ipso_app.
--   3. Five narrow SECURITY DEFINER functions owned by ipso_migrate (with pinned search_path and
--      EXECUTE granted only to ipso_app) mediate human tenant listing and single-key pending choice
--      lifecycle.

ALTER POLICY migrate_select ON tenancy.tenant
    USING (tenant_id = ipso.current_tenant() OR ipso.current_tenant() IS NULL);

ALTER POLICY migrate_select ON identity.principal
    USING (tenant_id = ipso.current_tenant() OR ipso.current_tenant() IS NULL);

CREATE TABLE identity.login_choice (
    token_sha256            bytea       PRIMARY KEY,
    issuer                  text        NOT NULL,
    subject                 text        NOT NULL,
    previous_session_sha256 bytea,
    cli_redirect_uri        text        NOT NULL DEFAULT '',
    cli_state               text        NOT NULL DEFAULT '',
    cli_challenge           text        NOT NULL DEFAULT '',
    created_at              timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at              timestamptz NOT NULL,
    CONSTRAINT login_choice_hash CHECK (octet_length(token_sha256) = 32),
    CONSTRAINT login_choice_issuer CHECK (
        char_length(issuer) BETWEEN 9 AND 2000
        AND issuer ~ '^https://[^[:space:][:cntrl:]]+$'),
    CONSTRAINT login_choice_subject CHECK (
        char_length(subject) BETWEEN 1 AND 255
        AND btrim(subject) = subject
        AND subject !~ '[[:cntrl:]]'),
    CONSTRAINT login_choice_previous CHECK (
        previous_session_sha256 IS NULL
        OR octet_length(previous_session_sha256) = 32),
    CONSTRAINT login_choice_cli CHECK (
        (cli_redirect_uri = '' AND cli_state = '' AND cli_challenge = '')
        OR (
            cli_redirect_uri <> ''
            AND cli_state <> ''
            AND cli_challenge <> ''
            AND char_length(cli_redirect_uri) <= 256
            AND char_length(cli_state) <= 256
            AND char_length(cli_challenge) BETWEEN 43 AND 128
        )),
    CONSTRAINT login_choice_cli_no_previous CHECK (
        cli_redirect_uri = '' OR previous_session_sha256 IS NULL),
    CONSTRAINT login_choice_expiry CHECK (expires_at > created_at)
);

CREATE INDEX login_choice_by_expiry ON identity.login_choice (expires_at);
CREATE INDEX login_choice_by_subject ON identity.login_choice (issuer, subject);

REVOKE ALL ON TABLE identity.login_choice FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION identity.human_login_tenants(p_issuer text, p_subject text)
    RETURNS TABLE (tenant_id uuid, tenant_name text)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
AS $$
    SELECT l.tenant_id, t.name
    FROM identity.login AS l
    JOIN identity.principal AS p
      ON p.tenant_id = l.tenant_id AND p.id = l.principal_id
    JOIN tenancy.tenant AS t
      ON t.tenant_id = l.tenant_id
    WHERE l.issuer = p_issuer
      AND l.subject = p_subject
      AND l.closed_at IS NULL
      AND p.kind = 'human'
    ORDER BY t.name, l.tenant_id
    LIMIT 100
$$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION identity.human_login_tenants(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.human_login_tenants(text, text) TO ipso_app;

-- +goose StatementBegin
CREATE FUNCTION identity.create_login_choice(
    p_token_sha256 bytea,
    p_issuer text,
    p_subject text,
    p_previous_session_sha256 bytea,
    p_cli_redirect_uri text,
    p_cli_state text,
    p_cli_challenge text
) RETURNS timestamptz
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    v_now timestamptz := clock_timestamp();
    v_expires timestamptz := v_now + interval '5 minutes';
BEGIN
    DELETE FROM identity.login_choice
    WHERE expires_at <= v_now
       OR (issuer = p_issuer AND subject = p_subject);
    INSERT INTO identity.login_choice (
        token_sha256,
        issuer,
        subject,
        previous_session_sha256,
        cli_redirect_uri,
        cli_state,
        cli_challenge,
        created_at,
        expires_at
    ) VALUES (
        p_token_sha256,
        p_issuer,
        p_subject,
        p_previous_session_sha256,
        coalesce(p_cli_redirect_uri, ''),
        coalesce(p_cli_state, ''),
        coalesce(p_cli_challenge, ''),
        v_now,
        v_expires
    );
    RETURN v_expires;
END;
$$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION identity.create_login_choice(bytea, text, text, bytea, text, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.create_login_choice(bytea, text, text, bytea, text, text, text) TO ipso_app;

-- +goose StatementBegin
CREATE FUNCTION identity.read_login_choice(p_token_sha256 bytea)
    RETURNS TABLE (issuer text, subject text, is_cli boolean, expires_at timestamptz)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
AS $$
    SELECT c.issuer, c.subject, (c.cli_redirect_uri <> '') AS is_cli, c.expires_at
    FROM identity.login_choice AS c
    WHERE c.token_sha256 = p_token_sha256
      AND c.expires_at > clock_timestamp()
$$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION identity.read_login_choice(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.read_login_choice(bytea) TO ipso_app;

-- +goose StatementBegin
CREATE FUNCTION identity.consume_login_choice(p_token_sha256 bytea)
    RETURNS TABLE (
        issuer text,
        subject text,
        previous_session_sha256 bytea,
        cli_redirect_uri text,
        cli_state text,
        cli_challenge text
    )
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    v_now timestamptz := clock_timestamp();
BEGIN
    DELETE FROM identity.login_choice WHERE expires_at <= v_now;
    RETURN QUERY
    DELETE FROM identity.login_choice AS c
    WHERE c.token_sha256 = p_token_sha256
      AND c.expires_at > v_now
    RETURNING
        c.issuer,
        c.subject,
        c.previous_session_sha256,
        c.cli_redirect_uri,
        c.cli_state,
        c.cli_challenge;
END;
$$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION identity.consume_login_choice(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.consume_login_choice(bytea) TO ipso_app;

-- +goose StatementBegin
CREATE FUNCTION identity.cancel_login_choice(p_token_sha256 bytea)
    RETURNS void
    LANGUAGE plpgsql VOLATILE SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    v_now timestamptz := clock_timestamp();
BEGIN
    DELETE FROM identity.login_choice
    WHERE token_sha256 = p_token_sha256
       OR expires_at <= v_now;
END;
$$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION identity.cancel_login_choice(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION identity.cancel_login_choice(bytea) TO ipso_app;
