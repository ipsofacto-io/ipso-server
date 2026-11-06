-- +goose Up
-- Browser sessions, ADR-0099. A session is the server-side half of the cookie a person holds after a
-- sign-in through an identity provider. It names the login that signed in, so the principal is read
-- through identity.login on every lookup and a future revocation of a login ends its sessions. The
-- cookie holds 32 random bytes and the table holds their SHA-256, so a read of this table is not a
-- session. created_at and expires_at are stamped by the trigger, so no writer can lengthen a session.
-- The trigger also refuses a login of an agent: an agent has no browser and keeps its bearer login.
-- The trigger is not SECURITY DEFINER. It reads identity.login and identity.principal as the
-- application role, under the same policies as every other read.
--
-- The application role may select, insert, and delete a session and never update one. Deleting is how
-- a session ends, and how StartSession drops the tenant's expired rows.
CREATE TABLE identity.session (
    tenant_id    uuid        NOT NULL,
    id           uuid        NOT NULL DEFAULT uuidv7(),
    login_id     uuid        NOT NULL,
    token_sha256 bytea       NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at   timestamptz NOT NULL DEFAULT clock_timestamp() + interval '8 hours',
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT session_token_once UNIQUE (tenant_id, token_sha256),
    CONSTRAINT session_login FOREIGN KEY (tenant_id, login_id)
        REFERENCES identity.login (tenant_id, id),
    CONSTRAINT session_token_length CHECK (octet_length(token_sha256) = 32),
    CONSTRAINT session_lifetime CHECK (expires_at > created_at)
);

CREATE INDEX session_by_expiry ON identity.session (tenant_id, expires_at);
CREATE INDEX session_by_login ON identity.session (tenant_id, login_id);

-- +goose StatementBegin
CREATE FUNCTION identity.session_stamp() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM identity.login l
        JOIN identity.principal p ON p.tenant_id = l.tenant_id AND p.id = l.principal_id
        WHERE l.tenant_id = NEW.tenant_id
          AND l.id = NEW.login_id
          AND p.kind = 'human'
    ) THEN
        RAISE EXCEPTION 'a session needs the login of a person'
            USING ERRCODE = 'check_violation';
    END IF;
    NEW.created_at := clock_timestamp();
    NEW.expires_at := NEW.created_at + interval '8 hours';
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER session_stamp
    BEFORE INSERT ON identity.session
    FOR EACH ROW EXECUTE FUNCTION identity.session_stamp();

ALTER TABLE identity.session ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.session FORCE ROW LEVEL SECURITY;

CREATE POLICY app_select ON identity.session
    FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON identity.session
    FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY app_delete ON identity.session
    FOR DELETE TO ipso_app
    USING (tenant_id = ipso.current_tenant());

GRANT SELECT, INSERT, DELETE ON identity.session TO ipso_app;
