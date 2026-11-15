-- +goose Up
-- Invitations, ADR-0127. An admin invites a person by name and role, and the first sign-in that carries
-- the invitation binds that person's issuer and subject to a new human principal, a login and the role,
-- so no operator inserts a login with SQL. The link holds 32 random bytes and this table holds their
-- SHA-256, so a read of the table is not an invitation, like identity.session (ADR-0099).
--
-- An invitation is used once by deleting it in the transaction that writes the person, so a second use
-- finds no row. Revoking is a delete too, and the expired rows go whenever an invitation is made or
-- used. The application role may select, insert and delete one and never update one. The audit trail is
-- the action log, which names the person who invited and the person who accepted.
--
-- created_at and expires_at are stamped by the trigger, so no writer can lengthen an invitation, and
-- the trigger refuses an inviter who is not a person. The role is one a person may hold: an agent is
-- never invited. The trigger is not SECURITY DEFINER. It reads identity.principal as the application
-- role, under the same policies as every other read.
CREATE TABLE identity.invitation (
    tenant_id    uuid        NOT NULL,
    id           uuid        NOT NULL DEFAULT uuidv7(),
    token_sha256 bytea       NOT NULL,
    name         text        NOT NULL,
    role         text        NOT NULL,
    created_by   uuid        NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at   timestamptz NOT NULL DEFAULT clock_timestamp() + interval '7 days',
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT invitation_token_once UNIQUE (tenant_id, token_sha256),
    CONSTRAINT invitation_creator FOREIGN KEY (tenant_id, created_by)
        REFERENCES identity.principal (tenant_id, id),
    CONSTRAINT invitation_token_length CHECK (octet_length(token_sha256) = 32),
    CONSTRAINT invitation_name CHECK (
        char_length(name) BETWEEN 1 AND 200
        AND btrim(name) = name
        AND name !~ '[[:cntrl:]]'),
    CONSTRAINT invitation_role CHECK (role IN (
        'viewer', 'contributor', 'decision-owner', 'approver', 'admin', 'auditor')),
    CONSTRAINT invitation_lifetime CHECK (expires_at > created_at)
);

CREATE INDEX invitation_by_expiry ON identity.invitation (tenant_id, expires_at);

-- +goose StatementBegin
CREATE FUNCTION identity.invitation_stamp() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM identity.principal p
        WHERE p.tenant_id = NEW.tenant_id
          AND p.id = NEW.created_by
          AND p.kind = 'human'
    ) THEN
        RAISE EXCEPTION 'an invitation is made by a person'
            USING ERRCODE = 'check_violation';
    END IF;
    NEW.created_at := clock_timestamp();
    NEW.expires_at := NEW.created_at + interval '7 days';
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER invitation_stamp
    BEFORE INSERT ON identity.invitation
    FOR EACH ROW EXECUTE FUNCTION identity.invitation_stamp();

ALTER TABLE identity.invitation ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.invitation FORCE ROW LEVEL SECURITY;

CREATE POLICY app_select ON identity.invitation
    FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON identity.invitation
    FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY app_delete ON identity.invitation
    FOR DELETE TO ipso_app
    USING (tenant_id = ipso.current_tenant());

-- Offboarding (ADR-0100) deletes an invitation with the rest of the tenant. An export leaves it out, like
-- a session, because it holds a credential hash, so there is nothing to restore.
CREATE POLICY migrate_select ON identity.invitation
    FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON identity.invitation
    FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());

GRANT SELECT, INSERT, DELETE ON identity.invitation TO ipso_app;
