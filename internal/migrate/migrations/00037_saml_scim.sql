-- +goose Up
-- SAML and SCIM, ADR-0131. The community server keeps the rows. The enterprise binary is the only
-- writer that provisions a person from an identity provider and the only writer that closes a login.
--
-- closed_at is the revocation ADR-0093 left open. The application role may update that column and no
-- other. The trigger refuses every other change, including a change of issuer or subject. A closed
-- login may be opened again when the same person is provisioned once more.
--
-- source marks a role binding that came from an IdP group. A binding an admin granted stays source
-- hand, which is the default, and a group push does not delete it.
--
-- identity.scim_user holds the SCIM filter key user_name. It is not a login and it is not an email
-- column: PrincipalFor never reads it. identity.scim_token holds the SHA-256 of the bearer token and
-- never the token. Both are left out of an export, like a session. Group rows, membership, and the
-- group-to-role map are part of the tenant and are exported.

ALTER TABLE identity.login
    ADD COLUMN closed_at timestamptz;

-- +goose StatementBegin
CREATE FUNCTION identity.login_close() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.id IS DISTINCT FROM OLD.id
        OR NEW.principal_id IS DISTINCT FROM OLD.principal_id
        OR NEW.issuer IS DISTINCT FROM OLD.issuer
        OR NEW.subject IS DISTINCT FROM OLD.subject
        OR NEW.sys_period IS DISTINCT FROM OLD.sys_period
    THEN
        RAISE EXCEPTION 'a login may close or reopen, and nothing else on it changes'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER login_close
    BEFORE UPDATE ON identity.login
    FOR EACH ROW EXECUTE FUNCTION identity.login_close();

REVOKE ALL ON FUNCTION identity.login_close() FROM PUBLIC;

CREATE POLICY app_update ON identity.login
    FOR UPDATE TO ipso_app
    USING (tenant_id = ipso.current_tenant())
    WITH CHECK (tenant_id = ipso.current_tenant());

GRANT UPDATE (closed_at) ON identity.login TO ipso_app;

-- A later provision may change the person's name. The application role may update that column
-- and no other. The trigger refuses every other change.

-- +goose StatementBegin
CREATE FUNCTION identity.principal_name() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.id IS DISTINCT FROM OLD.id
        OR NEW.kind IS DISTINCT FROM OLD.kind
        OR NEW.sponsor_id IS DISTINCT FROM OLD.sponsor_id
        OR NEW.sys_period IS DISTINCT FROM OLD.sys_period
    THEN
        RAISE EXCEPTION 'a principal name may change, and nothing else on it changes'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER principal_name
    BEFORE UPDATE ON identity.principal
    FOR EACH ROW EXECUTE FUNCTION identity.principal_name();

REVOKE ALL ON FUNCTION identity.principal_name() FROM PUBLIC;

CREATE POLICY app_update ON identity.principal
    FOR UPDATE TO ipso_app
    USING (tenant_id = ipso.current_tenant())
    WITH CHECK (tenant_id = ipso.current_tenant());

GRANT UPDATE (name) ON identity.principal TO ipso_app;

ALTER TABLE identity.role_binding
    ADD COLUMN source text NOT NULL DEFAULT 'hand';

ALTER TABLE identity.role_binding
    ADD CONSTRAINT role_binding_source CHECK (source IN ('hand', 'idp'));

CREATE TABLE identity.scim_user (
    tenant_id    uuid    NOT NULL,
    principal_id uuid    NOT NULL,
    external_id  text    NOT NULL,
    user_name    text    NOT NULL,
    active       boolean NOT NULL DEFAULT true,
    PRIMARY KEY (tenant_id, principal_id),
    CONSTRAINT scim_user_principal FOREIGN KEY (tenant_id, principal_id)
        REFERENCES identity.principal (tenant_id, id),
    CONSTRAINT scim_user_external_once UNIQUE (tenant_id, external_id),
    CONSTRAINT scim_user_name_once UNIQUE (tenant_id, user_name),
    CONSTRAINT scim_user_external CHECK (
        char_length(external_id) BETWEEN 1 AND 255
        AND btrim(external_id) = external_id
        AND external_id !~ '[[:cntrl:]]'),
    CONSTRAINT scim_user_user_name CHECK (
        char_length(user_name) BETWEEN 1 AND 200
        AND btrim(user_name) = user_name
        AND user_name !~ '[[:cntrl:]]')
);

CREATE TABLE identity.scim_token (
    tenant_id    uuid  NOT NULL,
    token_sha256 bytea NOT NULL,
    PRIMARY KEY (tenant_id),
    CONSTRAINT scim_token_tenant FOREIGN KEY (tenant_id)
        REFERENCES tenancy.tenant (tenant_id),
    CONSTRAINT scim_token_length CHECK (octet_length(token_sha256) = 32)
);

CREATE TABLE identity.scim_group (
    tenant_id uuid NOT NULL,
    id        uuid NOT NULL DEFAULT uuidv7(),
    group_ref text NOT NULL,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT scim_group_ref_once UNIQUE (tenant_id, group_ref),
    CONSTRAINT scim_group_ref CHECK (
        char_length(group_ref) BETWEEN 1 AND 200
        AND btrim(group_ref) = group_ref
        AND group_ref !~ '[[:cntrl:]]')
);

CREATE TABLE identity.scim_membership (
    tenant_id    uuid NOT NULL,
    group_id     uuid NOT NULL,
    principal_id uuid NOT NULL,
    PRIMARY KEY (tenant_id, group_id, principal_id),
    CONSTRAINT scim_membership_group FOREIGN KEY (tenant_id, group_id)
        REFERENCES identity.scim_group (tenant_id, id),
    CONSTRAINT scim_membership_principal FOREIGN KEY (tenant_id, principal_id)
        REFERENCES identity.principal (tenant_id, id)
);

CREATE TABLE identity.idp_group_role (
    tenant_id uuid NOT NULL,
    id        uuid NOT NULL DEFAULT uuidv7(),
    group_ref text NOT NULL,
    role      text NOT NULL,
    scope_id  uuid,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT idp_group_role_once UNIQUE NULLS NOT DISTINCT (tenant_id, group_ref, role, scope_id),
    CONSTRAINT idp_group_role_scope FOREIGN KEY (tenant_id, scope_id)
        REFERENCES registry.scope (tenant_id, id),
    CONSTRAINT idp_group_role_role CHECK (role IN (
        'viewer', 'contributor', 'decision-owner', 'approver', 'admin', 'auditor')),
    CONSTRAINT idp_group_role_scoped CHECK (
        scope_id IS NULL OR role IN ('contributor', 'decision-owner', 'approver')),
    CONSTRAINT idp_group_role_ref CHECK (
        char_length(group_ref) BETWEEN 1 AND 200
        AND btrim(group_ref) = group_ref
        AND group_ref !~ '[[:cntrl:]]')
);

ALTER TABLE identity.scim_user ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.scim_user FORCE ROW LEVEL SECURITY;
ALTER TABLE identity.scim_token ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.scim_token FORCE ROW LEVEL SECURITY;
ALTER TABLE identity.scim_group ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.scim_group FORCE ROW LEVEL SECURITY;
ALTER TABLE identity.scim_membership ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.scim_membership FORCE ROW LEVEL SECURITY;
ALTER TABLE identity.idp_group_role ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.idp_group_role FORCE ROW LEVEL SECURITY;

CREATE POLICY app_select ON identity.scim_user FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON identity.scim_user FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY app_update ON identity.scim_user FOR UPDATE TO ipso_app
    USING (tenant_id = ipso.current_tenant())
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY app_select ON identity.scim_token FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON identity.scim_token FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY app_delete ON identity.scim_token FOR DELETE TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_select ON identity.scim_group FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON identity.scim_group FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY app_delete ON identity.scim_group FOR DELETE TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_select ON identity.scim_membership FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON identity.scim_membership FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY app_delete ON identity.scim_membership FOR DELETE TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_select ON identity.idp_group_role FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON identity.idp_group_role FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY app_delete ON identity.idp_group_role FOR DELETE TO ipso_app
    USING (tenant_id = ipso.current_tenant());

-- Offboarding deletes every tenant table. An export leaves the credential tables out.
CREATE POLICY migrate_select ON identity.scim_user FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON identity.scim_user FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_select ON identity.scim_token FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON identity.scim_token FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_select ON identity.scim_group FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_insert ON identity.scim_group FOR INSERT TO ipso_migrate
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON identity.scim_group FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_select ON identity.scim_membership FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_insert ON identity.scim_membership FOR INSERT TO ipso_migrate
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON identity.scim_membership FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_select ON identity.idp_group_role FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_insert ON identity.idp_group_role FOR INSERT TO ipso_migrate
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON identity.idp_group_role FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());

GRANT SELECT, INSERT, UPDATE (user_name, active) ON identity.scim_user TO ipso_app;
GRANT SELECT, INSERT, DELETE ON identity.scim_token TO ipso_app;
GRANT SELECT, INSERT, DELETE ON identity.scim_group TO ipso_app;
GRANT SELECT, INSERT, DELETE ON identity.scim_membership TO ipso_app;
GRANT SELECT, INSERT, DELETE ON identity.idp_group_role TO ipso_app;
