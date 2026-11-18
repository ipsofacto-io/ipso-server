-- +goose Up
-- Decision owner teams, ADR-0132. A group push writes these rows. It does not grant a role, and it
-- does not change the owner named in a decision file.
--
-- identity.idp_group_owner maps the group ref ADR-0131 already stores to one owner team. One group
-- may map to several teams. identity.principal_owner is the membership. source is hand or idp, and
-- hand is the default. The unique key does not include source, so an IdP row is not inserted when
-- any row already has that person and team. A group push deletes and inserts only source idp.
-- The trigger refuses an agent, because a CHECK cannot see the principal row. It is not SECURITY
-- DEFINER: it reads identity.principal as the caller, under the same policies as every other read.

CREATE TABLE identity.idp_group_owner (
    tenant_id uuid NOT NULL,
    id        uuid NOT NULL DEFAULT uuidv7(),
    group_ref text NOT NULL,
    owner_ref text NOT NULL,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT idp_group_owner_once UNIQUE (tenant_id, group_ref, owner_ref),
    CONSTRAINT idp_group_owner_ref CHECK (
        char_length(group_ref) BETWEEN 1 AND 200
        AND btrim(group_ref) = group_ref
        AND group_ref !~ '[[:cntrl:]]'),
    CONSTRAINT idp_group_owner_team CHECK (
        owner_ref ~ '^team:[a-z][a-z0-9]*(-[a-z0-9]+)*$'
        AND char_length(owner_ref) <= 200)
);

CREATE TABLE identity.principal_owner (
    tenant_id    uuid      NOT NULL,
    id           uuid      NOT NULL DEFAULT uuidv7(),
    principal_id uuid      NOT NULL,
    owner_ref    text      NOT NULL,
    source       text      NOT NULL DEFAULT 'hand',
    sys_period   tstzrange NOT NULL DEFAULT tstzrange(clock_timestamp(), NULL),
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT principal_owner_once UNIQUE (tenant_id, principal_id, owner_ref),
    CONSTRAINT principal_owner_principal FOREIGN KEY (tenant_id, principal_id)
        REFERENCES identity.principal (tenant_id, id),
    CONSTRAINT principal_owner_source CHECK (source IN ('hand', 'idp')),
    CONSTRAINT principal_owner_team CHECK (
        owner_ref ~ '^team:[a-z][a-z0-9]*(-[a-z0-9]+)*$'
        AND char_length(owner_ref) <= 200),
    CONSTRAINT principal_owner_sys_period_open CHECK (upper(sys_period) IS NULL)
);

-- +goose StatementBegin
CREATE FUNCTION identity.principal_owner_check() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM identity.principal p
        WHERE p.tenant_id = NEW.tenant_id
          AND p.id = NEW.principal_id
          AND p.kind = 'human'
    ) THEN
        RAISE EXCEPTION 'an owner team belongs to a person'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION identity.principal_owner_check() FROM PUBLIC;

CREATE TRIGGER principal_owner_check
    BEFORE INSERT ON identity.principal_owner
    FOR EACH ROW EXECUTE FUNCTION identity.principal_owner_check();

CREATE TRIGGER principal_owner_open_sys_period
    BEFORE INSERT ON identity.principal_owner
    FOR EACH ROW EXECUTE FUNCTION registry.open_sys_period();

ALTER TABLE identity.idp_group_owner ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.idp_group_owner FORCE ROW LEVEL SECURITY;
ALTER TABLE identity.principal_owner ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.principal_owner FORCE ROW LEVEL SECURITY;

CREATE POLICY app_select ON identity.idp_group_owner FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON identity.idp_group_owner FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY app_delete ON identity.idp_group_owner FOR DELETE TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_select ON identity.principal_owner FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON identity.principal_owner FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY app_delete ON identity.principal_owner FOR DELETE TO ipso_app
    USING (tenant_id = ipso.current_tenant());

CREATE POLICY migrate_select ON identity.idp_group_owner FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_insert ON identity.idp_group_owner FOR INSERT TO ipso_migrate
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON identity.idp_group_owner FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_select ON identity.principal_owner FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_insert ON identity.principal_owner FOR INSERT TO ipso_migrate
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON identity.principal_owner FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());

GRANT SELECT, INSERT, DELETE ON identity.idp_group_owner TO ipso_app;
GRANT SELECT, INSERT, DELETE ON identity.principal_owner TO ipso_app;
GRANT EXECUTE ON FUNCTION identity.principal_owner_check() TO ipso_app, ipso_migrate;
