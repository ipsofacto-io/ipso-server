-- +goose Up
-- Which tenant owns a GitHub App installation, and the one lookup that crosses tenants (IPSO-140,
-- ADR-0101).
--
-- tenancy.installation maps an installation id to its tenant. The id is the primary key of the whole
-- table and not of a tenant, so an installation belongs to one tenant and a second binding fails with a
-- unique violation. A tenant may hold several installations. Nothing here is a property of the
-- payload of a delivery: the id comes from a signed webhook or a verified CI token, and the tenant comes
-- from this table.
--
-- The table has a tenant_id column and the policies of every tenant table, so rls.Check, the isolation
-- suite, the export catalog and the offboard purge cover it with no special case. The application role
-- can read and insert its own tenant's bindings and cannot update or delete one. Only offboarding
-- removes a binding today.
--
-- A webhook delivery names an installation and no tenant, so the process that receives it has none to set.
-- tenancy.installation_tenant answers that one question: the tenant of the installation it is given, or
-- no row. It is SECURITY DEFINER and owned by ipso_migrate, and FORCE ROW LEVEL SECURITY binds the owner
-- too, so the migration role's SELECT policy decides what it sees: the rows of the tenant in ipso.tenant,
-- and every row when no tenant is set. A caller with a tenant set learns nothing about another tenant's
-- installations, and a caller with none gets the tenant of one installation id it names and cannot list
-- them. The restore and offboard commands always set a tenant, so for them the policy is the same as on
-- every other table.

CREATE TABLE tenancy.installation (
    installation_id bigint    NOT NULL,
    tenant_id       uuid      NOT NULL,
    sys_period      tstzrange NOT NULL DEFAULT tstzrange(clock_timestamp(), NULL),
    PRIMARY KEY (installation_id),
    CONSTRAINT installation_tenant FOREIGN KEY (tenant_id)
        REFERENCES tenancy.tenant (tenant_id),
    CONSTRAINT installation_id_positive CHECK (installation_id > 0),
    CONSTRAINT installation_sys_period_open CHECK (upper(sys_period) IS NULL)
);

CREATE TRIGGER installation_open_sys_period
    BEFORE INSERT ON tenancy.installation
    FOR EACH ROW EXECUTE FUNCTION registry.open_sys_period();

ALTER TABLE tenancy.installation ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenancy.installation FORCE ROW LEVEL SECURITY;

CREATE POLICY app_select ON tenancy.installation
    FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON tenancy.installation
    FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());

-- One SELECT policy for the migration role. The second arm is what lets the lookup function below read
-- a binding in a session that has no tenant. The delete policy has no such arm.
CREATE POLICY migrate_select ON tenancy.installation
    FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant() OR ipso.current_tenant() IS NULL);
CREATE POLICY migrate_delete ON tenancy.installation
    FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());

GRANT SELECT, INSERT ON tenancy.installation TO ipso_app;

-- +goose StatementBegin
CREATE FUNCTION tenancy.installation_tenant(p_installation_id bigint) RETURNS uuid
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
AS $$
    SELECT i.tenant_id FROM tenancy.installation AS i WHERE i.installation_id = p_installation_id
$$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION tenancy.installation_tenant(bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION tenancy.installation_tenant(bigint) TO ipso_app;
