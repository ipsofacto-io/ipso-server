-- +goose Up
-- Role bindings, ADR-0108. A binding gives a principal one of the seven roles of section 13.2, for the
-- whole tenant or for one scope and every scope below it. The role policy in internal/authz reads
-- them on every request, so removing a row takes effect on the next call.
--
-- Only the roles whose actions name a scope may be bound to one: a scope on a viewer, an auditor or an
-- admin would promise a narrowing the policy does not enforce, because reads and administration are
-- tenant-wide. An agent holds only the agent role and a person never holds it (ADR-0076), and the
-- trigger checks the kind because a CHECK cannot see the principal row. The trigger is not SECURITY
-- DEFINER: it reads identity.principal as the application role, under the same policies as every other
-- read.
--
-- Both foreign keys carry the tenant, so a binding cannot name a principal or a scope of another
-- tenant. The foreign key to the scope also refuses to retire a scope that is still bound, so a
-- binding never outlives the node it narrows to. The application role may select, insert and delete
-- a binding and never update one: an operator revokes a binding by deleting it.
CREATE TABLE identity.role_binding (
    tenant_id    uuid      NOT NULL,
    id           uuid      NOT NULL DEFAULT uuidv7(),
    principal_id uuid      NOT NULL,
    role         text      NOT NULL,
    scope_id     uuid,
    sys_period   tstzrange NOT NULL DEFAULT tstzrange(clock_timestamp(), NULL),
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT role_binding_once UNIQUE NULLS NOT DISTINCT (tenant_id, principal_id, role, scope_id),
    CONSTRAINT role_binding_principal FOREIGN KEY (tenant_id, principal_id)
        REFERENCES identity.principal (tenant_id, id),
    CONSTRAINT role_binding_scope FOREIGN KEY (tenant_id, scope_id)
        REFERENCES registry.scope (tenant_id, id),
    CONSTRAINT role_binding_role CHECK (role IN (
        'viewer', 'contributor', 'decision-owner', 'approver', 'admin', 'auditor', 'agent')),
    CONSTRAINT role_binding_scoped_role CHECK (
        scope_id IS NULL OR role IN ('contributor', 'decision-owner', 'approver', 'agent')),
    CONSTRAINT role_binding_sys_period_open CHECK (upper(sys_period) IS NULL)
);

CREATE INDEX role_binding_by_scope ON identity.role_binding (tenant_id, scope_id);

-- +goose StatementBegin
CREATE FUNCTION identity.role_binding_check() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM identity.principal p
        WHERE p.tenant_id = NEW.tenant_id
          AND p.id = NEW.principal_id
          AND (p.kind = 'agent') = (NEW.role = 'agent')
    ) THEN
        RAISE EXCEPTION 'an agent holds only the agent role, and a person never holds it'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER role_binding_check
    BEFORE INSERT ON identity.role_binding
    FOR EACH ROW EXECUTE FUNCTION identity.role_binding_check();

CREATE TRIGGER role_binding_open_sys_period
    BEFORE INSERT ON identity.role_binding
    FOR EACH ROW EXECUTE FUNCTION registry.open_sys_period();

ALTER TABLE identity.role_binding ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.role_binding FORCE ROW LEVEL SECURITY;

CREATE POLICY app_select ON identity.role_binding
    FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON identity.role_binding
    FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY app_delete ON identity.role_binding
    FOR DELETE TO ipso_app
    USING (tenant_id = ipso.current_tenant());

-- Export, restore and offboard (ADR-0100) treat bindings like logins: they belong to the tenant.
CREATE POLICY migrate_select ON identity.role_binding
    FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON identity.role_binding
    FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_insert ON identity.role_binding
    FOR INSERT TO ipso_migrate
    WITH CHECK (tenant_id = ipso.current_tenant());

GRANT SELECT, INSERT, DELETE ON identity.role_binding TO ipso_app;
