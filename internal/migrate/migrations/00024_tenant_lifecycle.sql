-- +goose Up
-- Tenant lifecycle: the wrapped key of a tenant, the record that outlives an offboarded tenant, and
-- the policies that let the migration role export-restore and purge a tenant (IPSO-63, ADR-0100).
--
-- tenancy.tenant_key holds the data key of one tenant, wrapped with AES-256-GCM under the key
-- encryption key of the deployment. The application role can write it once and read it back, and the
-- key encryption key never reaches the database. Deleting the row is the shred.
--
-- tenancy.offboarding is the tombstone. It has no foreign key to tenancy.tenant, because the tenant is
-- gone, and it holds ids and counts only. The application role reads it, so a provisioning run can
-- refuse an id that was offboarded. Nothing deletes it.
--
-- ipso_migrate gets SELECT and DELETE on every tenant table, and INSERT on every table a restore
-- writes. The expression is the same one, so FORCE ROW LEVEL SECURITY still binds every row that role
-- touches. The restore and offboard commands set session_replication_role to replica for their own
-- transaction, which skips triggers and the triggers behind foreign keys. Only a superuser sets that
-- parameter, so the administrator who prepares the database also runs
--     GRANT SET ON PARAMETER session_replication_role TO ipso_migrate;
-- (PostgreSQL 15 or later). The role owns every table and could already disable a trigger or drop a
-- table, so the grant adds no power over the schema. ipso_app does not get it.

CREATE TABLE tenancy.tenant_key (
    tenant_id   uuid      NOT NULL,
    wrapped_dek bytea     NOT NULL,
    sys_period  tstzrange NOT NULL DEFAULT tstzrange(clock_timestamp(), NULL),
    PRIMARY KEY (tenant_id),
    CONSTRAINT tenant_key_tenant FOREIGN KEY (tenant_id)
        REFERENCES tenancy.tenant (tenant_id),
    -- A 12 byte nonce, the 32 byte key, and the 16 byte GCM tag.
    CONSTRAINT tenant_key_wrapped CHECK (octet_length(wrapped_dek) = 60),
    CONSTRAINT tenant_key_sys_period_open CHECK (upper(sys_period) IS NULL)
);

CREATE TRIGGER tenant_key_open_sys_period
    BEFORE INSERT ON tenancy.tenant_key
    FOR EACH ROW EXECUTE FUNCTION registry.open_sys_period();

CREATE TABLE tenancy.offboarding (
    tenant_id     uuid      NOT NULL,
    deleted_rows  bigint    NOT NULL,
    deleted_jobs  bigint    NOT NULL,
    key_destroyed boolean   NOT NULL,
    sys_period    tstzrange NOT NULL DEFAULT tstzrange(clock_timestamp(), NULL),
    PRIMARY KEY (tenant_id),
    CONSTRAINT offboarding_counts CHECK (deleted_rows >= 0 AND deleted_jobs >= 0),
    CONSTRAINT offboarding_sys_period_open CHECK (upper(sys_period) IS NULL)
);

CREATE TRIGGER offboarding_open_sys_period
    BEFORE INSERT ON tenancy.offboarding
    FOR EACH ROW EXECUTE FUNCTION registry.open_sys_period();

ALTER TABLE tenancy.tenant_key ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenancy.tenant_key FORCE ROW LEVEL SECURITY;
ALTER TABLE tenancy.offboarding ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenancy.offboarding FORCE ROW LEVEL SECURITY;

CREATE POLICY app_select ON tenancy.tenant_key
    FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON tenancy.tenant_key
    FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY app_select ON tenancy.offboarding
    FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());

GRANT SELECT, INSERT ON tenancy.tenant_key TO ipso_app;
GRANT SELECT ON tenancy.offboarding TO ipso_app;

CREATE POLICY migrate_select ON identity.action_log
    FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON identity.action_log
    FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_insert ON identity.action_log
    FOR INSERT TO ipso_migrate
    WITH CHECK (tenant_id = ipso.current_tenant());

CREATE POLICY migrate_select ON identity.login
    FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON identity.login
    FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_insert ON identity.login
    FOR INSERT TO ipso_migrate
    WITH CHECK (tenant_id = ipso.current_tenant());

CREATE POLICY migrate_select ON identity.principal
    FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON identity.principal
    FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_insert ON identity.principal
    FOR INSERT TO ipso_migrate
    WITH CHECK (tenant_id = ipso.current_tenant());

CREATE POLICY migrate_select ON identity.session
    FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON identity.session
    FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());

CREATE POLICY migrate_select ON llm.usage
    FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON llm.usage
    FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_insert ON llm.usage
    FOR INSERT TO ipso_migrate
    WITH CHECK (tenant_id = ipso.current_tenant());

CREATE POLICY migrate_select ON proposals.agent_proposal
    FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON proposals.agent_proposal
    FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_insert ON proposals.agent_proposal
    FOR INSERT TO ipso_migrate
    WITH CHECK (tenant_id = ipso.current_tenant());

CREATE POLICY migrate_select ON proposals.approval
    FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON proposals.approval
    FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_insert ON proposals.approval
    FOR INSERT TO ipso_migrate
    WITH CHECK (tenant_id = ipso.current_tenant());

CREATE POLICY migrate_select ON proposals.check_proposal
    FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON proposals.check_proposal
    FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_insert ON proposals.check_proposal
    FOR INSERT TO ipso_migrate
    WITH CHECK (tenant_id = ipso.current_tenant());

CREATE POLICY migrate_select ON proposals.proposal
    FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON proposals.proposal
    FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_insert ON proposals.proposal
    FOR INSERT TO ipso_migrate
    WITH CHECK (tenant_id = ipso.current_tenant());

CREATE POLICY migrate_select ON registry.baseline
    FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON registry.baseline
    FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_insert ON registry.baseline
    FOR INSERT TO ipso_migrate
    WITH CHECK (tenant_id = ipso.current_tenant());

CREATE POLICY migrate_select ON registry.decision_version
    FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON registry.decision_version
    FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_insert ON registry.decision_version
    FOR INSERT TO ipso_migrate
    WITH CHECK (tenant_id = ipso.current_tenant());

CREATE POLICY migrate_select ON registry.decision_version_history
    FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON registry.decision_version_history
    FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());

CREATE POLICY migrate_select ON registry.grandfather_period
    FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON registry.grandfather_period
    FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_insert ON registry.grandfather_period
    FOR INSERT TO ipso_migrate
    WITH CHECK (tenant_id = ipso.current_tenant());

CREATE POLICY migrate_select ON registry.premise_clearance
    FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON registry.premise_clearance
    FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_insert ON registry.premise_clearance
    FOR INSERT TO ipso_migrate
    WITH CHECK (tenant_id = ipso.current_tenant());

CREATE POLICY migrate_select ON registry.premise_evaluation
    FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON registry.premise_evaluation
    FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_insert ON registry.premise_evaluation
    FOR INSERT TO ipso_migrate
    WITH CHECK (tenant_id = ipso.current_tenant());

CREATE POLICY migrate_select ON registry.premise_host_allow
    FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON registry.premise_host_allow
    FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_insert ON registry.premise_host_allow
    FOR INSERT TO ipso_migrate
    WITH CHECK (tenant_id = ipso.current_tenant());

CREATE POLICY migrate_select ON registry.premise_reason
    FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON registry.premise_reason
    FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_insert ON registry.premise_reason
    FOR INSERT TO ipso_migrate
    WITH CHECK (tenant_id = ipso.current_tenant());

CREATE POLICY migrate_delete ON registry.scope
    FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_insert ON registry.scope
    FOR INSERT TO ipso_migrate
    WITH CHECK (tenant_id = ipso.current_tenant());

CREATE POLICY migrate_select ON registry.scope_closure_history
    FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON registry.scope_closure_history
    FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());

CREATE POLICY migrate_select ON registry.scope_history
    FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON registry.scope_history
    FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());

CREATE POLICY migrate_select ON registry.supersession
    FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON registry.supersession
    FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_insert ON registry.supersession
    FOR INSERT TO ipso_migrate
    WITH CHECK (tenant_id = ipso.current_tenant());

CREATE POLICY migrate_select ON registry.waiver
    FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON registry.waiver
    FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_insert ON registry.waiver
    FOR INSERT TO ipso_migrate
    WITH CHECK (tenant_id = ipso.current_tenant());

CREATE POLICY migrate_select ON registry.waiver_notice
    FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON registry.waiver_notice
    FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_insert ON registry.waiver_notice
    FOR INSERT TO ipso_migrate
    WITH CHECK (tenant_id = ipso.current_tenant());

CREATE POLICY migrate_select ON tenancy.offboarding
    FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_insert ON tenancy.offboarding
    FOR INSERT TO ipso_migrate
    WITH CHECK (tenant_id = ipso.current_tenant());

CREATE POLICY migrate_select ON tenancy.tenant
    FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON tenancy.tenant
    FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());

CREATE POLICY migrate_select ON tenancy.tenant_key
    FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON tenancy.tenant_key
    FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());

