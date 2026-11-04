-- +goose Up
-- Tenant isolation for every table that carries tenant_id, section 10 of the specification
-- and ADR-0050. The application role sees and writes a row only when ipso.tenant is that
-- row's tenant. A missing setting and the empty string left after a transaction-local
-- setting both match no row.
--
-- FORCE ROW LEVEL SECURITY applies to the owner of a SECURITY DEFINER function too.
-- The archive and closure triggers run as ipso_migrate, so that role has the policies
-- those functions need: INSERT on the history tables, and SELECT, INSERT, and DELETE on
-- scope_closure. scope_version reads registry.scope, and scope_rewrite_closure updates
-- descendant rows, both as ipso_migrate, so that role also has SELECT and UPDATE on
-- registry.scope. The expression is the same one.
--
-- Policies match the grants already given. The owner bypasses row-level security until
-- FORCE is set, and this file writes no tenant row.
--
-- current_setting is not leakproof. An inline policy stops the planner from using the
-- scope_refs index, so a decisions read would scan every row. Only a superuser can mark
-- a function leakproof, and ipso_migrate is not one, so the install creates
-- ipso.current_tenant() before the first migrate. Its body is
-- nullif(current_setting('ipso.tenant', true), '')::uuid. The policies call it.
-- The history table has no btree on tenant_id. Under row-level security the scope_refs
-- index is not a legal access path, and without this index the history read is a
-- sequential scan of every tenant.

CREATE INDEX decision_version_history_tenant
    ON registry.decision_version_history (tenant_id);

-- +goose StatementBegin
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.pg_proc AS p
        JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace
        WHERE n.nspname = 'ipso'
          AND p.proname = 'current_tenant'
          AND p.proleakproof
          AND p.provolatile = 's'
    ) THEN
        RAISE EXCEPTION 'ipso.current_tenant() must exist, be stable, and be leakproof before this migration';
    END IF;
END $$;
-- +goose StatementEnd

ALTER TABLE registry.decision_version ENABLE ROW LEVEL SECURITY;
ALTER TABLE registry.decision_version FORCE ROW LEVEL SECURITY;
ALTER TABLE registry.decision_version_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE registry.decision_version_history FORCE ROW LEVEL SECURITY;
ALTER TABLE registry.scope ENABLE ROW LEVEL SECURITY;
ALTER TABLE registry.scope FORCE ROW LEVEL SECURITY;
ALTER TABLE registry.scope_closure ENABLE ROW LEVEL SECURITY;
ALTER TABLE registry.scope_closure FORCE ROW LEVEL SECURITY;
ALTER TABLE registry.scope_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE registry.scope_history FORCE ROW LEVEL SECURITY;
ALTER TABLE registry.scope_closure_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE registry.scope_closure_history FORCE ROW LEVEL SECURITY;
ALTER TABLE registry.supersession ENABLE ROW LEVEL SECURITY;
ALTER TABLE registry.supersession FORCE ROW LEVEL SECURITY;
ALTER TABLE registry.grandfather_period ENABLE ROW LEVEL SECURITY;
ALTER TABLE registry.grandfather_period FORCE ROW LEVEL SECURITY;
ALTER TABLE registry.baseline ENABLE ROW LEVEL SECURITY;
ALTER TABLE registry.baseline FORCE ROW LEVEL SECURITY;
ALTER TABLE registry.waiver ENABLE ROW LEVEL SECURITY;
ALTER TABLE registry.waiver FORCE ROW LEVEL SECURITY;
ALTER TABLE registry.waiver_notice ENABLE ROW LEVEL SECURITY;
ALTER TABLE registry.waiver_notice FORCE ROW LEVEL SECURITY;
ALTER TABLE registry.premise_evaluation ENABLE ROW LEVEL SECURITY;
ALTER TABLE registry.premise_evaluation FORCE ROW LEVEL SECURITY;
ALTER TABLE registry.premise_reason ENABLE ROW LEVEL SECURITY;
ALTER TABLE registry.premise_reason FORCE ROW LEVEL SECURITY;
ALTER TABLE registry.premise_clearance ENABLE ROW LEVEL SECURITY;
ALTER TABLE registry.premise_clearance FORCE ROW LEVEL SECURITY;
ALTER TABLE registry.premise_host_allow ENABLE ROW LEVEL SECURITY;
ALTER TABLE registry.premise_host_allow FORCE ROW LEVEL SECURITY;
ALTER TABLE proposals.proposal ENABLE ROW LEVEL SECURITY;
ALTER TABLE proposals.proposal FORCE ROW LEVEL SECURITY;
ALTER TABLE proposals.agent_proposal ENABLE ROW LEVEL SECURITY;
ALTER TABLE proposals.agent_proposal FORCE ROW LEVEL SECURITY;
ALTER TABLE proposals.approval ENABLE ROW LEVEL SECURITY;
ALTER TABLE proposals.approval FORCE ROW LEVEL SECURITY;
ALTER TABLE proposals.check_proposal ENABLE ROW LEVEL SECURITY;
ALTER TABLE proposals.check_proposal FORCE ROW LEVEL SECURITY;
ALTER TABLE identity.principal ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.principal FORCE ROW LEVEL SECURITY;
ALTER TABLE identity.action_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.action_log FORCE ROW LEVEL SECURITY;
ALTER TABLE llm.usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE llm.usage FORCE ROW LEVEL SECURITY;

CREATE POLICY app_select ON registry.decision_version
    FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON registry.decision_version
    FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY app_update ON registry.decision_version
    FOR UPDATE TO ipso_app
    USING (tenant_id = ipso.current_tenant())
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY app_delete ON registry.decision_version
    FOR DELETE TO ipso_app
    USING (tenant_id = ipso.current_tenant());

CREATE POLICY app_select ON registry.decision_version_history
    FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_insert ON registry.decision_version_history
    FOR INSERT TO ipso_migrate
    WITH CHECK (tenant_id = ipso.current_tenant());

CREATE POLICY app_select ON registry.scope
    FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON registry.scope
    FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY app_update ON registry.scope
    FOR UPDATE TO ipso_app
    USING (tenant_id = ipso.current_tenant())
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY app_delete ON registry.scope
    FOR DELETE TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_select ON registry.scope
    FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_update ON registry.scope
    FOR UPDATE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant())
    WITH CHECK (tenant_id = ipso.current_tenant());

CREATE POLICY app_select ON registry.scope_closure
    FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_select ON registry.scope_closure
    FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_insert ON registry.scope_closure
    FOR INSERT TO ipso_migrate
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON registry.scope_closure
    FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());

CREATE POLICY app_select ON registry.scope_history
    FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_insert ON registry.scope_history
    FOR INSERT TO ipso_migrate
    WITH CHECK (tenant_id = ipso.current_tenant());

CREATE POLICY app_select ON registry.scope_closure_history
    FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_insert ON registry.scope_closure_history
    FOR INSERT TO ipso_migrate
    WITH CHECK (tenant_id = ipso.current_tenant());

CREATE POLICY app_select ON registry.supersession
    FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON registry.supersession
    FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());

CREATE POLICY app_select ON registry.grandfather_period
    FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON registry.grandfather_period
    FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());

CREATE POLICY app_select ON registry.baseline
    FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON registry.baseline
    FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());

CREATE POLICY app_select ON registry.waiver
    FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON registry.waiver
    FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());

CREATE POLICY app_select ON registry.waiver_notice
    FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON registry.waiver_notice
    FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());

CREATE POLICY app_select ON registry.premise_evaluation
    FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON registry.premise_evaluation
    FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());

CREATE POLICY app_select ON registry.premise_reason
    FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON registry.premise_reason
    FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());

CREATE POLICY app_select ON registry.premise_clearance
    FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON registry.premise_clearance
    FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());

CREATE POLICY app_select ON registry.premise_host_allow
    FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON registry.premise_host_allow
    FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());

CREATE POLICY app_select ON proposals.proposal
    FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON proposals.proposal
    FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());

CREATE POLICY app_select ON proposals.agent_proposal
    FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON proposals.agent_proposal
    FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());

CREATE POLICY app_select ON proposals.approval
    FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON proposals.approval
    FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());

CREATE POLICY app_select ON proposals.check_proposal
    FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON proposals.check_proposal
    FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());

CREATE POLICY app_select ON identity.principal
    FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON identity.principal
    FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());

CREATE POLICY app_select ON identity.action_log
    FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON identity.action_log
    FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());

CREATE POLICY app_select ON llm.usage
    FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON llm.usage
    FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY app_update ON llm.usage
    FOR UPDATE TO ipso_app
    USING (tenant_id = ipso.current_tenant())
    WITH CHECK (tenant_id = ipso.current_tenant());
