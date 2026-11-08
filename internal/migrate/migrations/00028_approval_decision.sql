-- +goose Up
-- An approval names the decision it wrote, and an agent proposal gets an approval table of its own
-- (IPSO-134, ADR-0109).
--
-- ADR-0076 says a decision version is written only through a recorded approval by a person, and
-- 00009 left the two unlinked: nothing said which decision an approval produced. decision_id is that
-- link. It is set exactly when the outcome is approved, so a rejection writes no decision and an
-- approval cannot omit it, and it is unique, so one decision comes from at most one approval. It has
-- no foreign key, because registry.decision_version is keyed by its valid period and not by the
-- decision alone. The route writes the approval and the version in one transaction.
--
-- No route wrote an approval before this file, so the table holds no row to backfill.
ALTER TABLE proposals.approval
    ADD COLUMN decision_id uuid,
    ADD CONSTRAINT approval_decision CHECK ((outcome = 'approved') = (decision_id IS NOT NULL)),
    ADD CONSTRAINT approval_decision_once UNIQUE (tenant_id, decision_id);

-- The approval of a proposal an agent made over MCP (ADR-0077). Same shape and same rules as
-- proposals.approval: one outcome per proposal, by a person, insert-only. The row in
-- proposals.agent_proposal stays pending, as its CHECK says it must.
CREATE TABLE proposals.agent_approval (
    tenant_id   uuid      NOT NULL,
    id          uuid      NOT NULL DEFAULT uuidv7(),
    proposal_id uuid      NOT NULL,
    approver_id uuid      NOT NULL,
    outcome     text      NOT NULL,
    decision_id uuid,
    sys_period  tstzrange NOT NULL DEFAULT tstzrange(clock_timestamp(), NULL),
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT agent_approval_once UNIQUE (tenant_id, proposal_id),
    CONSTRAINT agent_approval_decision_once UNIQUE (tenant_id, decision_id),
    CONSTRAINT agent_approval_proposal FOREIGN KEY (tenant_id, proposal_id)
        REFERENCES proposals.agent_proposal (tenant_id, id),
    CONSTRAINT agent_approval_approver_principal FOREIGN KEY (tenant_id, approver_id)
        REFERENCES identity.principal (tenant_id, id),
    CONSTRAINT agent_approval_outcome CHECK (outcome IN ('approved', 'rejected')),
    CONSTRAINT agent_approval_decision CHECK ((outcome = 'approved') = (decision_id IS NOT NULL)),
    CONSTRAINT agent_approval_sys_period_open CHECK (upper(sys_period) IS NULL)
);

CREATE TRIGGER agent_approval_approver
    BEFORE INSERT ON proposals.agent_approval
    FOR EACH ROW EXECUTE FUNCTION identity.require_human_approver();

CREATE TRIGGER agent_approval_open_sys_period
    BEFORE INSERT ON proposals.agent_approval
    FOR EACH ROW EXECUTE FUNCTION registry.open_sys_period();

ALTER TABLE proposals.agent_approval ENABLE ROW LEVEL SECURITY;
ALTER TABLE proposals.agent_approval FORCE ROW LEVEL SECURITY;

CREATE POLICY app_select ON proposals.agent_approval
    FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON proposals.agent_approval
    FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());

-- Export, restore and offboard (ADR-0100) treat the table like every other tenant table.
CREATE POLICY migrate_select ON proposals.agent_approval
    FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON proposals.agent_approval
    FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_insert ON proposals.agent_approval
    FOR INSERT TO ipso_migrate
    WITH CHECK (tenant_id = ipso.current_tenant());

GRANT SELECT, INSERT ON proposals.agent_approval TO ipso_app;
