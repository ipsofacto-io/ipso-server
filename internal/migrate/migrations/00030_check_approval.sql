-- +goose Up
-- The approval of a check an LLM drafted for a decision (IPSO-148, ADR-0116).
--
-- proposals.check_proposal is insert-only and pending-only (ADR-0086), so the answer of a person is a row of
-- its own, the way proposals.approval and proposals.agent_approval answer the other two queues (ADR-0109).
-- One outcome for one drafted check, by a person, insert-only. The row in proposals.check_proposal stays
-- pending, as its CHECK says it must, and a check with an approval leaves the review queue. The table writes
-- no decision: accepting a check changes what a bundle holds and not the registry.
CREATE TABLE proposals.check_approval (
    tenant_id   uuid      NOT NULL,
    id          uuid      NOT NULL DEFAULT uuidv7(),
    proposal_id uuid      NOT NULL,
    approver_id uuid      NOT NULL,
    outcome     text      NOT NULL,
    sys_period  tstzrange NOT NULL DEFAULT tstzrange(clock_timestamp(), NULL),
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT check_approval_once UNIQUE (tenant_id, proposal_id),
    CONSTRAINT check_approval_proposal FOREIGN KEY (tenant_id, proposal_id)
        REFERENCES proposals.check_proposal (tenant_id, id),
    CONSTRAINT check_approval_approver_principal FOREIGN KEY (tenant_id, approver_id)
        REFERENCES identity.principal (tenant_id, id),
    CONSTRAINT check_approval_outcome CHECK (outcome IN ('approved', 'rejected')),
    CONSTRAINT check_approval_sys_period_open CHECK (upper(sys_period) IS NULL)
);

CREATE TRIGGER check_approval_approver
    BEFORE INSERT ON proposals.check_approval
    FOR EACH ROW EXECUTE FUNCTION identity.require_human_approver();

CREATE TRIGGER check_approval_open_sys_period
    BEFORE INSERT ON proposals.check_approval
    FOR EACH ROW EXECUTE FUNCTION registry.open_sys_period();

ALTER TABLE proposals.check_approval ENABLE ROW LEVEL SECURITY;
ALTER TABLE proposals.check_approval FORCE ROW LEVEL SECURITY;

CREATE POLICY app_select ON proposals.check_approval
    FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON proposals.check_approval
    FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());

-- Export, restore and offboard (ADR-0100) treat the table like every other tenant table.
CREATE POLICY migrate_select ON proposals.check_approval
    FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON proposals.check_approval
    FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_insert ON proposals.check_approval
    FOR INSERT TO ipso_migrate
    WITH CHECK (tenant_id = ipso.current_tenant());

GRANT SELECT, INSERT ON proposals.check_approval TO ipso_app;
