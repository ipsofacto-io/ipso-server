-- +goose Up
-- Decisions an AI coding agent proposes over MCP, section 3.5 of the specification and ADR-0077.
-- proposals.proposal describes LLM extraction from a pull request, and its constraints require a
-- pull request, so these rows have their own table. They wait for a person (ADR-0005). The review
-- path that reads them ships with IPSO-60. Row-level security ships with IPSO-61, and the table
-- carries tenant_id, so the criteria already on that issue cover it.
CREATE TABLE proposals.agent_proposal (
    tenant_id    uuid      NOT NULL,
    id           uuid      NOT NULL DEFAULT uuidv7(),
    principal_id uuid      NOT NULL,
    status       text      NOT NULL DEFAULT 'pending',
    payload      jsonb     NOT NULL,
    sys_period   tstzrange NOT NULL DEFAULT tstzrange(clock_timestamp(), NULL),
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT agent_proposal_principal FOREIGN KEY (tenant_id, principal_id)
        REFERENCES identity.principal (tenant_id, id),
    CONSTRAINT agent_proposal_status CHECK (status = 'pending'),
    CONSTRAINT agent_proposal_payload CHECK (
        jsonb_typeof(payload) = 'object' AND octet_length(payload::text) <= 65536),
    CONSTRAINT agent_proposal_sys_period_open CHECK (upper(sys_period) IS NULL)
);

CREATE INDEX agent_proposal_inbox ON proposals.agent_proposal (tenant_id, id DESC);

CREATE TRIGGER agent_proposal_open_sys_period
    BEFORE INSERT ON proposals.agent_proposal
    FOR EACH ROW EXECUTE FUNCTION registry.open_sys_period();

GRANT SELECT, INSERT ON proposals.agent_proposal TO ipso_app;
