-- +goose Up
-- Agent-edit checks an LLM drafted for a decision in force, section 4.4 of the specification and
-- ADR-0086. The model answers with a rule as data and the server writes the Rego. A row exists
-- only for a rule that compiled and passed every fixture a person wrote, and it waits for a
-- person (ADR-0005). The review path that accepts one ships with IPSO-60. Row-level security
-- ships with IPSO-61, and the table carries tenant_id, so the criteria already on that issue
-- cover it. decision_id and decision_version name the decision without a foreign key, because
-- registry.decision_version is keyed by its valid period.
CREATE TABLE proposals.check_proposal (
    tenant_id        uuid      NOT NULL,
    id               uuid      NOT NULL DEFAULT uuidv7(),
    status           text      NOT NULL DEFAULT 'pending',
    decision_id      uuid      NOT NULL,
    decision_version integer   NOT NULL,
    engine           text      NOT NULL DEFAULT 'opa',
    target           text      NOT NULL DEFAULT 'agent-edit',
    spec             jsonb     NOT NULL,
    rego             text      NOT NULL,
    rego_sha256      bytea     NOT NULL,
    fixtures         jsonb     NOT NULL,
    fixtures_total   integer   NOT NULL,
    fixtures_passed  integer   NOT NULL,
    repaired         boolean   NOT NULL,
    model_id         text      NOT NULL,
    prompt_version   text      NOT NULL,
    sys_period       tstzrange NOT NULL DEFAULT tstzrange(clock_timestamp(), NULL),
    PRIMARY KEY (tenant_id, id),
    -- Drafting the same rule again for the same decision version adds nothing.
    CONSTRAINT check_proposal_once UNIQUE (tenant_id, decision_id, decision_version, rego_sha256),
    CONSTRAINT check_proposal_status CHECK (status = 'pending'),
    CONSTRAINT check_proposal_engine CHECK (engine = 'opa'),
    CONSTRAINT check_proposal_target CHECK (target = 'agent-edit'),
    CONSTRAINT check_proposal_decision_version CHECK (decision_version > 0),
    CONSTRAINT check_proposal_spec CHECK (
        jsonb_typeof(spec) = 'object' AND octet_length(spec::text) <= 65536),
    CONSTRAINT check_proposal_rego CHECK (char_length(rego) BETWEEN 1 AND 65536),
    CONSTRAINT check_proposal_rego_sha256 CHECK (
        octet_length(rego_sha256) = 32 AND rego_sha256 = sha256(convert_to(rego, 'UTF8'))),
    -- A rule that fails a fixture never reaches review.
    CONSTRAINT check_proposal_fixtures CHECK (
        jsonb_typeof(fixtures) = 'array'
        AND jsonb_array_length(fixtures) = fixtures_total
        AND octet_length(fixtures::text) <= 2097152),
    CONSTRAINT check_proposal_fixtures_pass CHECK (
        fixtures_total BETWEEN 2 AND 50 AND fixtures_passed = fixtures_total),
    CONSTRAINT check_proposal_model_id CHECK (char_length(model_id) BETWEEN 1 AND 200),
    CONSTRAINT check_proposal_prompt_version CHECK (char_length(prompt_version) BETWEEN 1 AND 100),
    CONSTRAINT check_proposal_sys_period_open CHECK (upper(sys_period) IS NULL)
);

CREATE INDEX check_proposal_inbox ON proposals.check_proposal (tenant_id, id DESC);

CREATE TRIGGER check_proposal_open_sys_period
    BEFORE INSERT ON proposals.check_proposal
    FOR EACH ROW EXECUTE FUNCTION registry.open_sys_period();

GRANT SELECT, INSERT ON proposals.check_proposal TO ipso_app;
