-- +goose Up
-- Decision proposals from pull request discussion, section 2.1 of the specification and
-- ADR-0062. A proposal is an LLM output and untrusted, and every one waits for a person
-- (ADR-0005). Row-level security ships with IPSO-61. The table carries tenant_id, so the
-- criteria already on that issue cover it.
CREATE SCHEMA proposals;

-- Insert-only. status accepts only pending, and ipso_app holds no UPDATE, so nothing in this
-- schema can approve a proposal. The review path adds the approval table and role policy of
-- section 2.1 with IPSO-60 and IPSO-66, in a later migration.
-- The comment text is not stored. source_url and source_sha256 name what was read.
CREATE TABLE proposals.proposal (
    tenant_id       uuid      NOT NULL,
    id              uuid      NOT NULL DEFAULT uuidv7(),
    kind            text      NOT NULL DEFAULT 'decision',
    origin          text      NOT NULL DEFAULT 'llm',
    status          text      NOT NULL DEFAULT 'pending',
    payload         jsonb     NOT NULL,
    confidence      numeric(3, 2) NOT NULL,
    model_id        text      NOT NULL,
    prompt_version  text      NOT NULL,
    connector       text      NOT NULL DEFAULT 'github',
    trust_level     text      NOT NULL DEFAULT 'untrusted',
    repo            text      NOT NULL,
    pr_number       integer   NOT NULL,
    external_id     text      NOT NULL,
    source_url      text      NOT NULL,
    source_sha256   bytea     NOT NULL,
    candidate_index integer   NOT NULL,
    sys_period      tstzrange NOT NULL DEFAULT tstzrange(clock_timestamp(), NULL),
    PRIMARY KEY (tenant_id, id),
    -- A redelivered webhook cannot add the same candidate twice.
    CONSTRAINT proposal_once UNIQUE (tenant_id, connector, repo, pr_number, external_id, source_sha256, candidate_index),
    CONSTRAINT proposal_kind CHECK (kind = 'decision'),
    CONSTRAINT proposal_origin CHECK (origin = 'llm'),
    CONSTRAINT proposal_status CHECK (status = 'pending'),
    CONSTRAINT proposal_connector CHECK (connector = 'github'),
    CONSTRAINT proposal_trust_level CHECK (trust_level = 'untrusted'),
    CONSTRAINT proposal_payload CHECK (
        jsonb_typeof(payload) = 'object' AND octet_length(payload::text) <= 8192),
    CONSTRAINT proposal_confidence CHECK (confidence BETWEEN 0 AND 1),
    CONSTRAINT proposal_model_id CHECK (char_length(model_id) BETWEEN 1 AND 200),
    CONSTRAINT proposal_prompt_version CHECK (char_length(prompt_version) BETWEEN 1 AND 100),
    CONSTRAINT proposal_repo CHECK (repo ~ '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$'),
    CONSTRAINT proposal_pr_number CHECK (pr_number > 0),
    CONSTRAINT proposal_external_id CHECK (external_id ~ '^[a-z-]+[0-9]+$'),
    -- The server builds this link from the API answer, never from LLM output.
    CONSTRAINT proposal_source_url CHECK (
        char_length(source_url) <= 2048
        AND source_url ~ '^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/pull/[0-9]+(#[A-Za-z0-9_-]+)?$'),
    CONSTRAINT proposal_source_sha256 CHECK (octet_length(source_sha256) = 32),
    CONSTRAINT proposal_candidate_index CHECK (candidate_index >= 0),
    CONSTRAINT proposal_sys_period_open CHECK (upper(sys_period) IS NULL)
);

CREATE INDEX proposal_inbox ON proposals.proposal (tenant_id, id DESC);

CREATE TRIGGER proposal_open_sys_period
    BEFORE INSERT ON proposals.proposal
    FOR EACH ROW EXECUTE FUNCTION registry.open_sys_period();

GRANT USAGE ON SCHEMA proposals TO ipso_app;
GRANT SELECT, INSERT ON proposals.proposal TO ipso_app;
