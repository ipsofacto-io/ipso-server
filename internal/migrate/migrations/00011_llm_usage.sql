-- +goose Up
-- Monthly token use per tenant for the LLM gateway, section 4.4 of the specification and
-- ADR-0081. The gateway reserves the most a call can cost before it sends anything and settles
-- to what the provider reports, so the row is a counter that ipso_app updates. It holds no
-- prompt, no answer, and no person. Row-level security ships with IPSO-61, and the table
-- carries tenant_id, so the criteria already on that issue cover it.
CREATE SCHEMA llm;

CREATE TABLE llm.usage (
    tenant_id uuid   NOT NULL,
    month     date   NOT NULL,
    tokens    bigint NOT NULL,
    PRIMARY KEY (tenant_id, month),
    CONSTRAINT usage_month CHECK (extract(day FROM month) = 1),
    CONSTRAINT usage_tokens CHECK (tokens >= 0)
);

GRANT USAGE ON SCHEMA llm TO ipso_app;
GRANT SELECT, INSERT, UPDATE ON llm.usage TO ipso_app;
