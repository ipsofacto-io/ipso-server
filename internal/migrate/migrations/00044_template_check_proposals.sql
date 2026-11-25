-- +goose Up
-- Checks an LLM drafted by choosing one built-in template of ipso (ADR-0165). A template row names
-- its template in ref, as ipso:<id>, and holds no Rego and no fixtures: the rule is the tested
-- template of the ipso version that builds it, and the model only chose it. spec holds the catalog
-- entry the model chose, so a reviewer reads the title the check was proposed with. A plan template
-- is engine opa with target terraform-plan, and a Semgrep template is engine semgrep with no target.
-- A row still waits for a person in proposals.check_approval (ADR-0116).
ALTER TABLE proposals.check_proposal DROP CONSTRAINT check_proposal_engine;
ALTER TABLE proposals.check_proposal DROP CONSTRAINT check_proposal_target;
ALTER TABLE proposals.check_proposal DROP CONSTRAINT check_proposal_rego;
ALTER TABLE proposals.check_proposal DROP CONSTRAINT check_proposal_rego_sha256;
ALTER TABLE proposals.check_proposal DROP CONSTRAINT check_proposal_fixtures_pass;
ALTER TABLE proposals.check_proposal
    ALTER COLUMN target DROP NOT NULL,
    ALTER COLUMN rego DROP NOT NULL,
    ALTER COLUMN rego_sha256 DROP NOT NULL,
    ADD COLUMN ref text,
    ADD CONSTRAINT check_proposal_engine CHECK (engine IN ('opa', 'llm', 'semgrep')),
    ADD CONSTRAINT check_proposal_ref CHECK (ref IS NULL OR ref ~ '^ipso:[a-z0-9-]+/[a-z0-9-]+$'),
    ADD CONSTRAINT check_proposal_target CHECK (
        (ref IS NULL AND engine = 'opa' AND target IS NOT NULL AND target = 'agent-edit')
        OR (ref IS NULL AND engine = 'llm' AND target IS NOT NULL
            AND target IN ('diff', 'terraform-plan', 'kubernetes-manifest', 'json-snapshot', 'text'))
        OR (ref IS NOT NULL AND engine = 'opa' AND target IS NOT NULL AND target = 'terraform-plan')
        OR (ref IS NOT NULL AND engine = 'semgrep' AND target IS NULL)),
    -- A NULL in a CHECK passes, so each branch says which columns are set.
    ADD CONSTRAINT check_proposal_rego CHECK (
        (ref IS NULL AND rego IS NOT NULL AND rego_sha256 IS NOT NULL AND char_length(rego) BETWEEN 1 AND 65536)
        OR (ref IS NOT NULL AND rego IS NULL AND rego_sha256 IS NULL)),
    ADD CONSTRAINT check_proposal_rego_sha256 CHECK (
        rego IS NULL
        OR (rego_sha256 IS NOT NULL AND octet_length(rego_sha256) = 32
            AND rego_sha256 = sha256(convert_to(rego, 'UTF8')))),
    ADD CONSTRAINT check_proposal_fixtures_pass CHECK (
        ((ref IS NULL AND engine = 'opa' AND fixtures_total BETWEEN 2 AND 50)
         OR (ref IS NULL AND engine = 'llm' AND fixtures_total BETWEEN 0 AND 50)
         OR (ref IS NOT NULL AND fixtures_total = 0 AND NOT repaired))
        AND fixtures_passed = fixtures_total);

-- Choosing the same template again for the same decision version adds nothing.
CREATE UNIQUE INDEX check_proposal_template_once
    ON proposals.check_proposal (tenant_id, decision_id, decision_version, ref)
    WHERE ref IS NOT NULL;
