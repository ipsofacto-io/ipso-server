-- +goose Up
-- How a pending proposal relates to the decisions in force, as a model judged it (IPSO-159, ADR-0172).
--
-- An annotation sits beside one pull request proposal or one agent proposal and never changes it: the
-- proposal tables keep their rows, their payload, and their pending status. A hint names a decision the
-- server sent the model as a candidate, and the title it sent. Both tables are insert-only for ipso_app.
-- The decision id is not a foreign key, because the proposals schema reads the registry only through
-- its Go API (ADR-0085), as proposals.approval does.

CREATE TABLE proposals.relation_annotation (
    tenant_id         uuid      NOT NULL,
    id                uuid      NOT NULL DEFAULT uuidv7(),
    proposal_id       uuid,
    agent_proposal_id uuid,
    model_id          text      NOT NULL,
    prompt_version    text      NOT NULL,
    sys_period        tstzrange NOT NULL DEFAULT tstzrange(clock_timestamp(), NULL),
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT relation_annotation_proposal FOREIGN KEY (tenant_id, proposal_id)
        REFERENCES proposals.proposal (tenant_id, id),
    CONSTRAINT relation_annotation_agent_proposal FOREIGN KEY (tenant_id, agent_proposal_id)
        REFERENCES proposals.agent_proposal (tenant_id, id),
    CONSTRAINT relation_annotation_one_proposal CHECK (num_nonnulls(proposal_id, agent_proposal_id) = 1),
    CONSTRAINT relation_annotation_proposal_once UNIQUE (tenant_id, proposal_id),
    CONSTRAINT relation_annotation_agent_proposal_once UNIQUE (tenant_id, agent_proposal_id),
    CONSTRAINT relation_annotation_model CHECK (char_length(model_id) BETWEEN 1 AND 200),
    CONSTRAINT relation_annotation_prompt CHECK (char_length(prompt_version) BETWEEN 1 AND 100),
    CONSTRAINT relation_annotation_sys_period_open CHECK (upper(sys_period) IS NULL)
);

CREATE TABLE proposals.relation_hint (
    tenant_id        uuid    NOT NULL,
    annotation_id    uuid    NOT NULL,
    decision_id      uuid    NOT NULL,
    decision_version integer NOT NULL,
    title            text    NOT NULL,
    relation         text    NOT NULL,
    PRIMARY KEY (tenant_id, annotation_id, decision_id),
    CONSTRAINT relation_hint_annotation FOREIGN KEY (tenant_id, annotation_id)
        REFERENCES proposals.relation_annotation (tenant_id, id),
    CONSTRAINT relation_hint_version CHECK (decision_version >= 1),
    CONSTRAINT relation_hint_title CHECK (char_length(title) BETWEEN 1 AND 200),
    CONSTRAINT relation_hint_relation CHECK (relation IN ('duplicates', 'supersedes', 'conflicts'))
);

CREATE TRIGGER relation_annotation_open_sys_period
    BEFORE INSERT ON proposals.relation_annotation
    FOR EACH ROW EXECUTE FUNCTION registry.open_sys_period();

ALTER TABLE proposals.relation_annotation ENABLE ROW LEVEL SECURITY;
ALTER TABLE proposals.relation_annotation FORCE ROW LEVEL SECURITY;
ALTER TABLE proposals.relation_hint ENABLE ROW LEVEL SECURITY;
ALTER TABLE proposals.relation_hint FORCE ROW LEVEL SECURITY;

CREATE POLICY app_select ON proposals.relation_annotation FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON proposals.relation_annotation FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_select ON proposals.relation_annotation FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_insert ON proposals.relation_annotation FOR INSERT TO ipso_migrate
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON proposals.relation_annotation FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());

CREATE POLICY app_select ON proposals.relation_hint FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON proposals.relation_hint FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_select ON proposals.relation_hint FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_insert ON proposals.relation_hint FOR INSERT TO ipso_migrate
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON proposals.relation_hint FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());

GRANT SELECT, INSERT ON proposals.relation_annotation TO ipso_app;
GRANT SELECT, INSERT ON proposals.relation_hint TO ipso_app;

-- An agent starts the annotation of its own proposal with text it writes, so the tenant opts in to it, as
-- to authoring assistance and llm check evaluation. Pull request proposals need no opt-in: they follow the
-- extraction of a merged pull request.
ALTER TABLE llm.tenant_policy
    ADD COLUMN allow_agent_proposal_relations boolean NOT NULL DEFAULT false;
