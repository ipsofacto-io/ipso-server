-- +goose Up
-- Paid tracker connectors (IPSO-71, ADR-0133).
--
-- proposals.proposal stays pull-request shaped. A decision ticket is a row of
-- proposals.tracker_proposal: pending, untrusted, and insert-only. The ticket body is not a column.
-- proposals.tracker_approval is the person's answer, and a ticket cannot write it.
-- integrations.tracker_binding is one connector for a tenant. Its token and webhook secret are sealed.
-- The row is not exported. integrations.tracker_link holds the last status, and an update may change
-- only that column. A status is not an approval and not a waiver.

CREATE SCHEMA integrations;

CREATE TABLE proposals.tracker_proposal (
    tenant_id       uuid          NOT NULL,
    id              uuid          NOT NULL DEFAULT uuidv7(),
    connector       text          NOT NULL,
    status          text          NOT NULL DEFAULT 'pending',
    trust_level     text          NOT NULL DEFAULT 'untrusted',
    payload         jsonb         NOT NULL,
    confidence      numeric(3, 2) NOT NULL,
    model_id        text          NOT NULL,
    prompt_version  text          NOT NULL,
    external_id     text          NOT NULL,
    source_url      text          NOT NULL,
    source_sha256   bytea         NOT NULL,
    candidate_index integer       NOT NULL,
    sys_period      tstzrange     NOT NULL DEFAULT tstzrange(clock_timestamp(), NULL),
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT tracker_proposal_once UNIQUE (tenant_id, connector, external_id, source_sha256, candidate_index),
    CONSTRAINT tracker_proposal_connector CHECK (connector IN ('jira', 'linear', 'github_issues')),
    CONSTRAINT tracker_proposal_status CHECK (status = 'pending'),
    CONSTRAINT tracker_proposal_trust_level CHECK (trust_level = 'untrusted'),
    CONSTRAINT tracker_proposal_payload CHECK (
        jsonb_typeof(payload) = 'object'
        AND octet_length(payload::text) <= 8192
        AND NOT (payload ? 'status')),
    CONSTRAINT tracker_proposal_confidence CHECK (confidence BETWEEN 0 AND 1),
    CONSTRAINT tracker_proposal_model_id CHECK (char_length(model_id) BETWEEN 1 AND 200),
    CONSTRAINT tracker_proposal_prompt_version CHECK (char_length(prompt_version) BETWEEN 1 AND 100),
    CONSTRAINT tracker_proposal_external_id CHECK (
        char_length(external_id) BETWEEN 1 AND 200
        AND btrim(external_id) = external_id
        AND external_id !~ '[[:cntrl:]]'),
    CONSTRAINT tracker_proposal_source_url CHECK (
        char_length(source_url) <= 2048
        AND (
            (connector = 'jira' AND source_url ~ '^https://[a-z0-9-]+\.atlassian\.net/browse/[A-Z][A-Z0-9_]+-[0-9]+$')
            OR (connector = 'linear' AND source_url ~ '^https://linear\.app/[a-z0-9-]+/issue/[A-Za-z0-9]+-[0-9]+$')
            OR (connector = 'github_issues' AND source_url ~ '^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/issues/[0-9]+$')
        )),
    CONSTRAINT tracker_proposal_source_sha256 CHECK (octet_length(source_sha256) = 32),
    CONSTRAINT tracker_proposal_candidate_index CHECK (candidate_index >= 0 AND candidate_index < 5),
    CONSTRAINT tracker_proposal_sys_period_open CHECK (upper(sys_period) IS NULL)
);

CREATE INDEX tracker_proposal_inbox ON proposals.tracker_proposal (tenant_id, id DESC);

CREATE TRIGGER tracker_proposal_open_sys_period
    BEFORE INSERT ON proposals.tracker_proposal
    FOR EACH ROW EXECUTE FUNCTION registry.open_sys_period();

CREATE TABLE proposals.tracker_approval (
    tenant_id   uuid      NOT NULL,
    id          uuid      NOT NULL DEFAULT uuidv7(),
    proposal_id uuid      NOT NULL,
    approver_id uuid      NOT NULL,
    outcome     text      NOT NULL,
    decision_id uuid,
    sys_period  tstzrange NOT NULL DEFAULT tstzrange(clock_timestamp(), NULL),
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT tracker_approval_once UNIQUE (tenant_id, proposal_id),
    CONSTRAINT tracker_approval_decision_once UNIQUE (tenant_id, decision_id),
    CONSTRAINT tracker_approval_proposal FOREIGN KEY (tenant_id, proposal_id)
        REFERENCES proposals.tracker_proposal (tenant_id, id),
    CONSTRAINT tracker_approval_approver_principal FOREIGN KEY (tenant_id, approver_id)
        REFERENCES identity.principal (tenant_id, id),
    CONSTRAINT tracker_approval_outcome CHECK (outcome IN ('approved', 'rejected')),
    CONSTRAINT tracker_approval_decision CHECK ((outcome = 'approved') = (decision_id IS NOT NULL)),
    CONSTRAINT tracker_approval_sys_period_open CHECK (upper(sys_period) IS NULL)
);

CREATE TRIGGER tracker_approval_approver
    BEFORE INSERT ON proposals.tracker_approval
    FOR EACH ROW EXECUTE FUNCTION identity.require_human_approver();

CREATE TRIGGER tracker_approval_open_sys_period
    BEFORE INSERT ON proposals.tracker_approval
    FOR EACH ROW EXECUTE FUNCTION registry.open_sys_period();

-- The id is the primary key of the whole table, so a webhook path names one binding.
-- external_account is unique per connector across tenants, the way an installation id is.
CREATE TABLE integrations.tracker_binding (
    id               uuid      NOT NULL DEFAULT uuidv7(),
    tenant_id        uuid      NOT NULL,
    connector        text      NOT NULL,
    external_account text      NOT NULL,
    label            text      NOT NULL DEFAULT 'ipso-decision',
    token_sealed     bytea     NOT NULL,
    webhook_sealed   bytea     NOT NULL,
    sys_period       tstzrange NOT NULL DEFAULT tstzrange(clock_timestamp(), NULL),
    PRIMARY KEY (id),
    CONSTRAINT tracker_binding_tenant_connector UNIQUE (tenant_id, connector),
    CONSTRAINT tracker_binding_account UNIQUE (connector, external_account),
    CONSTRAINT tracker_binding_tenant FOREIGN KEY (tenant_id) REFERENCES tenancy.tenant (tenant_id),
    CONSTRAINT tracker_binding_connector CHECK (connector IN ('jira', 'linear', 'github_issues')),
    CONSTRAINT tracker_binding_account_text CHECK (
        char_length(external_account) BETWEEN 1 AND 200
        AND btrim(external_account) = external_account
        AND external_account !~ '[[:cntrl:]]'),
    CONSTRAINT tracker_binding_label CHECK (label ~ '^[A-Za-z0-9][A-Za-z0-9-]{0,63}$'),
    CONSTRAINT tracker_binding_token CHECK (octet_length(token_sealed) BETWEEN 29 AND 8192),
    CONSTRAINT tracker_binding_webhook CHECK (octet_length(webhook_sealed) BETWEEN 29 AND 8192),
    CONSTRAINT tracker_binding_sys_period_open CHECK (upper(sys_period) IS NULL)
);

CREATE TRIGGER tracker_binding_open_sys_period
    BEFORE INSERT ON integrations.tracker_binding
    FOR EACH ROW EXECUTE FUNCTION registry.open_sys_period();

CREATE TABLE integrations.tracker_link (
    tenant_id   uuid      NOT NULL,
    id          uuid      NOT NULL DEFAULT uuidv7(),
    connector   text      NOT NULL,
    external_id text      NOT NULL,
    url         text      NOT NULL,
    kind        text      NOT NULL,
    proposal_id uuid,
    waiver_id   uuid,
    status      text      NOT NULL,
    sys_period  tstzrange NOT NULL DEFAULT tstzrange(clock_timestamp(), NULL),
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT tracker_link_once UNIQUE (tenant_id, connector, external_id),
    CONSTRAINT tracker_link_connector CHECK (connector IN ('jira', 'linear', 'github_issues')),
    CONSTRAINT tracker_link_external_id CHECK (
        char_length(external_id) BETWEEN 1 AND 200
        AND btrim(external_id) = external_id
        AND external_id !~ '[[:cntrl:]]'),
    CONSTRAINT tracker_link_url CHECK (
        char_length(url) <= 2048
        AND (
            (connector = 'jira' AND url ~ '^https://[a-z0-9-]+\.atlassian\.net/browse/[A-Z][A-Z0-9_]+-[0-9]+$')
            OR (connector = 'linear' AND url ~ '^https://linear\.app/[a-z0-9-]+/issue/[A-Za-z0-9]+-[0-9]+$')
            OR (connector = 'github_issues' AND url ~ '^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/issues/[0-9]+$')
        )),
    CONSTRAINT tracker_link_kind CHECK (kind IN ('decision', 'waiver')),
    CONSTRAINT tracker_link_proposal CHECK ((kind = 'decision') = (proposal_id IS NOT NULL)),
    CONSTRAINT tracker_link_waiver CHECK ((kind = 'waiver') = (waiver_id IS NOT NULL)),
    CONSTRAINT tracker_link_proposal_fk FOREIGN KEY (tenant_id, proposal_id)
        REFERENCES proposals.tracker_proposal (tenant_id, id),
    CONSTRAINT tracker_link_waiver_fk FOREIGN KEY (tenant_id, waiver_id)
        REFERENCES registry.waiver (tenant_id, id),
    CONSTRAINT tracker_link_status CHECK (status IN ('open', 'done', 'canceled')),
    CONSTRAINT tracker_link_sys_period_open CHECK (upper(sys_period) IS NULL)
);

CREATE TRIGGER tracker_link_open_sys_period
    BEFORE INSERT ON integrations.tracker_link
    FOR EACH ROW EXECUTE FUNCTION registry.open_sys_period();

-- +goose StatementBegin
CREATE FUNCTION integrations.tracker_link_status() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.id IS DISTINCT FROM OLD.id
        OR NEW.connector IS DISTINCT FROM OLD.connector
        OR NEW.external_id IS DISTINCT FROM OLD.external_id
        OR NEW.url IS DISTINCT FROM OLD.url
        OR NEW.kind IS DISTINCT FROM OLD.kind
        OR NEW.proposal_id IS DISTINCT FROM OLD.proposal_id
        OR NEW.waiver_id IS DISTINCT FROM OLD.waiver_id
        OR NEW.sys_period IS DISTINCT FROM OLD.sys_period
    THEN
        RAISE EXCEPTION 'only the tracker status may change' USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER tracker_link_status
    BEFORE UPDATE ON integrations.tracker_link
    FOR EACH ROW EXECUTE FUNCTION integrations.tracker_link_status();

ALTER TABLE proposals.tracker_proposal ENABLE ROW LEVEL SECURITY;
ALTER TABLE proposals.tracker_proposal FORCE ROW LEVEL SECURITY;
ALTER TABLE proposals.tracker_approval ENABLE ROW LEVEL SECURITY;
ALTER TABLE proposals.tracker_approval FORCE ROW LEVEL SECURITY;
ALTER TABLE integrations.tracker_binding ENABLE ROW LEVEL SECURITY;
ALTER TABLE integrations.tracker_binding FORCE ROW LEVEL SECURITY;
ALTER TABLE integrations.tracker_link ENABLE ROW LEVEL SECURITY;
ALTER TABLE integrations.tracker_link FORCE ROW LEVEL SECURITY;

CREATE POLICY app_select ON proposals.tracker_proposal FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON proposals.tracker_proposal FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY app_select ON proposals.tracker_approval FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON proposals.tracker_approval FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY app_select ON integrations.tracker_binding FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON integrations.tracker_binding FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY app_delete ON integrations.tracker_binding FOR DELETE TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_select ON integrations.tracker_link FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON integrations.tracker_link FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY app_update ON integrations.tracker_link FOR UPDATE TO ipso_app
    USING (tenant_id = ipso.current_tenant())
    WITH CHECK (tenant_id = ipso.current_tenant());

CREATE POLICY migrate_select ON proposals.tracker_proposal FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_insert ON proposals.tracker_proposal FOR INSERT TO ipso_migrate
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON proposals.tracker_proposal FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_select ON proposals.tracker_approval FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_insert ON proposals.tracker_approval FOR INSERT TO ipso_migrate
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON proposals.tracker_approval FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
-- The second arm is the webhook lookup, which has no tenant set. Delete has no such arm.
CREATE POLICY migrate_select ON integrations.tracker_binding FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant() OR ipso.current_tenant() IS NULL);
CREATE POLICY migrate_delete ON integrations.tracker_binding FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_select ON integrations.tracker_link FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_insert ON integrations.tracker_link FOR INSERT TO ipso_migrate
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON integrations.tracker_link FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());

GRANT USAGE ON SCHEMA integrations TO ipso_app;
GRANT SELECT, INSERT ON proposals.tracker_proposal TO ipso_app;
GRANT SELECT, INSERT ON proposals.tracker_approval TO ipso_app;
GRANT SELECT, INSERT, DELETE ON integrations.tracker_binding TO ipso_app;
GRANT SELECT, INSERT, UPDATE ON integrations.tracker_link TO ipso_app;

-- +goose StatementBegin
CREATE FUNCTION integrations.tracker_binding_for_webhook(p_id uuid)
    RETURNS TABLE (tenant_id uuid, connector text, external_account text, label text, token_sealed bytea, webhook_sealed bytea)
    LANGUAGE sql STABLE SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
AS $$
    SELECT b.tenant_id, b.connector, b.external_account, b.label, b.token_sealed, b.webhook_sealed
    FROM integrations.tracker_binding AS b
    WHERE b.id = p_id
$$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION integrations.tracker_binding_for_webhook(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION integrations.tracker_binding_for_webhook(uuid) TO ipso_app;
