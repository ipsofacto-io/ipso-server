-- +goose Up
-- Verifiable decisions, authoritative engine: llm checks, CLI PKCE sessions,
-- human authoring proposals, live drift verdicts, and decision health (ADR-0158..ADR-0163).

-- 1. Revocable CLI bearer sessions opened via loopback PKCE S256 (ADR-0160).
CREATE TABLE identity.cli_session (
    tenant_id    uuid        NOT NULL,
    id           uuid        NOT NULL DEFAULT uuidv7(),
    login_id     uuid        NOT NULL,
    token_sha256 bytea       NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at   timestamptz NOT NULL DEFAULT clock_timestamp() + interval '30 days',
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT cli_session_tenant FOREIGN KEY (tenant_id) REFERENCES tenancy.tenant (tenant_id),
    CONSTRAINT cli_session_token_once UNIQUE (tenant_id, token_sha256),
    CONSTRAINT cli_session_login FOREIGN KEY (tenant_id, login_id)
        REFERENCES identity.login (tenant_id, id),
    CONSTRAINT cli_session_token_length CHECK (octet_length(token_sha256) = 32),
    CONSTRAINT cli_session_lifetime CHECK (expires_at > created_at)
);

CREATE INDEX cli_session_by_expiry ON identity.cli_session (tenant_id, expires_at);
CREATE INDEX cli_session_by_login ON identity.cli_session (tenant_id, login_id);

-- +goose StatementBegin
CREATE FUNCTION identity.cli_session_stamp() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM identity.login l
        JOIN identity.principal p ON p.tenant_id = l.tenant_id AND p.id = l.principal_id
        WHERE l.tenant_id = NEW.tenant_id
          AND l.id = NEW.login_id
          AND l.closed_at IS NULL
          AND p.kind = 'human'
    ) THEN
        RAISE EXCEPTION 'a CLI session needs an open login of a person'
            USING ERRCODE = 'check_violation';
    END IF;
    NEW.created_at := clock_timestamp();
    NEW.expires_at := NEW.created_at + interval '30 days';
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER cli_session_stamp
    BEFORE INSERT ON identity.cli_session
    FOR EACH ROW EXECUTE FUNCTION identity.cli_session_stamp();

ALTER TABLE identity.cli_session ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.cli_session FORCE ROW LEVEL SECURITY;

CREATE POLICY app_select ON identity.cli_session FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON identity.cli_session FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY app_delete ON identity.cli_session FOR DELETE TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_select ON identity.cli_session FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON identity.cli_session FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());

GRANT SELECT, INSERT, DELETE ON identity.cli_session TO ipso_app;

-- 2. Human-authored decision proposals and approvals (ADR-0161).
CREATE TABLE proposals.human_proposal (
    tenant_id    uuid      NOT NULL,
    id           uuid      NOT NULL DEFAULT uuidv7(),
    principal_id uuid      NOT NULL,
    status       text      NOT NULL DEFAULT 'pending',
    payload      jsonb     NOT NULL,
    sys_period   tstzrange NOT NULL DEFAULT tstzrange(clock_timestamp(), NULL),
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT human_proposal_tenant FOREIGN KEY (tenant_id) REFERENCES tenancy.tenant (tenant_id),
    CONSTRAINT human_proposal_principal FOREIGN KEY (tenant_id, principal_id)
        REFERENCES identity.principal (tenant_id, id),
    CONSTRAINT human_proposal_status CHECK (status = 'pending'),
    CONSTRAINT human_proposal_payload CHECK (
        jsonb_typeof(payload) = 'object'
        AND octet_length(payload::text) <= 65536
        AND NOT (payload ? 'status')),
    CONSTRAINT human_proposal_sys_period_open CHECK (upper(sys_period) IS NULL)
);

CREATE INDEX human_proposal_inbox ON proposals.human_proposal (tenant_id, id DESC);

-- +goose StatementBegin
CREATE FUNCTION proposals.require_human_author() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM identity.principal p
        WHERE p.tenant_id = NEW.tenant_id
          AND p.id = NEW.principal_id
          AND p.kind = 'human'
    ) THEN
        RAISE EXCEPTION 'a human proposal requires a human principal'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER human_proposal_author
    BEFORE INSERT ON proposals.human_proposal
    FOR EACH ROW EXECUTE FUNCTION proposals.require_human_author();

CREATE TRIGGER human_proposal_open_sys_period
    BEFORE INSERT ON proposals.human_proposal
    FOR EACH ROW EXECUTE FUNCTION registry.open_sys_period();

CREATE TABLE proposals.human_approval (
    tenant_id   uuid      NOT NULL,
    id          uuid      NOT NULL DEFAULT uuidv7(),
    proposal_id uuid      NOT NULL,
    approver_id uuid      NOT NULL,
    outcome     text      NOT NULL,
    decision_id uuid,
    sys_period  tstzrange NOT NULL DEFAULT tstzrange(clock_timestamp(), NULL),
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT human_approval_tenant FOREIGN KEY (tenant_id) REFERENCES tenancy.tenant (tenant_id),
    CONSTRAINT human_approval_once UNIQUE (tenant_id, proposal_id),
    CONSTRAINT human_approval_decision_once UNIQUE (tenant_id, decision_id),
    CONSTRAINT human_approval_proposal FOREIGN KEY (tenant_id, proposal_id)
        REFERENCES proposals.human_proposal (tenant_id, id),
    CONSTRAINT human_approval_approver_principal FOREIGN KEY (tenant_id, approver_id)
        REFERENCES identity.principal (tenant_id, id),
    CONSTRAINT human_approval_outcome CHECK (outcome IN ('approved', 'rejected')),
    CONSTRAINT human_approval_decision CHECK ((outcome = 'approved') = (decision_id IS NOT NULL)),
    CONSTRAINT human_approval_sys_period_open CHECK (upper(sys_period) IS NULL)
);

CREATE TRIGGER human_approval_approver
    BEFORE INSERT ON proposals.human_approval
    FOR EACH ROW EXECUTE FUNCTION identity.require_human_approver();

CREATE TRIGGER human_approval_open_sys_period
    BEFORE INSERT ON proposals.human_approval
    FOR EACH ROW EXECUTE FUNCTION registry.open_sys_period();

ALTER TABLE proposals.human_proposal ENABLE ROW LEVEL SECURITY;
ALTER TABLE proposals.human_proposal FORCE ROW LEVEL SECURITY;
ALTER TABLE proposals.human_approval ENABLE ROW LEVEL SECURITY;
ALTER TABLE proposals.human_approval FORCE ROW LEVEL SECURITY;

CREATE POLICY app_select ON proposals.human_proposal FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON proposals.human_proposal FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_select ON proposals.human_proposal FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_insert ON proposals.human_proposal FOR INSERT TO ipso_migrate
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON proposals.human_proposal FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());

CREATE POLICY app_select ON proposals.human_approval FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON proposals.human_approval FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_select ON proposals.human_approval FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_insert ON proposals.human_approval FOR INSERT TO ipso_migrate
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON proposals.human_approval FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());

GRANT SELECT, INSERT ON proposals.human_proposal TO ipso_app;
GRANT SELECT, INSERT ON proposals.human_approval TO ipso_app;

-- 3. Extend proposals.check_proposal to support engine: llm and max_age_days (ADR-0158, ADR-0159).
ALTER TABLE proposals.check_proposal DROP CONSTRAINT check_proposal_engine;
ALTER TABLE proposals.check_proposal DROP CONSTRAINT check_proposal_target;
ALTER TABLE proposals.check_proposal DROP CONSTRAINT check_proposal_fixtures_pass;
ALTER TABLE proposals.check_proposal
    ADD COLUMN max_age_days integer,
    ADD CONSTRAINT check_proposal_engine CHECK (engine IN ('opa', 'llm')),
    ADD CONSTRAINT check_proposal_target CHECK (
        (engine = 'opa' AND target = 'agent-edit')
        OR (engine = 'llm' AND target IN ('diff', 'terraform-plan', 'kubernetes-manifest', 'json-snapshot', 'text'))),
    ADD CONSTRAINT check_proposal_fixtures_pass CHECK (
        ((engine = 'opa' AND fixtures_total BETWEEN 2 AND 50)
         OR (engine = 'llm' AND fixtures_total BETWEEN 0 AND 50))
        AND fixtures_passed = fixtures_total),
    ADD CONSTRAINT check_proposal_max_age_days CHECK (max_age_days IS NULL OR max_age_days BETWEEN 1 AND 365);

-- 4. Explicit per-tenant LLM opt-in policy (off by default, ADR-0160, ADR-0161).
CREATE TABLE llm.tenant_policy (
    tenant_id              uuid        NOT NULL,
    allow_authoring_assist boolean     NOT NULL DEFAULT false,
    allow_check_eval       boolean     NOT NULL DEFAULT false,
    updated_at             timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id),
    CONSTRAINT tenant_policy_tenant FOREIGN KEY (tenant_id) REFERENCES tenancy.tenant (tenant_id)
);

ALTER TABLE llm.tenant_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE llm.tenant_policy FORCE ROW LEVEL SECURITY;

CREATE POLICY app_select ON llm.tenant_policy FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON llm.tenant_policy FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY app_update ON llm.tenant_policy FOR UPDATE TO ipso_app
    USING (tenant_id = ipso.current_tenant())
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_select ON llm.tenant_policy FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_insert ON llm.tenant_policy FOR INSERT TO ipso_migrate
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON llm.tenant_policy FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());

GRANT SELECT, INSERT, UPDATE ON llm.tenant_policy TO ipso_app;

-- 5. Extend verification.upload for check: llm and source_kind (change vs live) (ADR-0158, ADR-0162).
ALTER TABLE verification.upload DROP CONSTRAINT upload_check_name;
ALTER TABLE verification.upload DROP CONSTRAINT upload_installation_positive;
ALTER TABLE verification.upload DROP CONSTRAINT upload_repository_positive;

ALTER TABLE verification.upload
    ADD COLUMN source_kind text NOT NULL DEFAULT 'change',
    ADD CONSTRAINT upload_source_kind CHECK (source_kind IN ('change', 'live')),
    ADD CONSTRAINT upload_check_name CHECK (check_name IN (
        'plan', 'ci', 'checkov', 'snyk', 'wiz', 'sonarqube', 'dependabot',
        'pulumi', 'cloudformation', 'arm', 'depcruise', 'semgrep',
        'archunit', 'importlinter', 'kyverno', 'gatekeeper', 'eslint', 'llm')),
    ADD CONSTRAINT upload_installation_positive CHECK (
        (source_kind = 'change' AND installation_id > 0)
        OR (source_kind = 'live' AND installation_id >= 0)),
    ADD CONSTRAINT upload_repository_positive CHECK (
        (source_kind = 'change' AND repository_id > 0)
        OR (source_kind = 'live' AND repository_id >= 0));

CREATE INDEX upload_source_recent ON verification.upload (tenant_id, source_kind, repo, id DESC);

ALTER TABLE verification.verdict
    ADD COLUMN model_id       text,
    ADD COLUMN prompt_version text,
    ADD CONSTRAINT verdict_model_id CHECK (model_id IS NULL OR char_length(model_id) BETWEEN 1 AND 200),
    ADD CONSTRAINT verdict_prompt_version CHECK (prompt_version IS NULL OR char_length(prompt_version) BETWEEN 1 AND 100),
    ADD CONSTRAINT verdict_model_pair CHECK ((model_id IS NULL) = (prompt_version IS NULL));

-- 6. Pinned ipso-agent public keys for signed live drift reports (ADR-0162).
CREATE TABLE verification.agent_pin (
    tenant_id      uuid      NOT NULL,
    id             uuid      NOT NULL DEFAULT uuidv7(),
    name           text      NOT NULL,
    repo           text      NOT NULL,
    env            text      NOT NULL DEFAULT '',
    pin_sha256     bytea     NOT NULL,
    public_key_der bytea     NOT NULL,
    sys_period     tstzrange NOT NULL DEFAULT tstzrange(clock_timestamp(), NULL),
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT agent_pin_tenant FOREIGN KEY (tenant_id) REFERENCES tenancy.tenant (tenant_id),
    CONSTRAINT agent_pin_unique UNIQUE (tenant_id, pin_sha256),
    CONSTRAINT agent_pin_name_once UNIQUE (tenant_id, name),
    CONSTRAINT agent_pin_name CHECK (
        char_length(name) BETWEEN 1 AND 100 AND name ~ '^[a-z0-9][a-z0-9._-]*$'),
    CONSTRAINT agent_pin_repo CHECK (
        char_length(repo) <= 140 AND repo ~ '^[a-z0-9_.-]+/[a-z0-9_.-]+$'),
    CONSTRAINT agent_pin_env CHECK (char_length(env) <= 256 AND env !~ '[[:cntrl:]]'),
    CONSTRAINT agent_pin_sha256 CHECK (octet_length(pin_sha256) = 32),
    CONSTRAINT agent_pin_der CHECK (octet_length(public_key_der) BETWEEN 32 AND 4096),
    CONSTRAINT agent_pin_sys_period_open CHECK (upper(sys_period) IS NULL)
);

CREATE TRIGGER agent_pin_open_sys_period
    BEFORE INSERT ON verification.agent_pin
    FOR EACH ROW EXECUTE FUNCTION registry.open_sys_period();

ALTER TABLE verification.agent_pin ENABLE ROW LEVEL SECURITY;
ALTER TABLE verification.agent_pin FORCE ROW LEVEL SECURITY;

CREATE POLICY app_select ON verification.agent_pin FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON verification.agent_pin FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY app_delete ON verification.agent_pin FOR DELETE TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_select ON verification.agent_pin FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON verification.agent_pin FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());

GRANT SELECT, INSERT, DELETE ON verification.agent_pin TO ipso_app;

-- 7. Per-tenant and per-environment default max_age_days freshness thresholds (ADR-0163).
CREATE TABLE verification.freshness_policy (
    tenant_id    uuid        NOT NULL,
    env          text        NOT NULL DEFAULT '',
    max_age_days integer     NOT NULL,
    updated_at   timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (tenant_id, env),
    CONSTRAINT freshness_policy_tenant FOREIGN KEY (tenant_id) REFERENCES tenancy.tenant (tenant_id),
    CONSTRAINT freshness_policy_env CHECK (char_length(env) <= 256 AND env !~ '[[:cntrl:]]'),
    CONSTRAINT freshness_policy_age CHECK (max_age_days BETWEEN 1 AND 365)
);

ALTER TABLE verification.freshness_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE verification.freshness_policy FORCE ROW LEVEL SECURITY;

CREATE POLICY app_select ON verification.freshness_policy FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON verification.freshness_policy FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY app_update ON verification.freshness_policy FOR UPDATE TO ipso_app
    USING (tenant_id = ipso.current_tenant())
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY app_delete ON verification.freshness_policy FOR DELETE TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_select ON verification.freshness_policy FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_insert ON verification.freshness_policy FOR INSERT TO ipso_migrate
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON verification.freshness_policy FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());

GRANT SELECT, INSERT, UPDATE, DELETE ON verification.freshness_policy TO ipso_app;

-- 8. Full-text GIN indexes on decision versions and history for topic queries (ADR-0163).
CREATE INDEX decision_version_fts ON registry.decision_version
    USING gin (to_tsvector('simple',
        coalesce(body->>'title', '') || ' ' ||
        coalesce(body->>'slug', '') || ' ' ||
        coalesce(body->>'statement', '')));

CREATE INDEX decision_version_history_fts ON registry.decision_version_history
    USING gin (to_tsvector('simple',
        coalesce(body->>'title', '') || ' ' ||
        coalesce(body->>'slug', '') || ' ' ||
        coalesce(body->>'statement', '')));
