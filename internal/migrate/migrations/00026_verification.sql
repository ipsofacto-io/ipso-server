-- +goose Up
-- The verdicts a CI job uploads (IPSO-135, ADR-0102).
--
-- verification.upload is one accepted upload: the run that produced it, which the signed CI token names
-- and the body never does, and the hashes and counts of the ADR-0030 verdict report. verification.verdict
-- is one row per decision check of that report. Nothing in either table is a plan value, a resource
-- address, a violation message, or SARIF: the runner keeps those (ADR-0006), and the SARIF file is
-- represented by its digest.
--
-- Both are insert-only tenant tables with the policies of every other one, so rls.Check, the isolation
-- suite, the export catalog and the offboard purge cover them with no special case. The application role
-- reads and inserts its own tenant's rows and cannot update or delete one. The tenant is the tenant
-- of the installation that owns the repository (ADR-0101), never a column the uploader supplies.
--
-- A repeated upload adds nothing: the same run, attempt and content digest is one row (upload_once).

CREATE SCHEMA verification;

CREATE TABLE verification.upload (
    tenant_id       uuid        NOT NULL,
    id              uuid        NOT NULL DEFAULT uuidv7(),
    installation_id bigint      NOT NULL,
    repository_id   bigint      NOT NULL,
    repo            text        NOT NULL,
    run_id          bigint      NOT NULL,
    run_attempt     integer     NOT NULL,
    sha             text        NOT NULL,
    ref             text        NOT NULL,
    event_name      text        NOT NULL,
    workflow_ref    text        NOT NULL,
    check_name      text        NOT NULL,
    env             text        NOT NULL,
    ipso_version    text        NOT NULL,
    evaluated_at    timestamptz NOT NULL,
    build_sha256    bytea       NOT NULL,
    sarif_sha256    bytea,
    -- The fields only some reports have: the plan, evidence or input hash, the commit, the adapter, the
    -- paths and the engine version. The server wrote it from a validated report.
    evidence        jsonb       NOT NULL,
    content_sha256  bytea       NOT NULL,
    sys_period      tstzrange   NOT NULL DEFAULT tstzrange(clock_timestamp(), NULL),
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT upload_tenant FOREIGN KEY (tenant_id) REFERENCES tenancy.tenant (tenant_id),
    CONSTRAINT upload_once UNIQUE (tenant_id, repository_id, run_id, run_attempt, content_sha256),
    CONSTRAINT upload_installation_positive CHECK (installation_id > 0),
    CONSTRAINT upload_repository_positive CHECK (repository_id > 0),
    CONSTRAINT upload_run_positive CHECK (run_id > 0 AND run_attempt > 0),
    CONSTRAINT upload_repo CHECK (
        char_length(repo) <= 140 AND repo ~ '^[a-z0-9_.-]+/[a-z0-9_.-]+$'),
    CONSTRAINT upload_sha CHECK (sha ~ '^[0-9a-f]{40}$|^[0-9a-f]{64}$'),
    CONSTRAINT upload_ref CHECK (char_length(ref) BETWEEN 1 AND 512 AND ref !~ '[[:cntrl:]]'),
    CONSTRAINT upload_event_name CHECK (char_length(event_name) BETWEEN 1 AND 64 AND event_name !~ '[[:cntrl:]]'),
    CONSTRAINT upload_workflow_ref CHECK (char_length(workflow_ref) BETWEEN 1 AND 512 AND workflow_ref !~ '[[:cntrl:]]'),
    CONSTRAINT upload_check_name CHECK (check_name IN (
        'plan', 'ci', 'checkov', 'pulumi', 'cloudformation', 'arm', 'depcruise', 'semgrep',
        'archunit', 'importlinter', 'kyverno', 'gatekeeper', 'eslint')),
    CONSTRAINT upload_env CHECK (char_length(env) <= 256 AND env !~ '[[:cntrl:]]'),
    CONSTRAINT upload_ipso_version CHECK (char_length(ipso_version) BETWEEN 1 AND 64 AND ipso_version !~ '[[:cntrl:]]'),
    CONSTRAINT upload_build_sha256 CHECK (octet_length(build_sha256) = 32),
    CONSTRAINT upload_sarif_sha256 CHECK (sarif_sha256 IS NULL OR octet_length(sarif_sha256) = 32),
    CONSTRAINT upload_evidence CHECK (
        jsonb_typeof(evidence) = 'object' AND octet_length(evidence::text) <= 65536),
    CONSTRAINT upload_content_sha256 CHECK (octet_length(content_sha256) = 32),
    CONSTRAINT upload_sys_period_open CHECK (upper(sys_period) IS NULL)
);

CREATE INDEX upload_repo_recent ON verification.upload (tenant_id, repo, id DESC);

CREATE TABLE verification.verdict (
    tenant_id   uuid      NOT NULL,
    id          uuid      NOT NULL DEFAULT uuidv7(),
    upload_id   uuid      NOT NULL,
    decision_id text      NOT NULL,
    slug        text      NOT NULL,
    check_index integer   NOT NULL,
    mode        text      NOT NULL,
    result      text      NOT NULL,
    violations  integer   NOT NULL,
    sys_period  tstzrange NOT NULL DEFAULT tstzrange(clock_timestamp(), NULL),
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT verdict_tenant FOREIGN KEY (tenant_id) REFERENCES tenancy.tenant (tenant_id),
    CONSTRAINT verdict_upload FOREIGN KEY (tenant_id, upload_id) REFERENCES verification.upload (tenant_id, id),
    CONSTRAINT verdict_once UNIQUE (tenant_id, upload_id, decision_id, check_index),
    -- The EDR id is a ULID and the slug is the EDR slug form (edr-spec).
    CONSTRAINT verdict_decision_id CHECK (decision_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'),
    CONSTRAINT verdict_slug CHECK (char_length(slug) BETWEEN 1 AND 128 AND slug ~ '^[a-z0-9]+(-[a-z0-9]+)*$'),
    CONSTRAINT verdict_check_index CHECK (check_index >= 0),
    CONSTRAINT verdict_mode CHECK (mode IN ('block', 'warn', 'advise')),
    CONSTRAINT verdict_result CHECK (result IN ('pass', 'fail', 'waived', 'error')),
    -- Violations are the count of denials: none for a pass or an error, at least one otherwise.
    CONSTRAINT verdict_violations CHECK (
        (result IN ('pass', 'error') AND violations = 0) OR (result IN ('fail', 'waived') AND violations > 0)),
    CONSTRAINT verdict_sys_period_open CHECK (upper(sys_period) IS NULL)
);

CREATE INDEX verdict_recent ON verification.verdict (tenant_id, id DESC);
CREATE INDEX verdict_by_decision ON verification.verdict (tenant_id, decision_id, id DESC);
CREATE INDEX verdict_by_slug ON verification.verdict (tenant_id, slug, id DESC);

CREATE TRIGGER upload_open_sys_period
    BEFORE INSERT ON verification.upload
    FOR EACH ROW EXECUTE FUNCTION registry.open_sys_period();
CREATE TRIGGER verdict_open_sys_period
    BEFORE INSERT ON verification.verdict
    FOR EACH ROW EXECUTE FUNCTION registry.open_sys_period();

ALTER TABLE verification.upload ENABLE ROW LEVEL SECURITY;
ALTER TABLE verification.upload FORCE ROW LEVEL SECURITY;
ALTER TABLE verification.verdict ENABLE ROW LEVEL SECURITY;
ALTER TABLE verification.verdict FORCE ROW LEVEL SECURITY;

CREATE POLICY app_select ON verification.upload
    FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON verification.upload
    FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_select ON verification.upload
    FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON verification.upload
    FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_insert ON verification.upload
    FOR INSERT TO ipso_migrate
    WITH CHECK (tenant_id = ipso.current_tenant());

CREATE POLICY app_select ON verification.verdict
    FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON verification.verdict
    FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_select ON verification.verdict
    FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON verification.verdict
    FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_insert ON verification.verdict
    FOR INSERT TO ipso_migrate
    WITH CHECK (tenant_id = ipso.current_tenant());

GRANT USAGE ON SCHEMA verification TO ipso_app;
GRANT SELECT, INSERT ON verification.upload TO ipso_app;
GRANT SELECT, INSERT ON verification.verdict TO ipso_app;
