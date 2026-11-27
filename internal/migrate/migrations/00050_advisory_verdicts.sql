-- +goose Up
-- Advisory verdicts of llm-advisory checks on pull requests (IPSO-160, ADR-0173).
--
-- A tenant names the repositories whose pull requests may send diff hunks to a model. The list is the
-- only switch: an empty list sends nothing. Each entry is a lowercase owner/name, as verification.upload
-- stores a repository.
--
-- An advisory verdict is what a model said about one llm-advisory check of one decision version on one
-- head commit of a pull request. Its result is always advisory and its mode always advise: the columns
-- default to those values and a CHECK refuses any other, so no code path can store a pass, a fail or a
-- block from this engine (ADR-0005, ADR-0152 decision 5). The table is apart from verification.verdict,
-- which holds CI reports, so health, audit and the merge gate never read an advisory verdict.
--
-- Unlike verification.verdict, a row names places in the change and holds a reason the model wrote:
-- the reviewer needs both, and IPSO-162 shows them with the AI label. It holds no diff text beyond what
-- the reason of at most 300 characters may quote. The places are built by the server from its own hunks,
-- never from the answer, and the reason passed the plain text filter. No column names a person, though a
-- reason may quote a name from a code comment. The decision id is not a foreign key, because the verification
-- schema reads the registry only through its Go API.
--
-- The table is insert-only for ipso_app, with the policies of every other tenant table, so rls.Check,
-- the isolation suite, the export catalog and the offboard purge cover it with no special case.

ALTER TABLE llm.tenant_policy
    ADD COLUMN advisory_repositories text[] NOT NULL DEFAULT '{}',
    ADD CONSTRAINT tenant_policy_advisory_repositories CHECK (
        cardinality(advisory_repositories) <= 100
        AND array_position(advisory_repositories, NULL) IS NULL
        AND (cardinality(advisory_repositories) = 0 OR array_to_string(advisory_repositories, ',')
            ~ '^[a-z0-9_.-]{1,39}/[a-z0-9_.-]{1,100}(,[a-z0-9_.-]{1,39}/[a-z0-9_.-]{1,100})*$'));

CREATE TABLE verification.advisory_verdict (
    tenant_id        uuid      NOT NULL,
    id               uuid      NOT NULL DEFAULT uuidv7(),
    repository_id    bigint    NOT NULL,
    repo             text      NOT NULL,
    pull_number      integer   NOT NULL,
    head_sha         text      NOT NULL,
    base_sha         text      NOT NULL,
    decision_id      uuid      NOT NULL,
    decision_version integer   NOT NULL,
    check_index      integer   NOT NULL,
    mode             text      NOT NULL DEFAULT 'advise',
    result           text      NOT NULL DEFAULT 'advisory',
    assessment       text      NOT NULL,
    -- The places the answer cites: an array of {path, start_line, end_line} on the head side.
    cited            jsonb     NOT NULL,
    reason           text      NOT NULL,
    model_id         text      NOT NULL,
    prompt_version   text      NOT NULL,
    -- The digest of what was sent, without its random markers, and of the check prompt file at the base
    -- commit when the check names one. A later head that sends the same input reuses the answer.
    input_sha256     bytea     NOT NULL,
    prompt_sha256    bytea,
    sys_period       tstzrange NOT NULL DEFAULT tstzrange(clock_timestamp(), NULL),
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT advisory_verdict_tenant FOREIGN KEY (tenant_id) REFERENCES tenancy.tenant (tenant_id),
    CONSTRAINT advisory_verdict_once UNIQUE (
        tenant_id, repository_id, pull_number, head_sha, decision_id, decision_version, check_index),
    CONSTRAINT advisory_verdict_repository_positive CHECK (repository_id > 0),
    CONSTRAINT advisory_verdict_repo CHECK (
        char_length(repo) <= 140 AND repo ~ '^[a-z0-9_.-]+/[a-z0-9_.-]+$'),
    CONSTRAINT advisory_verdict_pull_number CHECK (pull_number > 0),
    CONSTRAINT advisory_verdict_head_sha CHECK (head_sha ~ '^[0-9a-f]{40}$|^[0-9a-f]{64}$'),
    CONSTRAINT advisory_verdict_base_sha CHECK (base_sha ~ '^[0-9a-f]{40}$|^[0-9a-f]{64}$'),
    CONSTRAINT advisory_verdict_version CHECK (decision_version >= 1),
    CONSTRAINT advisory_verdict_check_index CHECK (check_index >= 0),
    CONSTRAINT advisory_verdict_mode CHECK (mode = 'advise'),
    CONSTRAINT advisory_verdict_result CHECK (result = 'advisory'),
    CONSTRAINT advisory_verdict_assessment CHECK (assessment IN ('complies', 'deviates', 'unclear')),
    CONSTRAINT advisory_verdict_cited CHECK (
        jsonb_typeof(cited) = 'array' AND jsonb_array_length(cited) <= 10 AND octet_length(cited::text) <= 8192
        AND (assessment <> 'deviates' OR jsonb_array_length(cited) >= 1)),
    CONSTRAINT advisory_verdict_reason CHECK (char_length(reason) BETWEEN 1 AND 300 AND reason !~ '[[:cntrl:]]'),
    CONSTRAINT advisory_verdict_model CHECK (char_length(model_id) BETWEEN 1 AND 200 AND model_id !~ '[[:cntrl:]]'),
    CONSTRAINT advisory_verdict_prompt CHECK (
        char_length(prompt_version) BETWEEN 1 AND 100 AND prompt_version !~ '[[:cntrl:]]'),
    CONSTRAINT advisory_verdict_input_sha256 CHECK (octet_length(input_sha256) = 32),
    CONSTRAINT advisory_verdict_prompt_sha256 CHECK (prompt_sha256 IS NULL OR octet_length(prompt_sha256) = 32),
    CONSTRAINT advisory_verdict_sys_period_open CHECK (upper(sys_period) IS NULL)
);

CREATE TRIGGER advisory_verdict_open_sys_period
    BEFORE INSERT ON verification.advisory_verdict
    FOR EACH ROW EXECUTE FUNCTION registry.open_sys_period();

ALTER TABLE verification.advisory_verdict ENABLE ROW LEVEL SECURITY;
ALTER TABLE verification.advisory_verdict FORCE ROW LEVEL SECURITY;

CREATE POLICY app_select ON verification.advisory_verdict FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON verification.advisory_verdict FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_select ON verification.advisory_verdict FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_insert ON verification.advisory_verdict FOR INSERT TO ipso_migrate
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON verification.advisory_verdict FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());

GRANT SELECT, INSERT ON verification.advisory_verdict TO ipso_app;
