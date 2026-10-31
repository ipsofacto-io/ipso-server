-- +goose Up
-- Premise evaluations, review reasons, clearances, and the tenant host allowlist.
-- Section 2.1 and section 2.3 of the specification and ADR-0053. The four tables
-- are insert-only. A BEFORE INSERT trigger sets sys_period, so a caller cannot
-- backdate it. Row-level security ships with IPSO-61. The tables carry tenant_id,
-- so the criteria already on that issue cover them. No endpoint writes these rows.
-- The writer inserts a reason for a fail. This file does not invent one.

-- One probe result. The response body is not stored. Pass and fail keep the
-- observed JSON and a 32-byte digest. An error may omit both. Expected and
-- observed JSON are each at most 1024 bytes of text. The URL is https, with no
-- userinfo, no fragment, and no address as the host.
CREATE TABLE registry.premise_evaluation (
    tenant_id    uuid      NOT NULL,
    id           uuid      NOT NULL DEFAULT uuidv7(),
    decision_id  uuid      NOT NULL,
    premise_id   text      NOT NULL,
    result       text      NOT NULL,
    url          text      NOT NULL,
    pointer      text      NOT NULL,
    expected     jsonb     NOT NULL,
    observed     jsonb,
    body_sha256  bytea,
    sys_period   tstzrange NOT NULL DEFAULT tstzrange(clock_timestamp(), NULL),
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT premise_evaluation_result CHECK (result IN ('pass', 'fail', 'error')),
    CONSTRAINT premise_evaluation_premise_id CHECK (
        premise_id ~ '^[a-z0-9]+(-[a-z0-9]+)*$'),
    CONSTRAINT premise_evaluation_url CHECK (
        char_length(url) BETWEEN 1 AND 2048
        AND url ~ '^https://[^[:space:]/:@?#]+(:443)?([/?][^[:space:]#]*)?$'
        AND url !~ '^https://[0-9.]+(:443)?([/?][^[:space:]#]*)?$'),
    CONSTRAINT premise_evaluation_pointer CHECK (
        pointer ~ '^(/([^/~]|~[01])*)*$'),
    CONSTRAINT premise_evaluation_json_size CHECK (
        octet_length(expected::text) <= 1024
        AND (
            (result = 'error' AND (observed IS NULL OR octet_length(observed::text) <= 1024))
            OR (result IN ('pass', 'fail')
                AND observed IS NOT NULL
                AND octet_length(observed::text) <= 1024))),
    CONSTRAINT premise_evaluation_hash CHECK (
        (result = 'error' AND (body_sha256 IS NULL OR octet_length(body_sha256) = 32))
        OR (result IN ('pass', 'fail') AND body_sha256 IS NOT NULL AND octet_length(body_sha256) = 32)),
    CONSTRAINT premise_evaluation_sys_period_open CHECK (upper(sys_period) IS NULL)
);

CREATE INDEX premise_evaluation_by_premise
    ON registry.premise_evaluation (tenant_id, decision_id, premise_id);

-- An open fail for one premise. Open means no clearance row. A later fail can
-- open another reason once the earlier one is cleared, so the key is not unique
-- on the premise. The trigger refuses a second reason that is still open.
CREATE TABLE registry.premise_reason (
    tenant_id     uuid      NOT NULL,
    id            uuid      NOT NULL DEFAULT uuidv7(),
    decision_id   uuid      NOT NULL,
    premise_id    text      NOT NULL,
    evaluation_id uuid      NOT NULL,
    sys_period    tstzrange NOT NULL DEFAULT tstzrange(clock_timestamp(), NULL),
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT premise_reason_evaluation FOREIGN KEY (tenant_id, evaluation_id)
        REFERENCES registry.premise_evaluation (tenant_id, id),
    CONSTRAINT premise_reason_premise_id CHECK (
        premise_id ~ '^[a-z0-9]+(-[a-z0-9]+)*$'),
    CONSTRAINT premise_reason_sys_period_open CHECK (upper(sys_period) IS NULL)
);

CREATE INDEX premise_reason_by_premise
    ON registry.premise_reason (tenant_id, decision_id, premise_id);

-- One insert closes one reason. human is a person. premise-removed is the
-- version update that dropped the id. A second clearance of the same reason
-- conflicts with premise_clearance_reason.
CREATE TABLE registry.premise_clearance (
    tenant_id  uuid      NOT NULL,
    id         uuid      NOT NULL DEFAULT uuidv7(),
    reason_id  uuid      NOT NULL,
    kind       text      NOT NULL,
    sys_period tstzrange NOT NULL DEFAULT tstzrange(clock_timestamp(), NULL),
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT premise_clearance_reason UNIQUE (tenant_id, reason_id),
    CONSTRAINT premise_clearance_reason_fk FOREIGN KEY (tenant_id, reason_id)
        REFERENCES registry.premise_reason (tenant_id, id),
    CONSTRAINT premise_clearance_kind CHECK (kind IN ('human', 'premise-removed')),
    CONSTRAINT premise_clearance_sys_period_open CHECK (upper(sys_period) IS NULL)
);

-- Append-only. The latest row for a host is the greatest lower(sys_period),
-- then the greatest id. An empty table allows no host. The worker that reads
-- this is a later issue. The prepare trigger stores the host in lowercase, and
-- the check below sees that value.
CREATE TABLE registry.premise_host_allow (
    tenant_id  uuid      NOT NULL,
    id         uuid      NOT NULL DEFAULT uuidv7(),
    host       text      NOT NULL,
    allowed    boolean   NOT NULL,
    sys_period tstzrange NOT NULL DEFAULT tstzrange(clock_timestamp(), NULL),
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT premise_host_allow_host CHECK (
        char_length(host) BETWEEN 1 AND 253
        AND host = lower(host)
        AND host ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'
        AND host !~ '^[0-9.]+$'),
    CONSTRAINT premise_host_allow_sys_period_open CHECK (upper(sys_period) IS NULL)
);

CREATE INDEX premise_host_allow_by_host
    ON registry.premise_host_allow (tenant_id, host);

-- Ids on a decision body. A missing key or a JSON null means none. Any other
-- value that is not an array is refused, so a bad body cannot hide a drop.
-- The triggers call this as the session user, so that role can execute it.
-- search_path is fixed so a caller cannot redirect an unqualified name.
-- +goose StatementBegin
CREATE FUNCTION registry.premise_ids(body jsonb) RETURNS text[]
    LANGUAGE plpgsql
    STABLE
    SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    premises jsonb := body -> 'premises';
    ids      text[];
BEGIN
    IF premises IS NULL OR jsonb_typeof(premises) = 'null' THEN
        RETURN ARRAY[]::text[];
    END IF;
    IF jsonb_typeof(premises) <> 'array' THEN
        RAISE EXCEPTION 'premises is not an array'
            USING ERRCODE = 'check_violation';
    END IF;
    SELECT coalesce(array_agg(e.item ->> 'id' ORDER BY e.item ->> 'id'), ARRAY[]::text[])
        INTO ids
    FROM jsonb_array_elements(premises) AS e(item)
    WHERE jsonb_typeof(e.item) = 'object'
      AND (e.item ->> 'id') IS NOT NULL;
    RETURN ids;
END;
$$;
-- +goose StatementEnd

-- The premise has to be on a current row of this tenant and decision. A check
-- cannot see that row. Pass and error do not open or clear a reason.
-- +goose StatementBegin
CREATE FUNCTION registry.premise_evaluation_check() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    -- Same lock as a reason insert, so the reason sees this evaluation after it commits.
    PERFORM pg_advisory_xact_lock(hashtextextended(
        NEW.tenant_id::text || '/' || NEW.decision_id::text || '/' || NEW.premise_id, 53));
    IF NOT EXISTS (
        SELECT 1
        FROM registry.decision_version d
        WHERE d.tenant_id = NEW.tenant_id
          AND d.decision_id = NEW.decision_id
          AND NEW.premise_id = ANY (registry.premise_ids(d.body))
    ) THEN
        RAISE EXCEPTION 'the premise is not on a current version'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

-- One open reason per tenant, decision, and premise. The lock and the read are
-- separate statements on purpose. In READ COMMITTED the read after the wait sees
-- a reason that committed while this one waited. REPEATABLE READ would keep the
-- snapshot from before the wait, so that insert is refused. A hash collision
-- only adds waiting. Seed 53 is not the supersession lock.
-- The evaluation has to be a fail of this same premise. A pass does not open one.
-- +goose StatementBegin
CREATE FUNCTION registry.premise_reason_check() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF current_setting('transaction_isolation') = 'repeatable read' THEN
        RAISE EXCEPTION 'a premise reason cannot be recorded in a repeatable read transaction'
            USING ERRCODE = 'feature_not_supported';
    END IF;
    -- Held until this transaction ends. The reads stay below it. Seed 53 is not
    -- the supersession lock. An evaluation insert takes the same lock.
    PERFORM pg_advisory_xact_lock(hashtextextended(
        NEW.tenant_id::text || '/' || NEW.decision_id::text || '/' || NEW.premise_id, 53));
    IF NOT EXISTS (
        SELECT 1
        FROM registry.premise_evaluation e
        WHERE e.tenant_id = NEW.tenant_id
          AND e.id = NEW.evaluation_id
          AND e.decision_id = NEW.decision_id
          AND e.premise_id = NEW.premise_id
          AND e.result = 'fail'
    ) THEN
        RAISE EXCEPTION 'the reason does not name a fail of this premise'
            USING ERRCODE = 'check_violation';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM registry.premise_evaluation named
        JOIN registry.premise_evaluation later
          ON later.tenant_id = named.tenant_id
         AND later.decision_id = named.decision_id
         AND later.premise_id = named.premise_id
         AND (lower(later.sys_period), later.id) > (lower(named.sys_period), named.id)
        WHERE named.tenant_id = NEW.tenant_id
          AND named.id = NEW.evaluation_id
    ) THEN
        RAISE EXCEPTION 'the reason does not name the latest evaluation'
            USING ERRCODE = 'check_violation';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM registry.decision_version d
        WHERE d.tenant_id = NEW.tenant_id
          AND d.decision_id = NEW.decision_id
          AND NEW.premise_id = ANY (registry.premise_ids(d.body))
    ) THEN
        RAISE EXCEPTION 'the premise is not on a current version'
            USING ERRCODE = 'check_violation';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM registry.premise_reason r
        WHERE r.tenant_id = NEW.tenant_id
          AND r.decision_id = NEW.decision_id
          AND r.premise_id = NEW.premise_id
          AND NOT EXISTS (
              SELECT 1
              FROM registry.premise_clearance c
              WHERE c.tenant_id = r.tenant_id
                AND c.reason_id = r.id)
    ) THEN
        RAISE EXCEPTION 'a premise reason is already open'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

-- premise-removed is only true once no current row of the decision still carries
-- the id. A human clearance does not need the premise to be gone.
-- +goose StatementBegin
CREATE FUNCTION registry.premise_clearance_check() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF NEW.kind = 'premise-removed' AND EXISTS (
        SELECT 1
        FROM registry.premise_reason r
        JOIN registry.decision_version d
          ON d.tenant_id = r.tenant_id
         AND d.decision_id = r.decision_id
        WHERE r.tenant_id = NEW.tenant_id
          AND r.id = NEW.reason_id
          AND r.premise_id = ANY (registry.premise_ids(d.body))
    ) THEN
        RAISE EXCEPTION 'the premise is still on a current version'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

-- The caller cannot choose the casing of a host. The check constraint then
-- requires a lowercase DNS name.
-- +goose StatementBegin
CREATE FUNCTION registry.premise_host_allow_prepare() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    NEW.host := lower(NEW.host);
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

-- A version write that drops a premise id clears that premise's open reason in
-- this same statement. Another current row that still has the id keeps it. A
-- clearance that already exists conflicts and is left as it is, so a human
-- clearance does not abort the version write. Deleting a version does not clear
-- a reason. One UPDATE of two current rows of the same decision can see a row
-- this statement has not rewritten yet. Callers update one row.
-- +goose StatementBegin
CREATE FUNCTION registry.decision_version_clear_premise() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    old_ids       text[];
    still         text[];
    prior         jsonb := OLD.body -> 'premises';
    next_premises jsonb := NEW.body -> 'premises';
BEGIN
    IF prior IS NOT DISTINCT FROM next_premises THEN
        RETURN NULL;
    END IF;
    -- Replacing the field with a non-array is refused. Leaving a non-array
    -- unchanged is the equality check above, and a non-array old value has no
    -- ids to clear, so a later update can still replace it with an array.
    IF next_premises IS NOT NULL AND jsonb_typeof(next_premises) NOT IN ('null', 'array') THEN
        RAISE EXCEPTION 'premises is not an array'
            USING ERRCODE = 'check_violation';
    END IF;
    IF prior IS NULL OR jsonb_typeof(prior) IN ('null', 'array') THEN
        old_ids := registry.premise_ids(OLD.body);
    ELSE
        old_ids := ARRAY[]::text[];
    END IF;
    IF cardinality(old_ids) = 0 THEN
        RETURN NULL;
    END IF;
    SELECT coalesce(array_agg(DISTINCT pid), ARRAY[]::text[])
        INTO still
    FROM registry.decision_version d
    CROSS JOIN LATERAL unnest(registry.premise_ids(d.body)) AS u(pid)
    WHERE d.tenant_id = NEW.tenant_id
      AND d.decision_id = NEW.decision_id;

    INSERT INTO registry.premise_clearance (tenant_id, reason_id, kind)
    SELECT r.tenant_id, r.id, 'premise-removed'
    FROM registry.premise_reason r
    WHERE r.tenant_id = NEW.tenant_id
      AND r.decision_id = NEW.decision_id
      AND r.premise_id = ANY (old_ids)
      AND NOT (r.premise_id = ANY (still))
      AND NOT EXISTS (
          SELECT 1
          FROM registry.premise_clearance c
          WHERE c.tenant_id = r.tenant_id
            AND c.reason_id = r.id)
    ON CONFLICT ON CONSTRAINT premise_clearance_reason DO NOTHING;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION registry.premise_ids(jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION registry.premise_evaluation_check() FROM PUBLIC;
REVOKE ALL ON FUNCTION registry.premise_reason_check() FROM PUBLIC;
REVOKE ALL ON FUNCTION registry.premise_clearance_check() FROM PUBLIC;
REVOKE ALL ON FUNCTION registry.premise_host_allow_prepare() FROM PUBLIC;
REVOKE ALL ON FUNCTION registry.decision_version_clear_premise() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION registry.premise_ids(jsonb) TO ipso_app;

CREATE TRIGGER premise_evaluation_check
    BEFORE INSERT ON registry.premise_evaluation
    FOR EACH ROW EXECUTE FUNCTION registry.premise_evaluation_check();

CREATE TRIGGER premise_evaluation_open_sys_period
    BEFORE INSERT ON registry.premise_evaluation
    FOR EACH ROW EXECUTE FUNCTION registry.open_sys_period();

CREATE TRIGGER premise_reason_check
    BEFORE INSERT ON registry.premise_reason
    FOR EACH ROW EXECUTE FUNCTION registry.premise_reason_check();

CREATE TRIGGER premise_reason_open_sys_period
    BEFORE INSERT ON registry.premise_reason
    FOR EACH ROW EXECUTE FUNCTION registry.open_sys_period();

CREATE TRIGGER premise_clearance_check
    BEFORE INSERT ON registry.premise_clearance
    FOR EACH ROW EXECUTE FUNCTION registry.premise_clearance_check();

CREATE TRIGGER premise_clearance_open_sys_period
    BEFORE INSERT ON registry.premise_clearance
    FOR EACH ROW EXECUTE FUNCTION registry.open_sys_period();

CREATE TRIGGER premise_host_allow_prepare
    BEFORE INSERT ON registry.premise_host_allow
    FOR EACH ROW EXECUTE FUNCTION registry.premise_host_allow_prepare();

CREATE TRIGGER premise_host_allow_open_sys_period
    BEFORE INSERT ON registry.premise_host_allow
    FOR EACH ROW EXECUTE FUNCTION registry.open_sys_period();

CREATE TRIGGER decision_version_clear_premise
    AFTER UPDATE ON registry.decision_version
    FOR EACH ROW EXECUTE FUNCTION registry.decision_version_clear_premise();

-- The application role records these rows and can read them back. It cannot
-- change or remove one, so a result cannot be edited into a pass and a
-- clearance cannot be taken back.
GRANT SELECT, INSERT ON registry.premise_evaluation TO ipso_app;
GRANT SELECT, INSERT ON registry.premise_reason TO ipso_app;
GRANT SELECT, INSERT ON registry.premise_clearance TO ipso_app;
GRANT SELECT, INSERT ON registry.premise_host_allow TO ipso_app;
