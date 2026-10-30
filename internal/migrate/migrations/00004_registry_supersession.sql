-- +goose Up
-- Supersession and grandfathering, section 2.3 of the specification and ADR-0052.
-- Recording a supersession closes the old decision in this same transaction. A grandfather
-- period says how long a baseline applies, and a baseline is recorded once per decision
-- and repository. Row-level security policies on these tables ship with IPSO-61, not here.
-- The tables carry tenant_id, so the criteria already on IPSO-61 cover them.

-- One successor per decision. from_decision and to_decision are decision ids, not rows:
-- decision_version has no row id that stays put, because a correction replaces the row.
CREATE TABLE registry.supersession (
    tenant_id     uuid        NOT NULL,
    id            uuid        NOT NULL DEFAULT uuidv7(),
    from_decision uuid        NOT NULL,
    to_decision   uuid        NOT NULL,
    effective_at  timestamptz NOT NULL,
    sys_period    tstzrange   NOT NULL DEFAULT tstzrange(clock_timestamp(), NULL),
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT supersession_one_successor UNIQUE (tenant_id, from_decision),
    CONSTRAINT supersession_not_self CHECK (from_decision <> to_decision),
    CONSTRAINT supersession_effective_finite CHECK (isfinite(effective_at)),
    CONSTRAINT supersession_sys_period_open CHECK (upper(sys_period) IS NULL)
);

-- The terms under which one decision grandfathers existing violations. No row means no
-- grandfathering, so no baseline can be recorded. An unbounded end is a baseline with no
-- deadline. A finite end is the deadline.
CREATE TABLE registry.grandfather_period (
    tenant_id    uuid      NOT NULL,
    decision_id  uuid      NOT NULL,
    valid_period tstzrange NOT NULL,
    sys_period   tstzrange NOT NULL DEFAULT tstzrange(clock_timestamp(), NULL),
    PRIMARY KEY (tenant_id, decision_id),
    -- isfinite of a missing bound is NULL, and a CHECK treats NULL as success, so an
    -- unbounded start is refused with lower_inf rather than with isfinite alone.
    CONSTRAINT grandfather_period_bounds CHECK (
        NOT isempty(valid_period)
        AND NOT lower_inf(valid_period)
        AND isfinite(lower(valid_period))
        AND (upper_inf(valid_period) OR isfinite(upper(valid_period)))),
    CONSTRAINT grandfather_period_sys_period_open CHECK (upper(sys_period) IS NULL)
);

-- The fingerprints of violations that already existed, for one decision and one repository.
-- They live in the row so a later insert cannot add one. The literal repo grammar is the
-- one in internal/registry/selector.go, and a test requires the two to agree.
CREATE TABLE registry.baseline (
    tenant_id    uuid      NOT NULL,
    id           uuid      NOT NULL DEFAULT uuidv7(),
    decision_id  uuid      NOT NULL,
    repo         text      NOT NULL,
    fingerprints bytea[]   NOT NULL,
    sys_period   tstzrange NOT NULL DEFAULT tstzrange(clock_timestamp(), NULL),
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT baseline_one_per_repo UNIQUE (tenant_id, decision_id, repo),
    CONSTRAINT baseline_period FOREIGN KEY (tenant_id, decision_id)
        REFERENCES registry.grandfather_period (tenant_id, decision_id),
    CONSTRAINT baseline_sys_period_open CHECK (upper(sys_period) IS NULL),
    CONSTRAINT baseline_repo CHECK (
        char_length(repo) <= 255
        AND repo ~ '^[a-z0-9][a-z0-9._-]{0,62}(/[a-z0-9._-]{1,100}){1,10}$'
        AND repo !~ '(^|/)\.{1,2}(/|$)'),
    CONSTRAINT baseline_fingerprints_bound CHECK (
        cardinality(fingerprints) <= 100000
        AND array_position(fingerprints, NULL) IS NULL)
);

-- The caller cannot backdate transaction time. One function serves the three tables, and
-- each of them has a sys_period column. search_path is fixed so a caller cannot redirect
-- an unqualified name. The function needs no privilege beyond the insert itself.
-- +goose StatementBegin
CREATE FUNCTION registry.open_sys_period() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    NEW.sys_period := tstzrange(clock_timestamp(), NULL);
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

-- The rules a supersession has to pass before the row exists. The lock and the reads are
-- separate statements on purpose. In READ COMMITTED each statement of a function takes a
-- new snapshot, so a check that ran in the same statement as the lock would keep the
-- snapshot from before the wait and could miss a supersession that committed while this
-- one waited. Two such writes can form a cycle. REPEATABLE READ keeps one snapshot for
-- the transaction, so the same wait would not help, and the insert is refused. SERIALIZABLE
-- keeps one snapshot too, and PostgreSQL aborts one of the two writes itself.
-- The lock is per tenant, so supersessions of one tenant run one at a time. A collision of
-- the hash only adds waiting. It cannot let a cycle through.
-- +goose StatementBegin
CREATE FUNCTION registry.supersession_check() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF current_setting('transaction_isolation') = 'repeatable read' THEN
        RAISE EXCEPTION 'a supersession cannot be recorded in a repeatable read transaction'
            USING ERRCODE = 'feature_not_supported';
    END IF;
    -- Held until this transaction ends. The reads below must stay in later statements.
    PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id::text, 24));

    IF NOT isfinite(NEW.effective_at) THEN
        RAISE EXCEPTION 'effective_at must be finite' USING ERRCODE = 'check_violation';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM registry.decision_version d
        WHERE d.tenant_id = NEW.tenant_id
          AND d.decision_id = NEW.from_decision
          AND (lower_inf(d.valid_period) OR lower(d.valid_period) <= NEW.effective_at)
    ) THEN
        RAISE EXCEPTION 'the superseded decision has no current row that starts at or before effective_at'
            USING ERRCODE = 'check_violation';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM registry.decision_version d
        WHERE d.tenant_id = NEW.tenant_id
          AND d.decision_id = NEW.to_decision
          AND d.valid_period @> NEW.effective_at
    ) THEN
        RAISE EXCEPTION 'the successor does not cover effective_at'
            USING ERRCODE = 'check_violation';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM registry.supersession s
        WHERE s.tenant_id = NEW.tenant_id
          AND s.from_decision = NEW.to_decision
    ) THEN
        RAISE EXCEPTION 'the successor is already superseded'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

-- Closes the old decision at effective_at. A row that starts then or later is deleted.
-- A row that runs past the instant is trimmed with range subtraction, which only removes
-- the tail, so two current rows that did not overlap still do not. Deleting first matters:
-- subtracting a range that contains the whole row yields an empty range, and an empty
-- valid period would stay in the table. The archive trigger on decision_version records
-- the previous belief, so a query as known before this insert still returns the old decision.
-- +goose StatementBegin
CREATE FUNCTION registry.supersession_close() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    DELETE FROM registry.decision_version d
    WHERE d.tenant_id = NEW.tenant_id
      AND d.decision_id = NEW.from_decision
      AND NOT lower_inf(d.valid_period)
      AND lower(d.valid_period) >= NEW.effective_at;

    UPDATE registry.decision_version d
    SET valid_period = d.valid_period - tstzrange(NEW.effective_at, NULL, '[)')
    WHERE d.tenant_id = NEW.tenant_id
      AND d.decision_id = NEW.from_decision
      AND d.valid_period && tstzrange(NEW.effective_at, NULL, '[)');
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

-- Each fingerprint is 32 bytes and none is repeated. The cardinality and NULL checks are
-- also a CHECK constraint, so they hold when the triggers are off. The length and the
-- distinctness need a walk of the array. The cardinality is refused before that walk, so
-- a huge array is not expanded. Repeats include an occurrence number, so two copies of
-- one digest would waive one violation twice.
-- +goose StatementBegin
CREATE FUNCTION registry.baseline_check_fingerprints() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF cardinality(NEW.fingerprints) > 100000 THEN
        RAISE EXCEPTION 'a baseline holds more than 100000 fingerprints'
            USING ERRCODE = 'check_violation';
    END IF;
    IF array_position(NEW.fingerprints, NULL) IS NOT NULL THEN
        RAISE EXCEPTION 'a fingerprint is null' USING ERRCODE = 'check_violation';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM unnest(NEW.fingerprints) AS f(v)
        WHERE octet_length(v) <> 32
    ) THEN
        RAISE EXCEPTION 'a fingerprint must be 32 bytes' USING ERRCODE = 'check_violation';
    END IF;
    IF (SELECT count(DISTINCT v) FROM unnest(NEW.fingerprints) AS f(v))
        IS DISTINCT FROM cardinality(NEW.fingerprints) THEN
        RAISE EXCEPTION 'a baseline holds a repeated fingerprint'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION registry.open_sys_period() FROM PUBLIC;
REVOKE ALL ON FUNCTION registry.supersession_check() FROM PUBLIC;
REVOKE ALL ON FUNCTION registry.supersession_close() FROM PUBLIC;
REVOKE ALL ON FUNCTION registry.baseline_check_fingerprints() FROM PUBLIC;

CREATE TRIGGER supersession_check
    BEFORE INSERT ON registry.supersession
    FOR EACH ROW EXECUTE FUNCTION registry.supersession_check();

CREATE TRIGGER supersession_open_sys_period
    BEFORE INSERT ON registry.supersession
    FOR EACH ROW EXECUTE FUNCTION registry.open_sys_period();

CREATE TRIGGER supersession_close
    AFTER INSERT ON registry.supersession
    FOR EACH ROW EXECUTE FUNCTION registry.supersession_close();

CREATE TRIGGER grandfather_period_open_sys_period
    BEFORE INSERT ON registry.grandfather_period
    FOR EACH ROW EXECUTE FUNCTION registry.open_sys_period();

CREATE TRIGGER baseline_open_sys_period
    BEFORE INSERT ON registry.baseline
    FOR EACH ROW EXECUTE FUNCTION registry.open_sys_period();

CREATE TRIGGER baseline_fingerprints
    BEFORE INSERT ON registry.baseline
    FOR EACH ROW EXECUTE FUNCTION registry.baseline_check_fingerprints();

-- The application role records a supersession, a grandfather period, and a baseline, and
-- it can read them back. It cannot change or remove one, so a baseline cannot grow and a
-- closed decision cannot be reopened by editing the row.
GRANT SELECT, INSERT ON registry.supersession TO ipso_app;
GRANT SELECT, INSERT ON registry.grandfather_period TO ipso_app;
GRANT SELECT, INSERT ON registry.baseline TO ipso_app;
