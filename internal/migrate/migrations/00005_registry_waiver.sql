-- +goose Up
-- Scoped waivers and their expiry notices, section 2.1 and section 2.3 of the
-- specification and ADR-0054. A waiver is insert-only. It applies only while its
-- period and a current decision row both cover the valid time. Notices are rows
-- addressed by ticket_ref. Row-level security on these tables ships with IPSO-61.
-- The tables carry tenant_id, so the criteria already on IPSO-61 cover them.

-- One exception for one decision and one scope. The period is half-open and at
-- most 90 days of elapsed time. The scope has to be one the decision already
-- names, or a descendant of one, which waiver_check enforces. A CHECK cannot see
-- the other row.
CREATE TABLE registry.waiver (
    tenant_id    uuid      NOT NULL,
    id           uuid      NOT NULL DEFAULT uuidv7(),
    decision_id  uuid      NOT NULL,
    scope_id     uuid      NOT NULL,
    reason       text      NOT NULL,
    approver     text      NOT NULL,
    valid_period tstzrange NOT NULL,
    ticket_ref   text      NOT NULL,
    sys_period   tstzrange NOT NULL DEFAULT tstzrange(clock_timestamp(), NULL),
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT waiver_scope FOREIGN KEY (tenant_id, scope_id)
        REFERENCES registry.scope (tenant_id, id),
    CONSTRAINT waiver_sys_period_open CHECK (upper(sys_period) IS NULL),
    CONSTRAINT waiver_bounds CHECK (
        NOT isempty(valid_period)
        AND NOT lower_inf(valid_period)
        AND NOT upper_inf(valid_period)
        AND isfinite(lower(valid_period))
        AND isfinite(upper(valid_period))
        AND lower_inc(valid_period)
        AND NOT upper_inc(valid_period)
        AND upper(valid_period) - lower(valid_period) <= interval '90 days'),
    CONSTRAINT waiver_reason CHECK (
        char_length(reason) BETWEEN 1 AND 2000
        AND btrim(reason) = reason
        AND reason !~ '[[:cntrl:]]'),
    CONSTRAINT waiver_approver CHECK (
        char_length(approver) BETWEEN 1 AND 200
        AND btrim(approver) = approver
        AND approver !~ '[[:cntrl:]]'),
    CONSTRAINT waiver_ticket_ref CHECK (
        char_length(ticket_ref) BETWEEN 1 AND 200
        AND btrim(ticket_ref) = ticket_ref
        AND ticket_ref !~ '[[:cntrl:]]')
);

CREATE INDEX waiver_by_decision ON registry.waiver (tenant_id, decision_id);

-- One row per offset that has come due. The sweep and a direct insert share
-- waiver_notice_check, so an early notice cannot be written around the sweep.
CREATE TABLE registry.waiver_notice (
    tenant_id   uuid      NOT NULL,
    id          uuid      NOT NULL DEFAULT uuidv7(),
    waiver_id   uuid      NOT NULL,
    days_before integer   NOT NULL,
    ticket_ref  text      NOT NULL,
    sys_period  tstzrange NOT NULL DEFAULT tstzrange(clock_timestamp(), NULL),
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT waiver_notice_once UNIQUE (tenant_id, waiver_id, days_before),
    CONSTRAINT waiver_notice_waiver FOREIGN KEY (tenant_id, waiver_id)
        REFERENCES registry.waiver (tenant_id, id),
    CONSTRAINT waiver_notice_days CHECK (days_before IN (14, 3, 0)),
    CONSTRAINT waiver_notice_sys_period_open CHECK (upper(sys_period) IS NULL),
    CONSTRAINT waiver_notice_ticket_ref CHECK (
        char_length(ticket_ref) BETWEEN 1 AND 200
        AND btrim(ticket_ref) = ticket_ref
        AND ticket_ref !~ '[[:cntrl:]]')
);

-- The waiver has to sit inside one current decision row, and its scope has to be
-- that row's scope or a descendant. A closure row is required, so a damaged
-- closure cannot attach the waiver. search_path is fixed so a caller cannot
-- redirect an unqualified name. The function needs no privilege beyond the insert.
-- +goose StatementBegin
CREATE FUNCTION registry.waiver_check() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    refs uuid[];
BEGIN
    SELECT d.scope_refs INTO refs
    FROM registry.decision_version d
    WHERE d.tenant_id = NEW.tenant_id
      AND d.decision_id = NEW.decision_id
      AND d.valid_period @> NEW.valid_period;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'a waiver extends beyond the decision'
            USING ERRCODE = 'check_violation';
    END IF;

    IF NOT EXISTS (
        SELECT 1
        FROM registry.scope_closure c
        WHERE c.tenant_id = NEW.tenant_id
          AND c.descendant_id = NEW.scope_id
          AND c.ancestor_id = ANY (refs)
    ) THEN
        RAISE EXCEPTION 'the waiver scope is outside the decision'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

-- Copies ticket_ref from the waiver and refuses a notice that is early, for a
-- waiver the current decision no longer contains, or for an offset the waiver is
-- too short to have. The due rule here and the one in record_waiver_notices are
-- the same predicate. A change to one has to change the other.
-- +goose StatementBegin
CREATE FUNCTION registry.waiver_notice_check() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    starts_at timestamptz;
    ends_at   timestamptz;
    ref       text;
    threshold timestamptz;
BEGIN
    SELECT lower(w.valid_period), upper(w.valid_period), w.ticket_ref
        INTO starts_at, ends_at, ref
    FROM registry.waiver w
    WHERE w.tenant_id = NEW.tenant_id
      AND w.id = NEW.waiver_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'the notice names no waiver'
            USING ERRCODE = 'foreign_key_violation';
    END IF;

    -- The caller cannot point the notice at a different ticket.
    NEW.ticket_ref := ref;

    IF NOT EXISTS (
        SELECT 1
        FROM registry.decision_version d
        JOIN registry.waiver w
          ON w.tenant_id = d.tenant_id
         AND w.decision_id = d.decision_id
        WHERE w.tenant_id = NEW.tenant_id
          AND w.id = NEW.waiver_id
          AND d.valid_period @> w.valid_period
    ) THEN
        RAISE EXCEPTION 'the waiver is outside the decision'
            USING ERRCODE = 'check_violation';
    END IF;

    threshold := ends_at - make_interval(days => NEW.days_before);
    IF starts_at > threshold THEN
        RAISE EXCEPTION 'the waiver is shorter than the notice'
            USING ERRCODE = 'check_violation';
    END IF;
    IF clock_timestamp() < threshold THEN
        RAISE EXCEPTION 'the notice is early'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

-- Inserts each due notice for the tenant in ipso.tenant. No setting inserts
-- nothing. The database clock decides what is due, so the caller cannot pass a
-- future time. A second call inserts nothing. Returns the number of new rows.
-- +goose StatementBegin
CREATE FUNCTION registry.record_waiver_notices() RETURNS integer
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    inserted integer;
BEGIN
    INSERT INTO registry.waiver_notice (tenant_id, waiver_id, days_before, ticket_ref)
    SELECT w.tenant_id, w.id, d.days, w.ticket_ref
    FROM registry.waiver w
    CROSS JOIN (VALUES (14), (3), (0)) AS d(days)
    WHERE w.tenant_id = nullif(current_setting('ipso.tenant', true), '')::uuid
      AND EXISTS (
          SELECT 1
          FROM registry.decision_version dv
          WHERE dv.tenant_id = w.tenant_id
            AND dv.decision_id = w.decision_id
            AND dv.valid_period @> w.valid_period)
      AND lower(w.valid_period) <= upper(w.valid_period) - make_interval(days => d.days)
      AND clock_timestamp() >= upper(w.valid_period) - make_interval(days => d.days)
    ON CONFLICT ON CONSTRAINT waiver_notice_once DO NOTHING;

    GET DIAGNOSTICS inserted = ROW_COUNT;
    RETURN inserted;
END;
$$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION registry.waiver_check() FROM PUBLIC;
REVOKE ALL ON FUNCTION registry.waiver_notice_check() FROM PUBLIC;
REVOKE ALL ON FUNCTION registry.record_waiver_notices() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION registry.record_waiver_notices() TO ipso_app;

CREATE TRIGGER waiver_check
    BEFORE INSERT ON registry.waiver
    FOR EACH ROW EXECUTE FUNCTION registry.waiver_check();

CREATE TRIGGER waiver_open_sys_period
    BEFORE INSERT ON registry.waiver
    FOR EACH ROW EXECUTE FUNCTION registry.open_sys_period();

CREATE TRIGGER waiver_notice_check
    BEFORE INSERT ON registry.waiver_notice
    FOR EACH ROW EXECUTE FUNCTION registry.waiver_notice_check();

CREATE TRIGGER waiver_notice_open_sys_period
    BEFORE INSERT ON registry.waiver_notice
    FOR EACH ROW EXECUTE FUNCTION registry.open_sys_period();

-- The application role records a waiver and can read it back. It cannot change
-- or remove one, so an approval cannot be edited in place. It can insert a
-- notice, and the notice trigger refuses one that is not due.
GRANT SELECT, INSERT ON registry.waiver TO ipso_app;
GRANT SELECT, INSERT ON registry.waiver_notice TO ipso_app;
