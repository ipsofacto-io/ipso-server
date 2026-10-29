-- +goose Up
-- Bitemporal decision versions, section 2.3 of the specification and ADR-0003.
-- Valid time is valid_period. Transaction time is sys_period, set by the triggers below.
-- Row-level security policies and the INSERT policy on the history table for ipso_migrate
-- ship with IPSO-61, not here.

CREATE SCHEMA registry;

CREATE TABLE registry.decision_version (
    decision_id  uuid      NOT NULL,
    version      int       NOT NULL,
    tenant_id    uuid      NOT NULL,
    body         jsonb     NOT NULL,
    scope_refs   uuid[]    NOT NULL,
    valid_period tstzrange NOT NULL,
    sys_period   tstzrange NOT NULL DEFAULT tstzrange(clock_timestamp(), NULL),
    PRIMARY KEY (tenant_id, decision_id, valid_period WITHOUT OVERLAPS),
    CONSTRAINT decision_version_sys_period_open CHECK (upper(sys_period) IS NULL)
);

-- Closed sys_period rows. LIKE copies columns and NOT NULL, not defaults, check constraints,
-- or the primary key. No trigger runs on this table.
CREATE TABLE registry.decision_version_history (LIKE registry.decision_version);

CREATE VIEW registry.decision_version_all
    WITH (security_invoker = true) AS
    SELECT decision_id, version, tenant_id, body, scope_refs, valid_period, sys_period
    FROM registry.decision_version
    UNION ALL
    SELECT decision_id, version, tenant_id, body, scope_refs, valid_period, sys_period
    FROM registry.decision_version_history;

-- Both trigger functions are SECURITY DEFINER and owned by the migration role, which runs
-- this file. search_path is fixed so a caller cannot redirect an unqualified name.

-- A caller cannot backdate transaction time: the insert trigger replaces whatever
-- sys_period the row carries.
-- +goose StatementBegin
CREATE FUNCTION registry.decision_version_open_sys_period() RETURNS trigger
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    NEW.sys_period := tstzrange(clock_timestamp(), NULL);
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

-- An update or a delete archives the old row with sys_period closed at the current time.
-- PostgreSQL writes an update as a new row version, so the result is the section 2.3 shape:
-- the old row sits in the history table, and the current row carries a fresh open sys_period.
-- An update that changes no column records no new belief, so it archives nothing and leaves
-- sys_period alone. A caller that supplies a different sys_period changes a column, so it is
-- archived and the supplied value is replaced like any other.
-- If the clock reads earlier than the row's start, tstzrange raises and the write fails.
-- +goose StatementBegin
CREATE FUNCTION registry.decision_version_archive() RETURNS trigger
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    closed_at timestamptz := clock_timestamp();
BEGIN
    IF TG_OP = 'UPDATE' AND NEW IS NOT DISTINCT FROM OLD THEN
        RETURN NEW;
    END IF;
    INSERT INTO registry.decision_version_history
        (decision_id, version, tenant_id, body, scope_refs, valid_period, sys_period)
    VALUES
        (OLD.decision_id, OLD.version, OLD.tenant_id, OLD.body, OLD.scope_refs, OLD.valid_period,
         tstzrange(lower(OLD.sys_period), closed_at));
    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    NEW.sys_period := tstzrange(closed_at, NULL);
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION registry.decision_version_open_sys_period() FROM PUBLIC;
REVOKE ALL ON FUNCTION registry.decision_version_archive() FROM PUBLIC;

CREATE TRIGGER decision_version_open_sys_period
    BEFORE INSERT ON registry.decision_version
    FOR EACH ROW EXECUTE FUNCTION registry.decision_version_open_sys_period();

CREATE TRIGGER decision_version_archive
    BEFORE UPDATE OR DELETE ON registry.decision_version
    FOR EACH ROW EXECUTE FUNCTION registry.decision_version_archive();

-- The application role reads and changes current rows and can only read history.
-- The install creates ipso_app before the first run, and this file fails closed without it.
GRANT USAGE ON SCHEMA registry TO ipso_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON registry.decision_version TO ipso_app;
GRANT SELECT ON registry.decision_version_history TO ipso_app;
GRANT SELECT ON registry.decision_version_all TO ipso_app;
