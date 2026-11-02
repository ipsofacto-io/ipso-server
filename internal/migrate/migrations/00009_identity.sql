-- +goose Up
-- Who acts: people and AI coding agents, section 3.5 and section 13 of the specification and
-- ADR-0076. An agent is a principal with a human sponsor. It cannot approve a proposal or a
-- waiver, and every entry in the action log names the person responsible. Row-level security on
-- these tables ships with IPSO-61. The tables carry tenant_id, so the criteria already on IPSO-61
-- cover them.
CREATE SCHEMA identity;

-- Insert-only, so a sponsor cannot be swapped after the fact. An agent has a sponsor and a person
-- has none. The sponsor has to be a person in the same tenant: the foreign key holds the tenant,
-- and principal_check holds the kind, because a CHECK cannot see the other row.
CREATE TABLE identity.principal (
    tenant_id  uuid      NOT NULL,
    id         uuid      NOT NULL DEFAULT uuidv7(),
    kind       text      NOT NULL,
    name       text      NOT NULL,
    sponsor_id uuid,
    sys_period tstzrange NOT NULL DEFAULT tstzrange(clock_timestamp(), NULL),
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT principal_sponsor FOREIGN KEY (tenant_id, sponsor_id)
        REFERENCES identity.principal (tenant_id, id),
    CONSTRAINT principal_kind CHECK (kind IN ('human', 'agent')),
    CONSTRAINT principal_sponsor_shape CHECK ((kind = 'agent') = (sponsor_id IS NOT NULL)),
    CONSTRAINT principal_name CHECK (
        char_length(name) BETWEEN 1 AND 200
        AND btrim(name) = name
        AND name !~ '[[:cntrl:]]'),
    CONSTRAINT principal_sys_period_open CHECK (upper(sys_period) IS NULL)
);

-- +goose StatementBegin
CREATE FUNCTION identity.principal_check() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF NEW.sponsor_id IS NOT NULL AND NOT EXISTS (
        SELECT 1
        FROM identity.principal p
        WHERE p.tenant_id = NEW.tenant_id
          AND p.id = NEW.sponsor_id
          AND p.kind = 'human'
    ) THEN
        RAISE EXCEPTION 'an agent sponsor must be a person in the same tenant'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER principal_check
    BEFORE INSERT ON identity.principal
    FOR EACH ROW EXECUTE FUNCTION identity.principal_check();

CREATE TRIGGER principal_open_sys_period
    BEFORE INSERT ON identity.principal
    FOR EACH ROW EXECUTE FUNCTION registry.open_sys_period();

-- Refuses an approver that is not a person. Both tables that record an approval use it, so the
-- rule holds for any writer, not only the ones that remember to ask.
-- +goose StatementBegin
CREATE FUNCTION identity.require_human_approver() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM identity.principal p
        WHERE p.tenant_id = NEW.tenant_id
          AND p.id = NEW.approver_id
          AND p.kind = 'human'
    ) THEN
        RAISE EXCEPTION 'an approver must be a person, and an agent cannot approve or waive'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

-- A waiver names the principal who approved it. NOT NULL, because a nullable column would let a
-- caller skip the rule by leaving it out. Waivers are insert-only, so extending one is a new row
-- and meets the same trigger. No deployment serves a tenant yet (ADR-0050), so the table is empty.
-- approver stays as the text the record shows.
ALTER TABLE registry.waiver
    ADD COLUMN approver_id uuid NOT NULL,
    ADD CONSTRAINT waiver_approver_principal FOREIGN KEY (tenant_id, approver_id)
        REFERENCES identity.principal (tenant_id, id);

CREATE TRIGGER waiver_approver
    BEFORE INSERT ON registry.waiver
    FOR EACH ROW EXECUTE FUNCTION identity.require_human_approver();

-- One outcome for one proposal, by a person. This is the approval table the note in 00008 expects.
-- The route that writes it ships with IPSO-60 and IPSO-66.
CREATE TABLE proposals.approval (
    tenant_id   uuid      NOT NULL,
    id          uuid      NOT NULL DEFAULT uuidv7(),
    proposal_id uuid      NOT NULL,
    approver_id uuid      NOT NULL,
    outcome     text      NOT NULL,
    sys_period  tstzrange NOT NULL DEFAULT tstzrange(clock_timestamp(), NULL),
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT approval_once UNIQUE (tenant_id, proposal_id),
    CONSTRAINT approval_proposal FOREIGN KEY (tenant_id, proposal_id)
        REFERENCES proposals.proposal (tenant_id, id),
    CONSTRAINT approval_approver_principal FOREIGN KEY (tenant_id, approver_id)
        REFERENCES identity.principal (tenant_id, id),
    CONSTRAINT approval_outcome CHECK (outcome IN ('approved', 'rejected')),
    CONSTRAINT approval_sys_period_open CHECK (upper(sys_period) IS NULL)
);

CREATE TRIGGER approval_approver
    BEFORE INSERT ON proposals.approval
    FOR EACH ROW EXECUTE FUNCTION identity.require_human_approver();

CREATE TRIGGER approval_open_sys_period
    BEFORE INSERT ON proposals.approval
    FOR EACH ROW EXECUTE FUNCTION registry.open_sys_period();

-- What a principal did, insert-only. action_log_stamp writes responsible_id whatever the caller
-- sent: the sponsor for an agent and the person themself otherwise, so the log cannot name someone
-- else. The hash chain and export arrive with IPSO-68.
CREATE TABLE identity.action_log (
    tenant_id      uuid      NOT NULL,
    id             uuid      NOT NULL DEFAULT uuidv7(),
    principal_id   uuid      NOT NULL,
    responsible_id uuid      NOT NULL,
    action         text      NOT NULL,
    subject        text      NOT NULL,
    sys_period     tstzrange NOT NULL DEFAULT tstzrange(clock_timestamp(), NULL),
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT action_log_principal FOREIGN KEY (tenant_id, principal_id)
        REFERENCES identity.principal (tenant_id, id),
    CONSTRAINT action_log_responsible FOREIGN KEY (tenant_id, responsible_id)
        REFERENCES identity.principal (tenant_id, id),
    CONSTRAINT action_log_action CHECK (action ~ '^[a-z][a-z0-9_.-]{0,99}$'),
    CONSTRAINT action_log_subject CHECK (
        char_length(subject) <= 2000
        AND subject !~ '[[:cntrl:]]'),
    CONSTRAINT action_log_sys_period_open CHECK (upper(sys_period) IS NULL)
);

CREATE INDEX action_log_by_responsible ON identity.action_log (tenant_id, responsible_id, id);

-- +goose StatementBegin
CREATE FUNCTION identity.action_log_stamp() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    sponsor uuid;
BEGIN
    SELECT p.sponsor_id INTO sponsor
    FROM identity.principal p
    WHERE p.tenant_id = NEW.tenant_id
      AND p.id = NEW.principal_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'the action names no principal in this tenant'
            USING ERRCODE = 'foreign_key_violation';
    END IF;
    NEW.responsible_id := coalesce(sponsor, NEW.principal_id);
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER action_log_open_sys_period
    BEFORE INSERT ON identity.action_log
    FOR EACH ROW EXECUTE FUNCTION registry.open_sys_period();

CREATE TRIGGER action_log_stamp
    BEFORE INSERT ON identity.action_log
    FOR EACH ROW EXECUTE FUNCTION identity.action_log_stamp();

GRANT USAGE ON SCHEMA identity TO ipso_app;
GRANT SELECT, INSERT ON identity.principal, identity.action_log TO ipso_app;
GRANT SELECT, INSERT ON proposals.approval TO ipso_app;
