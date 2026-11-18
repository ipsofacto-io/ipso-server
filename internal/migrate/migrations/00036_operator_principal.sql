-- +goose Up
-- The operator principal, ADR-0129. An operator command has no login, and an action log entry names a
-- principal, so each tenant that is exported, restored, offboarded or bound gains one reserved principal
-- of kind operator. It is not a person and not an agent: it holds no role and no login, and the checks
-- that already require a human keep it from approving or sponsoring. The chain and its hash do not change.
-- The row is inserted by the command that first logs, not by this migration, because a restore target is
-- created empty and a restore refuses a tenant that already has principal rows.

ALTER TABLE identity.principal DROP CONSTRAINT principal_kind;
ALTER TABLE identity.principal
    ADD CONSTRAINT principal_kind CHECK (kind IN ('human', 'agent', 'operator'));

-- The reserved id and the operator kind are the same row. A person, an agent, or a row copied from
-- an archive cannot take the id, and no other id can be an operator. A check still runs when triggers
-- are off, which is how a restore writes.
ALTER TABLE identity.principal
    ADD CONSTRAINT principal_operator_id CHECK (
        (id = '01900000-0000-7000-8000-000000000001'::uuid) = (kind = 'operator')
    );

-- A role on the operator would let a later grant turn the command's identity into a caller. The agent
-- rule stays as it was: an agent holds only the agent role, and a person never holds it.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION identity.role_binding_check() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM identity.principal p
        WHERE p.tenant_id = NEW.tenant_id
          AND p.id = NEW.principal_id
          AND p.kind = 'operator'
    ) THEN
        RAISE EXCEPTION 'the operator principal holds no role'
            USING ERRCODE = 'check_violation';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM identity.principal p
        WHERE p.tenant_id = NEW.tenant_id
          AND p.id = NEW.principal_id
          AND (p.kind = 'agent') = (NEW.role = 'agent')
    ) THEN
        RAISE EXCEPTION 'an agent holds only the agent role, and a person never holds it'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

-- A login on the operator would let someone sign in as the command. Agents keep their bearer logins.
-- The trigger is not SECURITY DEFINER. It reads identity.principal as the caller, under the same
-- policies as every other read.
-- +goose StatementBegin
CREATE FUNCTION identity.login_principal() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM identity.principal p
        WHERE p.tenant_id = NEW.tenant_id
          AND p.id = NEW.principal_id
          AND p.kind = 'operator'
    ) THEN
        RAISE EXCEPTION 'the operator principal holds no login'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER login_principal
    BEFORE INSERT ON identity.login
    FOR EACH ROW EXECUTE FUNCTION identity.login_principal();

REVOKE ALL ON FUNCTION identity.login_principal() FROM PUBLIC;
