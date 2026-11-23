-- +goose Up
-- Erasure of a person's name, ADR-0156. identity.principal already allows a change of name and of
-- nothing else (00037). These four tables have no history table, so the old name is overwritten in
-- place and is not copied aside. The application role may set the name to the placeholder and may
-- not write any other value back.
--
-- name_erased is the mark a later SCIM provision reads. Once it is set, the name and the SCIM
-- filter key stay as they are. The display placeholder is the word erased. The filter key is
-- erased- and the principal id, because user_name is unique in the tenant and one shared word
-- would collide.

ALTER TABLE identity.principal
    ADD COLUMN name_erased boolean NOT NULL DEFAULT false;

GRANT UPDATE (name_erased) ON identity.principal TO ipso_app;

-- +goose StatementBegin
CREATE OR REPLACE FUNCTION identity.principal_name() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.id IS DISTINCT FROM OLD.id
        OR NEW.kind IS DISTINCT FROM OLD.kind
        OR NEW.sponsor_id IS DISTINCT FROM OLD.sponsor_id
        OR NEW.sys_period IS DISTINCT FROM OLD.sys_period
    THEN
        RAISE EXCEPTION 'a principal name may change, and nothing else on it changes'
            USING ERRCODE = 'check_violation';
    END IF;
    IF OLD.name_erased AND (NEW.name IS DISTINCT FROM OLD.name OR NOT NEW.name_erased) THEN
        RAISE EXCEPTION 'an erased name is not restored'
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.name_erased AND NOT OLD.name_erased AND NEW.name IS DISTINCT FROM 'erased' THEN
        RAISE EXCEPTION 'an erasure replaces the name with the placeholder'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION identity.scim_user_erase() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.principal_id IS DISTINCT FROM OLD.principal_id
        OR NEW.external_id IS DISTINCT FROM OLD.external_id
    THEN
        RAISE EXCEPTION 'a scim user may change its filter key and its active flag, and nothing else'
            USING ERRCODE = 'check_violation';
    END IF;
    IF NEW.user_name IS DISTINCT FROM OLD.user_name AND EXISTS (
        SELECT 1
        FROM identity.principal p
        WHERE p.tenant_id = NEW.tenant_id
          AND p.id = NEW.principal_id
          AND p.name_erased
    ) THEN
        RAISE EXCEPTION 'an erased name is not restored'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER scim_user_erase
    BEFORE UPDATE ON identity.scim_user
    FOR EACH ROW EXECUTE FUNCTION identity.scim_user_erase();

REVOKE ALL ON FUNCTION identity.scim_user_erase() FROM PUBLIC;

-- +goose StatementBegin
CREATE FUNCTION registry.waiver_erase() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    -- A superuser ages rows in tests. The application role is the one this trigger binds.
    IF current_user <> 'ipso_app' THEN
        RETURN NEW;
    END IF;
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.id IS DISTINCT FROM OLD.id
        OR NEW.decision_id IS DISTINCT FROM OLD.decision_id
        OR NEW.scope_id IS DISTINCT FROM OLD.scope_id
        OR NEW.reason IS DISTINCT FROM OLD.reason
        OR NEW.approver_id IS DISTINCT FROM OLD.approver_id
        OR NEW.valid_period IS DISTINCT FROM OLD.valid_period
        OR NEW.ticket_ref IS DISTINCT FROM OLD.ticket_ref
        OR NEW.sys_period IS DISTINCT FROM OLD.sys_period
        OR NEW.approver IS DISTINCT FROM 'erased'
    THEN
        RAISE EXCEPTION 'a waiver approver may be replaced only with the placeholder'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER waiver_erase
    BEFORE UPDATE ON registry.waiver
    FOR EACH ROW EXECUTE FUNCTION registry.waiver_erase();

REVOKE ALL ON FUNCTION registry.waiver_erase() FROM PUBLIC;

CREATE POLICY app_update ON registry.waiver
    FOR UPDATE TO ipso_app
    USING (tenant_id = ipso.current_tenant())
    WITH CHECK (tenant_id = ipso.current_tenant());

GRANT UPDATE (approver) ON registry.waiver TO ipso_app;

-- +goose StatementBegin
CREATE FUNCTION identity.invitation_erase() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    -- A superuser ages an invitation in tests. The application role is the one this trigger binds.
    IF current_user <> 'ipso_app' THEN
        RETURN NEW;
    END IF;
    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.id IS DISTINCT FROM OLD.id
        OR NEW.token_sha256 IS DISTINCT FROM OLD.token_sha256
        OR NEW.role IS DISTINCT FROM OLD.role
        OR NEW.created_by IS DISTINCT FROM OLD.created_by
        OR NEW.created_at IS DISTINCT FROM OLD.created_at
        OR NEW.expires_at IS DISTINCT FROM OLD.expires_at
        OR NEW.name IS DISTINCT FROM 'erased'
    THEN
        RAISE EXCEPTION 'an invitation name may be replaced only with the placeholder'
            USING ERRCODE = 'check_violation';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER invitation_erase
    BEFORE UPDATE ON identity.invitation
    FOR EACH ROW EXECUTE FUNCTION identity.invitation_erase();

REVOKE ALL ON FUNCTION identity.invitation_erase() FROM PUBLIC;

CREATE POLICY app_update ON identity.invitation
    FOR UPDATE TO ipso_app
    USING (tenant_id = ipso.current_tenant())
    WITH CHECK (tenant_id = ipso.current_tenant());

GRANT UPDATE (name) ON identity.invitation TO ipso_app;
