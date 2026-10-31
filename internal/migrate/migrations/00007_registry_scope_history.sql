-- +goose Up
-- Scope retirement and re-parenting, section 2.3 of the specification and ADR-0056.
-- Row-level security policies ship with IPSO-61. Under FORCE ROW LEVEL SECURITY the
-- migration role needs INSERT on both history tables, and SELECT, INSERT, and DELETE
-- on scope_closure. The application role needs UPDATE and DELETE policies on scope.

-- Current closure edges gain an open sys_period. Existing edges start with the
-- descendant, which is when the insert trigger wrote them. A volatile default would
-- stamp existing rows with this statement's clock, so the column is filled explicitly.
ALTER TABLE registry.scope_closure ADD COLUMN sys_period tstzrange;

UPDATE registry.scope_closure AS c
SET sys_period = s.sys_period
FROM registry.scope AS s
WHERE s.tenant_id = c.tenant_id AND s.id = c.descendant_id;

ALTER TABLE registry.scope_closure
    ALTER COLUMN sys_period SET NOT NULL,
    ALTER COLUMN sys_period SET DEFAULT tstzrange(clock_timestamp(), NULL),
    ADD CONSTRAINT scope_closure_sys_period_open CHECK (upper(sys_period) IS NULL);

-- Closed scope rows. INCLUDING GENERATED keeps repo_key in step with match_repo.
-- LIKE does not copy keys, checks, or triggers.
CREATE TABLE registry.scope_history (LIKE registry.scope INCLUDING GENERATED);
ALTER TABLE registry.scope_history
    ADD CONSTRAINT scope_history_sys_period_closed CHECK (upper(sys_period) IS NOT NULL);

CREATE INDEX scope_history_candidates ON registry.scope_history (tenant_id, match_org, repo_key);

-- Closed closure edges. No foreign key: a retired scope is no longer in scope.
CREATE TABLE registry.scope_closure_history (
    tenant_id     uuid      NOT NULL,
    descendant_id uuid      NOT NULL,
    ancestor_id   uuid      NOT NULL,
    depth         int       NOT NULL CHECK (depth >= 0),
    sys_period    tstzrange NOT NULL,
    CONSTRAINT scope_closure_history_sys_period_closed CHECK (upper(sys_period) IS NOT NULL)
);

CREATE INDEX scope_closure_history_descendant
    ON registry.scope_closure_history (tenant_id, descendant_id);

CREATE VIEW registry.scope_all
    WITH (security_invoker = true) AS
SELECT tenant_id, id, parent_id, kind, selector, match_org, match_repo, match_path, match_env, repo_key, sys_period
FROM registry.scope
UNION ALL
SELECT tenant_id, id, parent_id, kind, selector, match_org, match_repo, match_path, match_env, repo_key, sys_period
FROM registry.scope_history;

CREATE VIEW registry.scope_closure_all
    WITH (security_invoker = true) AS
SELECT tenant_id, descendant_id, ancestor_id, depth, sys_period
FROM registry.scope_closure
UNION ALL
SELECT tenant_id, descendant_id, ancestor_id, depth, sys_period
FROM registry.scope_closure_history;

-- The closure rows of a new node are itself and every current ancestor of its parent.
-- Their sys_period is the node's, so the node and its self-edge begin together.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION registry.scope_write_closure() RETURNS trigger
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    INSERT INTO registry.scope_closure (tenant_id, descendant_id, ancestor_id, depth, sys_period)
    VALUES (NEW.tenant_id, NEW.id, NEW.id, 0, NEW.sys_period);
    IF NEW.parent_id IS NOT NULL THEN
        INSERT INTO registry.scope_closure (tenant_id, descendant_id, ancestor_id, depth, sys_period)
        SELECT c.tenant_id, NEW.id, c.ancestor_id, c.depth + 1, NEW.sys_period
        FROM registry.scope_closure c
        WHERE c.tenant_id = NEW.tenant_id AND c.descendant_id = NEW.parent_id;
    END IF;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

-- The same parent rules as the original function, plus the tenant lock. The lock is
-- taken before the parent is read, so an insert that waited on a re-parent copies
-- the parent chain that committed. Repeatable read keeps the snapshot from before
-- the wait, so the insert is refused.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION registry.scope_prepare() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    parent_kind text;
    parent_org  text;
    parent_repo text;
    parent_path text;
BEGIN
    IF current_setting('transaction_isolation') = 'repeatable read' THEN
        RAISE EXCEPTION 'a scope cannot be recorded in a repeatable read transaction'
            USING ERRCODE = 'feature_not_supported';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id::text, 122));

    NEW.sys_period := tstzrange(clock_timestamp(), NULL);
    NEW.match_org := NULL;
    NEW.match_repo := NULL;
    NEW.match_path := NULL;
    NEW.match_env := NULL;

    IF NEW.kind = 'org' THEN
        IF NEW.parent_id IS NOT NULL THEN
            RAISE EXCEPTION 'an org scope has no parent' USING ERRCODE = 'check_violation';
        END IF;
        NEW.match_org := NEW.selector;
        RETURN NEW;
    END IF;

    IF NEW.parent_id IS NULL THEN
        RAISE EXCEPTION 'a % scope needs a parent', NEW.kind USING ERRCODE = 'check_violation';
    END IF;
    SELECT p.kind, p.match_org, p.match_repo, p.match_path
        INTO parent_kind, parent_org, parent_repo, parent_path
        FROM registry.scope p
        WHERE p.tenant_id = NEW.tenant_id AND p.id = NEW.parent_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'the parent scope does not exist in this tenant' USING ERRCODE = 'foreign_key_violation';
    END IF;

    IF NOT coalesce(CASE NEW.kind
            WHEN 'domain'  THEN parent_kind = 'org'
            WHEN 'service' THEN parent_kind IN ('org', 'domain')
            WHEN 'repo'    THEN parent_kind IN ('org', 'domain', 'service')
            WHEN 'path'    THEN parent_kind = 'repo'
            WHEN 'env'     THEN parent_kind IN ('org', 'repo', 'path')
        END, false) THEN
        RAISE EXCEPTION 'a % scope cannot sit under a % scope', NEW.kind, parent_kind
            USING ERRCODE = 'check_violation';
    END IF;

    NEW.match_org := parent_org;
    IF NEW.kind = 'repo' THEN
        IF split_part(NEW.selector, '/', 1) IS DISTINCT FROM parent_org THEN
            RAISE EXCEPTION 'the repo owner must be the org of its parent' USING ERRCODE = 'check_violation';
        END IF;
        NEW.match_repo := NEW.selector;
    ELSIF NEW.kind = 'path' THEN
        NEW.match_repo := parent_repo;
        NEW.match_path := NEW.selector;
    ELSIF NEW.kind = 'env' THEN
        NEW.match_repo := parent_repo;
        NEW.match_path := parent_path;
        NEW.match_env := NEW.selector;
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

-- Archives a re-parent or a retirement. Only parent_id may change. The effective
-- selector is recomputed here, which is also what a cascade update of a descendant
-- relies on. The outermost call stores ipso.scope_cut from the clock after the
-- lock, overwriting a caller value. A cascade reuses it, and the rewrite clears
-- it when the trigger depth is 1.
-- +goose StatementBegin
CREATE FUNCTION registry.scope_version() RETURNS trigger
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    closed_at   timestamptz;
    cut_text    text;
    parent_kind text;
    parent_org  text;
    parent_repo text;
    parent_path text;
BEGIN
    IF current_setting('transaction_isolation') = 'repeatable read' THEN
        RAISE EXCEPTION 'a scope cannot be changed in a repeatable read transaction'
            USING ERRCODE = 'feature_not_supported';
    END IF;
    -- Grants are not tenant isolation. The setting is what Resolve uses, and a write
    -- without it, or for another tenant, is refused. Row-level security still ships
    -- with IPSO-61.
    IF nullif(current_setting('ipso.tenant', true), '') IS DISTINCT FROM OLD.tenant_id::text THEN
        RAISE EXCEPTION 'a scope change must run as its tenant' USING ERRCODE = 'insufficient_privilege';
    END IF;
    -- Held until this transaction ends. The reads below must stay in later statements.
    PERFORM pg_advisory_xact_lock(hashtextextended(OLD.tenant_id::text, 122));

    IF TG_OP = 'DELETE' THEN
        IF EXISTS (
            SELECT 1 FROM registry.scope AS s
            WHERE s.tenant_id = OLD.tenant_id AND s.parent_id = OLD.id
        ) THEN
            RAISE EXCEPTION 'a scope with children cannot be retired' USING ERRCODE = 'check_violation';
        END IF;

        closed_at := clock_timestamp();
        INSERT INTO registry.scope_history
            (tenant_id, id, parent_id, kind, selector, match_org, match_repo, match_path, match_env, sys_period)
        VALUES
            (OLD.tenant_id, OLD.id, OLD.parent_id, OLD.kind, OLD.selector,
             OLD.match_org, OLD.match_repo, OLD.match_path, OLD.match_env,
             tstzrange(lower(OLD.sys_period), closed_at));

        INSERT INTO registry.scope_closure_history
            (tenant_id, descendant_id, ancestor_id, depth, sys_period)
        SELECT c.tenant_id, c.descendant_id, c.ancestor_id, c.depth,
               tstzrange(lower(c.sys_period), closed_at)
        FROM registry.scope_closure AS c
        WHERE c.tenant_id = OLD.tenant_id AND c.descendant_id = OLD.id;

        DELETE FROM registry.scope_closure AS c
        WHERE c.tenant_id = OLD.tenant_id AND c.descendant_id = OLD.id;
        RETURN OLD;
    END IF;

    IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id
        OR NEW.id IS DISTINCT FROM OLD.id
        OR NEW.kind IS DISTINCT FROM OLD.kind
        OR NEW.selector IS DISTINCT FROM OLD.selector THEN
        RAISE EXCEPTION 'only the parent of a scope can change' USING ERRCODE = 'check_violation';
    END IF;

    NEW.match_org := NULL;
    NEW.match_repo := NULL;
    NEW.match_path := NULL;
    NEW.match_env := NULL;

    IF NEW.kind = 'org' THEN
        IF NEW.parent_id IS NOT NULL THEN
            RAISE EXCEPTION 'an org scope has no parent' USING ERRCODE = 'check_violation';
        END IF;
        NEW.match_org := NEW.selector;
    ELSE
        IF NEW.parent_id IS NULL THEN
            RAISE EXCEPTION 'a % scope needs a parent', NEW.kind USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.parent_id IS DISTINCT FROM OLD.parent_id AND EXISTS (
            SELECT 1 FROM registry.scope_closure AS c
            WHERE c.tenant_id = NEW.tenant_id
              AND c.ancestor_id = NEW.id
              AND c.descendant_id = NEW.parent_id
        ) THEN
            RAISE EXCEPTION 'a scope cannot move under itself or a descendant'
                USING ERRCODE = 'check_violation';
        END IF;

        SELECT p.kind, p.match_org, p.match_repo, p.match_path
            INTO parent_kind, parent_org, parent_repo, parent_path
            FROM registry.scope AS p
            WHERE p.tenant_id = NEW.tenant_id AND p.id = NEW.parent_id;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'the parent scope does not exist in this tenant'
                USING ERRCODE = 'foreign_key_violation';
        END IF;
        IF NOT coalesce(CASE NEW.kind
                WHEN 'domain'  THEN parent_kind = 'org'
                WHEN 'service' THEN parent_kind IN ('org', 'domain')
                WHEN 'repo'    THEN parent_kind IN ('org', 'domain', 'service')
                WHEN 'path'    THEN parent_kind = 'repo'
                WHEN 'env'     THEN parent_kind IN ('org', 'repo', 'path')
            END, false) THEN
            RAISE EXCEPTION 'a % scope cannot sit under a % scope', NEW.kind, parent_kind
                USING ERRCODE = 'check_violation';
        END IF;
        IF NEW.parent_id IS DISTINCT FROM OLD.parent_id AND NOT EXISTS (
            SELECT 1 FROM registry.scope_closure AS c
            WHERE c.tenant_id = NEW.tenant_id
              AND c.descendant_id = NEW.parent_id
              AND c.ancestor_id = NEW.parent_id
        ) THEN
            RAISE EXCEPTION 'the parent scope has no closure row' USING ERRCODE = 'data_exception';
        END IF;

        NEW.match_org := parent_org;
        IF NEW.kind = 'repo' THEN
            IF split_part(NEW.selector, '/', 1) IS DISTINCT FROM parent_org THEN
                RAISE EXCEPTION 'the repo owner must be the org of its parent'
                    USING ERRCODE = 'check_violation';
            END IF;
            NEW.match_repo := NEW.selector;
        ELSIF NEW.kind = 'path' THEN
            NEW.match_repo := parent_repo;
            NEW.match_path := NEW.selector;
        ELSIF NEW.kind = 'env' THEN
            NEW.match_repo := parent_repo;
            NEW.match_path := parent_path;
            NEW.match_env := NEW.selector;
        END IF;
    END IF;

    IF NEW.parent_id IS NOT DISTINCT FROM OLD.parent_id
        AND NEW.match_org IS NOT DISTINCT FROM OLD.match_org
        AND NEW.match_repo IS NOT DISTINCT FROM OLD.match_repo
        AND NEW.match_path IS NOT DISTINCT FROM OLD.match_path
        AND NEW.match_env IS NOT DISTINCT FROM OLD.match_env THEN
        NEW.sys_period := OLD.sys_period;
        RETURN NEW;
    END IF;

    -- The outermost trigger ignores any cut a caller stored and writes the clock
    -- taken after the lock. A cascade (trigger depth above 1) reuses that value
    -- so descendant periods abut. A caller cannot pre-set it.
    IF pg_trigger_depth() = 1 THEN
        closed_at := clock_timestamp();
        PERFORM set_config('ipso.scope_cut', to_char(closed_at, 'YYYY-MM-DD HH24:MI:SS.US'), true);
    ELSE
        cut_text := nullif(current_setting('ipso.scope_cut', true), '');
        IF cut_text IS NULL THEN
            RAISE EXCEPTION 'a scope archive is missing its transaction time'
                USING ERRCODE = 'data_exception';
        END IF;
        closed_at := to_timestamp(cut_text, 'YYYY-MM-DD HH24:MI:SS.US');
    END IF;

    INSERT INTO registry.scope_history
        (tenant_id, id, parent_id, kind, selector, match_org, match_repo, match_path, match_env, sys_period)
    VALUES
        (OLD.tenant_id, OLD.id, OLD.parent_id, OLD.kind, OLD.selector,
         OLD.match_org, OLD.match_repo, OLD.match_path, OLD.match_env,
         tstzrange(lower(OLD.sys_period), closed_at));
    NEW.sys_period := tstzrange(closed_at, NULL);
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

-- Rewrites the closure of a moved subtree, then archives descendants whose inherited
-- selector changed. The closure rewrite runs only when parent_id changed, so a
-- cascade update does not rewrite the same edges again.
-- +goose StatementBegin
CREATE FUNCTION registry.scope_rewrite_closure() RETURNS trigger
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    cut timestamptz := lower(NEW.sys_period);
BEGIN
    IF NEW.parent_id IS DISTINCT FROM OLD.parent_id THEN
        INSERT INTO registry.scope_closure_history
            (tenant_id, descendant_id, ancestor_id, depth, sys_period)
        SELECT c.tenant_id, c.descendant_id, c.ancestor_id, c.depth,
               tstzrange(lower(c.sys_period), cut)
        FROM registry.scope_closure AS c
        WHERE c.tenant_id = NEW.tenant_id
          AND c.descendant_id IN (
              SELECT sub.descendant_id
              FROM registry.scope_closure AS sub
              WHERE sub.tenant_id = NEW.tenant_id AND sub.ancestor_id = NEW.id)
          AND c.ancestor_id IN (
              SELECT above.ancestor_id
              FROM registry.scope_closure AS above
              WHERE above.tenant_id = NEW.tenant_id
                AND above.descendant_id = NEW.id
                AND above.ancestor_id <> NEW.id);

        DELETE FROM registry.scope_closure AS c
        WHERE c.tenant_id = NEW.tenant_id
          AND c.descendant_id IN (
              SELECT sub.descendant_id
              FROM registry.scope_closure AS sub
              WHERE sub.tenant_id = NEW.tenant_id AND sub.ancestor_id = NEW.id)
          AND c.ancestor_id IN (
              SELECT above.ancestor_id
              FROM registry.scope_closure AS above
              WHERE above.tenant_id = NEW.tenant_id
                AND above.descendant_id = NEW.id
                AND above.ancestor_id <> NEW.id);

        IF NEW.parent_id IS NOT NULL THEN
            INSERT INTO registry.scope_closure
                (tenant_id, descendant_id, ancestor_id, depth, sys_period)
            SELECT NEW.tenant_id, sub.descendant_id, anc.ancestor_id,
                   sub.depth + anc.depth + 1, tstzrange(cut, NULL)
            FROM registry.scope_closure AS sub
            JOIN registry.scope_closure AS anc
              ON anc.tenant_id = sub.tenant_id AND anc.descendant_id = NEW.parent_id
            WHERE sub.tenant_id = NEW.tenant_id AND sub.ancestor_id = NEW.id;
        END IF;
    END IF;

    IF NEW.match_org IS DISTINCT FROM OLD.match_org
        OR NEW.match_repo IS DISTINCT FROM OLD.match_repo
        OR NEW.match_path IS DISTINCT FROM OLD.match_path
        OR NEW.match_env IS DISTINCT FROM OLD.match_env THEN
        UPDATE registry.scope AS child
        SET parent_id = child.parent_id
        WHERE child.tenant_id = NEW.tenant_id AND child.parent_id = NEW.id;
    END IF;

    IF pg_trigger_depth() = 1 THEN
        PERFORM set_config('ipso.scope_cut', '', true);
    END IF;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

-- A new reference must name a current scope. An update may keep a reference that
-- was already on the row and now lives only in history, so a supersession can
-- still trim a decision that names a retired scope.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION registry.decision_version_check_scope_refs() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF cardinality(NEW.scope_refs) > 100 THEN
        RAISE EXCEPTION 'scope_refs holds more than 100 references' USING ERRCODE = 'check_violation';
    END IF;
    IF EXISTS (
        SELECT 1
        FROM unnest(NEW.scope_refs) AS ref(id)
        WHERE NOT EXISTS (
            SELECT 1 FROM registry.scope AS s
            WHERE s.tenant_id = NEW.tenant_id AND s.id = ref.id
        )
        AND NOT (
            TG_OP = 'UPDATE'
            AND ref.id = ANY (OLD.scope_refs)
            AND EXISTS (
                SELECT 1 FROM registry.scope_history AS h
                WHERE h.tenant_id = NEW.tenant_id AND h.id = ref.id
            )
        )
    ) THEN
        RAISE EXCEPTION 'scope_refs names a scope that does not exist in this tenant'
            USING ERRCODE = 'foreign_key_violation';
    END IF;
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION registry.scope_prepare() FROM PUBLIC;
REVOKE ALL ON FUNCTION registry.scope_write_closure() FROM PUBLIC;
REVOKE ALL ON FUNCTION registry.scope_version() FROM PUBLIC;
REVOKE ALL ON FUNCTION registry.scope_rewrite_closure() FROM PUBLIC;
REVOKE ALL ON FUNCTION registry.decision_version_check_scope_refs() FROM PUBLIC;

CREATE TRIGGER scope_version
    BEFORE UPDATE OR DELETE ON registry.scope
    FOR EACH ROW EXECUTE FUNCTION registry.scope_version();

CREATE TRIGGER scope_rewrite_closure
    AFTER UPDATE ON registry.scope
    FOR EACH ROW EXECUTE FUNCTION registry.scope_rewrite_closure();

-- An insert-only waiver must not make retirement impossible. waiver_check still
-- requires a current closure row, so a new waiver cannot name a retired scope.
ALTER TABLE registry.waiver DROP CONSTRAINT waiver_scope;

GRANT UPDATE, DELETE ON registry.scope TO ipso_app;
GRANT SELECT ON registry.scope_history TO ipso_app;
GRANT SELECT ON registry.scope_all TO ipso_app;
GRANT SELECT ON registry.scope_closure_history TO ipso_app;
GRANT SELECT ON registry.scope_closure_all TO ipso_app;
