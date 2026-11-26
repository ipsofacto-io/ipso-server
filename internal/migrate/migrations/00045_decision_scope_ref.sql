-- +goose Up
-- A lookup table that lets the decisions read of Resolve use an index under row-level security
-- (IPSO-194, ADR-0168).
--
-- The overlap operator on scope_refs is not leakproof, so under the policies of 00013 the planner may
-- not use it as an index condition. The two GIN indexes on scope_refs were never a legal access path
-- for ipso_app, and the read removed every other row of the tenant by filter, in proportion to the
-- decisions of the tenant and not to the decisions that match. Only a superuser can mark an operator
-- leakproof, and ipso_migrate is not one. Equality on a uuid is leakproof, so a btree on a table that
-- holds one row per scope and decision is a legal access path.
--
-- decision_scope_ref holds one row for each scope that any version of a decision has named, current or
-- closed. It has no periods and nothing deletes a row except the offboarding of the tenant, so it can
-- name a scope that a later version dropped. The read keeps the overlap test on scope_refs, so such a
-- row costs one lookup and never changes an answer. The trigger below is the only writer: ipso_app can
-- read the table and cannot write it.
--
-- The backfill reads both decision tables as their owner. FORCE ROW LEVEL SECURITY binds the owner, and
-- a migration has no tenant, so the file lifts FORCE on those two tables and sets it again before it
-- ends. ALTER TABLE holds an exclusive lock until the transaction commits, so no other session reads
-- them in between, and a failure rolls the file back to the forced state.

CREATE TABLE registry.decision_scope_ref (
    tenant_id   uuid NOT NULL,
    scope_id    uuid NOT NULL,
    decision_id uuid NOT NULL,
    PRIMARY KEY (tenant_id, scope_id, decision_id)
);

-- Writes the scopes of every version that is inserted or updated. The caller needs no privilege on the
-- table, so the function is SECURITY DEFINER and owned by the migration role, which runs this file, and
-- it relies on the migrate_insert policy below. search_path is fixed so a caller cannot redirect an
-- unqualified name. It fires on every update, and a scope that is already there is left alone. The rows
-- go in in id order, so two writes to different valid periods of one decision take the unique index in
-- the same order and cannot wait on each other.
-- +goose StatementBegin
CREATE FUNCTION registry.decision_version_index_scope_refs() RETURNS trigger
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    INSERT INTO registry.decision_scope_ref (tenant_id, scope_id, decision_id)
    SELECT NEW.tenant_id, ref.id, NEW.decision_id
    FROM unnest(NEW.scope_refs) AS ref(id)
    ORDER BY ref.id
    ON CONFLICT DO NOTHING;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION registry.decision_version_index_scope_refs() FROM PUBLIC;

CREATE TRIGGER decision_version_index_scope_refs
    AFTER INSERT OR UPDATE ON registry.decision_version
    FOR EACH ROW EXECUTE FUNCTION registry.decision_version_index_scope_refs();

ALTER TABLE registry.decision_version NO FORCE ROW LEVEL SECURITY;
ALTER TABLE registry.decision_version_history NO FORCE ROW LEVEL SECURITY;

INSERT INTO registry.decision_scope_ref (tenant_id, scope_id, decision_id)
SELECT DISTINCT v.tenant_id, ref.id, v.decision_id
FROM (
    SELECT tenant_id, decision_id, scope_refs FROM registry.decision_version
    UNION ALL
    SELECT tenant_id, decision_id, scope_refs FROM registry.decision_version_history
) AS v
CROSS JOIN LATERAL unnest(v.scope_refs) AS ref(id);

ALTER TABLE registry.decision_version FORCE ROW LEVEL SECURITY;
ALTER TABLE registry.decision_version_history FORCE ROW LEVEL SECURITY;

ALTER TABLE registry.decision_scope_ref ENABLE ROW LEVEL SECURITY;
ALTER TABLE registry.decision_scope_ref FORCE ROW LEVEL SECURITY;

CREATE POLICY app_select ON registry.decision_scope_ref
    FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_select ON registry.decision_scope_ref
    FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_insert ON registry.decision_scope_ref
    FOR INSERT TO ipso_migrate
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON registry.decision_scope_ref
    FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());

GRANT SELECT ON registry.decision_scope_ref TO ipso_app;

-- The read now reaches the version rows through the decision id. The current table has the primary key
-- (tenant_id, decision_id, valid_period). The history table has no key, so it gets the index of the
-- same two columns, which also serves every read by tenant that decision_version_history_tenant served.
CREATE INDEX decision_version_history_decision
    ON registry.decision_version_history (tenant_id, decision_id);
DROP INDEX registry.decision_version_history_tenant;

-- No role that reads through a policy can use these, and every decision write paid for them.
DROP INDEX registry.decision_version_scope_refs_gin;
DROP INDEX registry.decision_version_history_scope_refs_gin;
