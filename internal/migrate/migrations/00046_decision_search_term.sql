-- +goose Up
-- A lookup table that lets keyword search in SearchDecisions and ListDecisionHealth use an index
-- under row-level security (IPSO-195, ADR-0169).
--
-- Under the policies of 00013 neither the full-text match operator @@ nor ILIKE is leakproof, so the
-- planner cannot use decision_version_fts (00043) for ipso_app and scans every decision version of
-- the tenant. Standard btree comparisons (=, >=, <) on text COLLATE "C" are leakproof, so a lookup
-- table holding one row per (tenant, term, decision) serves exact and prefix keyword queries via an
-- index-only scan, then probes decision_version and decision_version_history by (tenant_id, decision_id).
--
-- Like decision_scope_ref (00045), decision_search_term is append-only because SearchDecisions and
-- ListDecisionHealth read bitemporal decision_version_all (current and closed versions). The outer
-- read re-checks each narrowed version row with registry.decision_search_terms(d.body), so a term
-- dropped by a later version or a non-sensitive-to-sensitive transition never leaks into current
-- answers. The trigger below is the only writer: ipso_app can read the table and cannot write it.
--
-- The backfill reads both decision tables as their owner. FORCE ROW LEVEL SECURITY binds the owner,
-- and a migration has no tenant, so the file lifts FORCE on those two tables and sets it again before
-- it ends. ALTER TABLE holds an exclusive lock until the transaction commits, so no other session
-- reads them in between, and a failure rolls the file back to the forced state.

-- Extracts the distinct, lowercase, length-capped searchable terms of a decision body (ADR-0163,
-- ADR-0072, ADR-0169). Non-sensitive decisions index title, slug, statement, tags, and EDR id.
-- Sensitive decisions index slug and EDR id only, so redacted content cannot be probed by keyword.
-- +goose StatementBegin
CREATE FUNCTION registry.decision_search_terms(body jsonb) RETURNS text[]
    LANGUAGE plpgsql
    IMMUTABLE
    SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    is_sensitive boolean;
    slug_val     text;
    id_val       text;
    tags_text    text;
    tag_vals     text[];
    terms        text[];
BEGIN
    IF body IS NULL OR pg_catalog.jsonb_typeof(body) <> 'object' THEN
        RETURN ARRAY[]::text[];
    END IF;

    is_sensitive := (
        (pg_catalog.jsonb_typeof(body->'tags') = 'array' AND (body->'tags') ? 'sensitive')
        OR CASE
            WHEN pg_catalog.jsonb_typeof(body->'sensitive') = 'boolean' THEN (body->>'sensitive')::boolean
            WHEN pg_catalog.jsonb_typeof(body->'sensitive') = 'string' AND pg_catalog.lower(body->>'sensitive') = 'true' THEN true
            ELSE false
        END
    );

    slug_val := pg_catalog.lower(pg_catalog.btrim(coalesce(body->>'slug', '')));
    id_val   := pg_catalog.lower(pg_catalog.btrim(coalesce(body->>'id', '')));

    IF is_sensitive THEN
        SELECT coalesce(pg_catalog.array_agg(DISTINCT t COLLATE "C" ORDER BY t COLLATE "C"), ARRAY[]::text[])
        INTO terms
        FROM (
            SELECT pg_catalog.left(slug_val, 128) AS t WHERE slug_val <> ''
            UNION ALL
            SELECT pg_catalog.left(id_val, 128) AS t WHERE id_val <> ''
            UNION ALL
            SELECT pg_catalog.left(pg_catalog.ltrim(tok, '-'), 128) AS t
            FROM pg_catalog.unnest(
                pg_catalog.tsvector_to_array(pg_catalog.to_tsvector('pg_catalog.simple', slug_val))
            ) AS tok
            WHERE slug_val <> '' AND tok <> ''
        ) AS s
        WHERE t <> '';
        RETURN terms;
    END IF;

    IF pg_catalog.jsonb_typeof(body->'tags') = 'array' THEN
        SELECT coalesce(pg_catalog.array_agg(pg_catalog.lower(pg_catalog.btrim(elem))), ARRAY[]::text[]),
               coalesce(pg_catalog.string_agg(elem, ' '), '')
        INTO tag_vals, tags_text
        FROM pg_catalog.jsonb_array_elements_text(body->'tags') AS elem
        WHERE pg_catalog.btrim(elem) <> '';
    ELSE
        tag_vals := ARRAY[]::text[];
        tags_text := '';
    END IF;

    SELECT coalesce(pg_catalog.array_agg(DISTINCT t COLLATE "C" ORDER BY t COLLATE "C"), ARRAY[]::text[])
    INTO terms
    FROM (
        SELECT pg_catalog.left(slug_val, 128) AS t WHERE slug_val <> ''
        UNION ALL
        SELECT pg_catalog.left(id_val, 128) AS t WHERE id_val <> ''
        UNION ALL
        SELECT pg_catalog.left(tag, 128) AS t FROM pg_catalog.unnest(tag_vals) AS tag WHERE tag <> ''
        UNION ALL
        SELECT pg_catalog.left(pg_catalog.ltrim(tok, '-'), 128) AS t
        FROM pg_catalog.unnest(
            pg_catalog.tsvector_to_array(
                pg_catalog.to_tsvector(
                    'pg_catalog.simple',
                    coalesce(body->>'title', '') || ' ' ||
                    coalesce(body->>'slug', '') || ' ' ||
                    coalesce(body->>'statement', '') || ' ' ||
                    tags_text
                )
            )
        ) AS tok
        WHERE tok <> ''
    ) AS s
    WHERE t <> '';

    RETURN terms;
END;
$$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION registry.decision_search_terms(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION registry.decision_search_terms(jsonb) TO ipso_app;

CREATE TABLE registry.decision_search_term (
    tenant_id   uuid NOT NULL,
    term        text COLLATE "C" NOT NULL,
    decision_id uuid NOT NULL,
    PRIMARY KEY (tenant_id, term, decision_id)
);

-- Writes the searchable terms of every version that is inserted or whose body changes. The caller
-- needs no privilege on the table, so the function is SECURITY DEFINER and owned by the migration
-- role, which runs this file, and it relies on the migrate_insert policy below. Rows go in in
-- COLLATE "C" term order so concurrent writes to different valid periods of one decision take the
-- unique index in the same order and cannot wait on each other.
-- +goose StatementBegin
CREATE FUNCTION registry.decision_version_index_search_terms() RETURNS trigger
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    IF TG_OP = 'UPDATE' AND NEW.body IS NOT DISTINCT FROM OLD.body THEN
        RETURN NULL;
    END IF;
    INSERT INTO registry.decision_search_term (tenant_id, term, decision_id)
    SELECT NEW.tenant_id, tok.term, NEW.decision_id
    FROM pg_catalog.unnest(registry.decision_search_terms(NEW.body)) AS tok(term)
    ORDER BY tok.term COLLATE "C"
    ON CONFLICT DO NOTHING;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

REVOKE ALL ON FUNCTION registry.decision_version_index_search_terms() FROM PUBLIC;

CREATE TRIGGER decision_version_index_search_terms
    AFTER INSERT OR UPDATE ON registry.decision_version
    FOR EACH ROW EXECUTE FUNCTION registry.decision_version_index_search_terms();

ALTER TABLE registry.decision_version NO FORCE ROW LEVEL SECURITY;
ALTER TABLE registry.decision_version_history NO FORCE ROW LEVEL SECURITY;

INSERT INTO registry.decision_search_term (tenant_id, term, decision_id)
SELECT DISTINCT v.tenant_id, tok.term, v.decision_id
FROM (
    SELECT tenant_id, decision_id, body FROM registry.decision_version
    UNION ALL
    SELECT tenant_id, decision_id, body FROM registry.decision_version_history
) AS v
CROSS JOIN LATERAL pg_catalog.unnest(registry.decision_search_terms(v.body)) AS tok(term);

ALTER TABLE registry.decision_version FORCE ROW LEVEL SECURITY;
ALTER TABLE registry.decision_version_history FORCE ROW LEVEL SECURITY;

ALTER TABLE registry.decision_search_term ENABLE ROW LEVEL SECURITY;
ALTER TABLE registry.decision_search_term FORCE ROW LEVEL SECURITY;

CREATE POLICY app_select ON registry.decision_search_term
    FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_select ON registry.decision_search_term
    FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_insert ON registry.decision_search_term
    FOR INSERT TO ipso_migrate
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON registry.decision_search_term
    FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());

GRANT SELECT ON registry.decision_search_term TO ipso_app;

-- No role that reads through a policy can use this GIN index, and every decision write paid for it.
DROP INDEX registry.decision_version_fts;
