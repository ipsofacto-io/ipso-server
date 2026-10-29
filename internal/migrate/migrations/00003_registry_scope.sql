-- +goose Up
-- Scopes and their closure, section 2.1 of the specification and ADR-0051.
-- Row-level security policies on these tables ship with IPSO-61, not here. Under FORCE ROW LEVEL
-- SECURITY the closure trigger needs a SELECT policy and an INSERT policy on scope_closure for ipso_migrate.

-- A scope is a node of one tree per tenant. selector is the node's own term. The match_* columns
-- are the effective selector, copied from the parent chain by scope_prepare, so a resolver can
-- match a node without walking its chain. A grouping node (domain, service) selects nothing itself.
-- The grammar of every selector is the one in internal/registry/selector.go. The two copies are
-- compared by a test.
CREATE TABLE registry.scope (
    tenant_id  uuid      NOT NULL,
    id         uuid      NOT NULL DEFAULT uuidv7(),
    parent_id  uuid,
    kind       text      NOT NULL,
    selector   text      NOT NULL,
    match_org  text      NOT NULL,
    match_repo text,
    match_path text,
    match_env  text,
    -- The literal repo, or empty for a node that is org-wide or holds a repo glob. Resolution
    -- reads the candidates with repo_key IN ('', subject repo).
    repo_key   text      GENERATED ALWAYS AS
        (CASE WHEN match_repo IS NULL OR match_repo ~ '[*?]' THEN '' ELSE match_repo END) STORED,
    sys_period tstzrange NOT NULL DEFAULT tstzrange(clock_timestamp(), NULL),
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT scope_parent FOREIGN KEY (tenant_id, parent_id) REFERENCES registry.scope (tenant_id, id),
    CONSTRAINT scope_kind CHECK (kind IN ('org', 'domain', 'service', 'repo', 'path', 'env')),
    CONSTRAINT scope_root_is_org CHECK ((kind = 'org') = (parent_id IS NULL)),
    CONSTRAINT scope_sys_period_open CHECK (upper(sys_period) IS NULL),
    CONSTRAINT scope_name_selector CHECK (
        kind NOT IN ('org', 'domain', 'service', 'env')
        OR selector ~ '^[a-z0-9][a-z0-9._-]{0,62}$'),
    CONSTRAINT scope_repo_selector CHECK (
        kind <> 'repo'
        OR (char_length(selector) <= 255
            AND selector ~ '^[a-z0-9][a-z0-9._-]{0,62}(/[a-z0-9._*?-]{1,100}){1,10}$'
            AND selector !~ '(^|/)\.{1,2}(/|$)'
            AND selector !~ '\*\*')),
    CONSTRAINT scope_path_selector CHECK (
        kind <> 'path'
        OR (selector ~ '^[\x22-\x5a\x5e-\x7a|~]{1,255}$'
            AND selector !~ '(^|/)\.{0,2}(/|$)'
            AND selector !~ '[^/]\*\*|\*\*[^/]')),
    CONSTRAINT scope_org_is_selector CHECK (kind <> 'org' OR match_org = selector),
    CONSTRAINT scope_effective_shape CHECK (
           (kind IN ('org', 'domain', 'service') AND match_repo IS NULL AND match_path IS NULL AND match_env IS NULL)
        OR (kind = 'repo' AND match_repo = selector AND match_path IS NULL AND match_env IS NULL)
        OR (kind = 'path' AND match_repo IS NOT NULL AND match_path = selector AND match_env IS NULL)
        OR (kind = 'env' AND match_env = selector AND (match_path IS NULL OR match_repo IS NOT NULL)))
);

CREATE INDEX scope_candidates ON registry.scope (tenant_id, match_org, repo_key);

-- One row per ancestor-or-self pair. depth is 0 for the node itself. The trigger below is the
-- only writer.
CREATE TABLE registry.scope_closure (
    tenant_id     uuid NOT NULL,
    descendant_id uuid NOT NULL,
    ancestor_id   uuid NOT NULL,
    depth         int  NOT NULL CHECK (depth >= 0),
    PRIMARY KEY (tenant_id, descendant_id, ancestor_id),
    FOREIGN KEY (tenant_id, descendant_id) REFERENCES registry.scope (tenant_id, id),
    FOREIGN KEY (tenant_id, ancestor_id) REFERENCES registry.scope (tenant_id, id)
);

-- The fixed parents of each kind, the effective selector, and transaction time. This function
-- needs no privilege beyond reading the parent, so it runs as the caller. search_path is fixed
-- anyway, so a caller cannot redirect an unqualified name.
-- +goose StatementBegin
CREATE FUNCTION registry.scope_prepare() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    parent_kind text;
    parent_org  text;
    parent_repo text;
    parent_path text;
BEGIN
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

-- The closure rows of a new node are itself and every ancestor of its parent. ipso_app cannot
-- write scope_closure, so this function is SECURITY DEFINER and owned by the migration role,
-- which runs this file. search_path is fixed so a caller cannot redirect an unqualified name.
-- +goose StatementBegin
CREATE FUNCTION registry.scope_write_closure() RETURNS trigger
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    INSERT INTO registry.scope_closure (tenant_id, descendant_id, ancestor_id, depth)
    VALUES (NEW.tenant_id, NEW.id, NEW.id, 0);
    IF NEW.parent_id IS NOT NULL THEN
        INSERT INTO registry.scope_closure (tenant_id, descendant_id, ancestor_id, depth)
        SELECT c.tenant_id, NEW.id, c.ancestor_id, c.depth + 1
        FROM registry.scope_closure c
        WHERE c.tenant_id = NEW.tenant_id AND c.descendant_id = NEW.parent_id;
    END IF;
    RETURN NULL;
END;
$$;
-- +goose StatementEnd

-- A decision applies only where its scope_refs point. An empty, mistyped, or foreign reference
-- would make it apply nowhere, so enforcement would fail open. The caller needs no elevation to
-- read the scopes of its own tenant. The array holds at most 100 references, the same limit as
-- the CHECK constraint below, so the loop over it stays small however large an array is sent.
-- +goose StatementBegin
CREATE FUNCTION registry.decision_version_check_scope_refs() RETURNS trigger
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
            SELECT 1 FROM registry.scope s WHERE s.tenant_id = NEW.tenant_id AND s.id = ref.id
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
REVOKE ALL ON FUNCTION registry.decision_version_check_scope_refs() FROM PUBLIC;

CREATE TRIGGER scope_prepare
    BEFORE INSERT ON registry.scope
    FOR EACH ROW EXECUTE FUNCTION registry.scope_prepare();

CREATE TRIGGER scope_write_closure
    AFTER INSERT ON registry.scope
    FOR EACH ROW EXECUTE FUNCTION registry.scope_write_closure();

-- scope_refs could be empty or unbounded in 00002. No deployment holds rows yet (ADR-0050), so
-- the check is validated against existing rows and the migration fails loudly if any row would
-- break it.
ALTER TABLE registry.decision_version
    ADD CONSTRAINT decision_version_scope_refs_valid
    CHECK (cardinality(scope_refs) BETWEEN 1 AND 100 AND array_position(scope_refs, NULL) IS NULL);

-- Nothing bounded a decision body in 00002. A record is a statement, a rationale and a few lists,
-- so 1 MiB of text is far above any real one, and it stops one write from bloating the table and
-- every read of decision_version_all. The text form is measured, so the limit does not depend on
-- how PostgreSQL stores the value.
ALTER TABLE registry.decision_version
    ADD CONSTRAINT decision_version_body_size CHECK (octet_length(body::text) <= 1048576);

CREATE TRIGGER decision_version_scope_refs
    BEFORE INSERT OR UPDATE ON registry.decision_version
    FOR EACH ROW EXECUTE FUNCTION registry.decision_version_check_scope_refs();

-- Resolution reads the decisions whose scope_refs overlap a set of scope ids, in both tables.
-- Decisions are written rarely and read on every check, so the indexes skip GIN's pending list.
-- With it, a read right after a burst of writes scans the list and the planner prices the index
-- out until vacuum has merged it.
CREATE INDEX decision_version_scope_refs_gin ON registry.decision_version
    USING gin (scope_refs) WITH (fastupdate = off);
CREATE INDEX decision_version_history_scope_refs_gin ON registry.decision_version_history
    USING gin (scope_refs) WITH (fastupdate = off);

-- The application role creates and reads scopes. It cannot change or remove one, and it cannot
-- write the closure.
GRANT SELECT, INSERT ON registry.scope TO ipso_app;
GRANT SELECT ON registry.scope_closure TO ipso_app;
