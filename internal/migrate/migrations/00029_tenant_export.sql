-- +goose Up
-- The exports a tenant admin asks for through the API (IPSO-142, ADR-0111).
--
-- tenancy.export is the one export a tenant may hold: a row names who asked for it, the age public key it is
-- encrypted to, and where it is. The worker builds it (state running), and only a ready row can be downloaded.
-- tenancy.export_part holds the finished archive in parts of at most 1 MiB, so no statement or download
-- reads it whole. The archive is the age ciphertext of ADR-0100: nothing in either table is a row of the
-- tenant in the clear, and the key that opens it never reaches the database.
--
-- A tenant holds at most one current export (export_one_at_a_time). Asking for another while one is pending or
-- running is refused. Asking for another after a finished one marks that one replaced: it is no longer served,
-- and its parts stay until the sweep deletes them, so a download that began in time can end. Every row expires:
-- the 24 hours it is kept after it finishes, and the same while it is still being made, so a job that died leaves
-- nothing behind. The sweep of the worker deletes an expired row and its parts half an hour after the expiry, and
-- the download refuses one the sweep has not reached yet.
--
-- Both are tenant tables with the policies of every other one, so rls.Check, the isolation suite and the
-- offboard purge cover them. The export leaves both out (an archive never holds the archive before it), so
-- the migration role may read and delete them and has no INSERT. The application role may change only the
-- columns the worker moves: who asked and the key stay as they were written.

CREATE TABLE tenancy.export (
    tenant_id    uuid        NOT NULL,
    id           uuid        NOT NULL DEFAULT uuidv7(),
    requested_by uuid        NOT NULL,
    recipient    text        NOT NULL,
    state        text        NOT NULL DEFAULT 'pending',
    created_at   timestamptz NOT NULL DEFAULT now(),
    -- When a job first claimed the export. The sweep gives up on a running export a fixed time after this, and
    -- not after the request, which may have waited for a worker for hours.
    started_at   timestamptz,
    finished_at  timestamptz,
    expires_at   timestamptz NOT NULL,
    bytes        bigint,
    parts        integer,
    sha256       bytea,
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT export_tenant FOREIGN KEY (tenant_id) REFERENCES tenancy.tenant (tenant_id),
    CONSTRAINT export_requested_by FOREIGN KEY (tenant_id, requested_by)
        REFERENCES identity.principal (tenant_id, id),
    -- A native or hybrid age public key: the bech32 text of one recipient. The server parses it again before
    -- it encrypts, so this only keeps a value that cannot be a key out of the table.
    CONSTRAINT export_recipient CHECK (char_length(recipient) <= 4096 AND recipient ~ '^age1[0-9a-z]+$'),
    CONSTRAINT export_state CHECK (state IN ('pending', 'running', 'ready', 'failed', 'replaced')),
    CONSTRAINT export_progress CHECK (
        (state IN ('pending', 'running')
            AND finished_at IS NULL AND bytes IS NULL AND parts IS NULL AND sha256 IS NULL)
        OR (state = 'failed'
            AND finished_at IS NOT NULL AND bytes IS NULL AND parts IS NULL AND sha256 IS NULL)
        OR (state = 'ready'
            AND finished_at IS NOT NULL AND bytes > 0 AND parts > 0 AND octet_length(sha256) = 32)
        -- A replaced export keeps what it had, so a download in flight can read its parts to the end.
        OR (state = 'replaced' AND finished_at IS NOT NULL)),
    CONSTRAINT export_expiry CHECK (expires_at > created_at)
);

CREATE UNIQUE INDEX export_one_at_a_time ON tenancy.export (tenant_id) WHERE state <> 'replaced';

CREATE TABLE tenancy.export_part (
    tenant_id uuid    NOT NULL,
    export_id uuid    NOT NULL,
    seq       integer NOT NULL,
    data      bytea   NOT NULL,
    PRIMARY KEY (tenant_id, export_id, seq),
    CONSTRAINT export_part_export FOREIGN KEY (tenant_id, export_id)
        REFERENCES tenancy.export (tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT export_part_seq CHECK (seq >= 0),
    CONSTRAINT export_part_size CHECK (octet_length(data) BETWEEN 1 AND 1048576)
);

-- Ciphertext does not compress, so the database does not try.
ALTER TABLE tenancy.export_part ALTER COLUMN data SET STORAGE EXTERNAL;

ALTER TABLE tenancy.export ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenancy.export FORCE ROW LEVEL SECURITY;
ALTER TABLE tenancy.export_part ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenancy.export_part FORCE ROW LEVEL SECURITY;

CREATE POLICY app_select ON tenancy.export
    FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON tenancy.export
    FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY app_update ON tenancy.export
    FOR UPDATE TO ipso_app
    USING (tenant_id = ipso.current_tenant())
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY app_delete ON tenancy.export
    FOR DELETE TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_select ON tenancy.export
    FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON tenancy.export
    FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());

CREATE POLICY app_select ON tenancy.export_part
    FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON tenancy.export_part
    FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY app_delete ON tenancy.export_part
    FOR DELETE TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_select ON tenancy.export_part
    FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON tenancy.export_part
    FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());

GRANT SELECT, INSERT, DELETE ON tenancy.export TO ipso_app;
GRANT UPDATE (state, started_at, finished_at, expires_at, bytes, parts, sha256) ON tenancy.export TO ipso_app;
GRANT SELECT, INSERT, DELETE ON tenancy.export_part TO ipso_app;
