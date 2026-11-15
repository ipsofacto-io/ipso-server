-- +goose Up
-- The hash chain of the action log, and the head of it in the tombstone (IPSO-68, ADR-0126).
--
-- Every entry of identity.action_log gets a position in the chain of its tenant (seq, from 1), the hash of
-- the entry before it (prev_hash) and its own hash (hash). The BEFORE INSERT trigger sets all three, and
-- the time of the entry, under a lock per tenant that is held to the end of the transaction, so the order
-- of the chain is the order of the commits and a caller cannot choose a position or a hash. The hash covers
-- the entry before it, the position, the id, the time, both principals, the action and the subject. It
-- leaves the tenant id out on purpose: a restore gives every row the id of the target tenant (ADR-0100),
-- and a chain must still verify after that.
--
-- The trigger refuses any transaction that is not READ COMMITTED. A snapshot taken before the lock would
-- read a head that another append has already moved, and two appends would write the same position. The
-- unique key on (tenant_id, seq) is the second wall: a fork fails and does not commit.
--
-- The log is append-only. ipso_app has no UPDATE, DELETE or TRUNCATE, and two triggers refuse them for the
-- owner too. They are ordinary triggers, so the restore and offboard commands, which run with
-- session_replication_role = replica (ADR-0100), still work. The owner can still disable a trigger, which
-- is why the chain is checked and why the head of it is copied into the tombstone (ADR-0126).
--
-- The entries that exist already are chained here, per tenant in the order of their ids. The table is not
-- forced for the owner for the length of the backfill, because the owner has no UPDATE policy and must see
-- every tenant, and it is forced again before the transaction ends.

ALTER TABLE identity.action_log
    ADD COLUMN seq       bigint,
    ADD COLUMN prev_hash bytea,
    ADD COLUMN hash      bytea;

-- The version 1 form of an entry: one UTF-8 text of nine lines, joined by LF. No field holds a control
-- character (the action grammar and the subject check forbid it), so the lines cannot run into each other.
-- Go computes the same text in internal/identity, and a test holds the two to one vector.
-- +goose StatementBegin
CREATE FUNCTION identity.action_log_hash(
    p_prev        bytea,
    p_seq         bigint,
    p_id          uuid,
    p_at          timestamptz,
    p_principal   uuid,
    p_responsible uuid,
    p_action      text,
    p_subject     text
) RETURNS bytea
    LANGUAGE sql STABLE
    SET search_path = pg_catalog, pg_temp
AS $$
    SELECT sha256(convert_to(
        'ipso-audit-log/1' || chr(10)
        || encode(p_prev, 'hex') || chr(10)
        || p_seq::text || chr(10)
        || p_id::text || chr(10)
        || to_char(p_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"') || chr(10)
        || p_principal::text || chr(10)
        || p_responsible::text || chr(10)
        || p_action || chr(10)
        || p_subject,
        'UTF8'))
$$;
-- +goose StatementEnd

ALTER TABLE identity.action_log NO FORCE ROW LEVEL SECURITY;

-- +goose StatementBegin
DO $$
DECLARE
    r           record;
    cur_tenant  uuid;
    cur_seq     bigint := 0;
    cur_hash    bytea;
    prev        bytea;
BEGIN
    FOR r IN
        SELECT a.tenant_id, a.id, a.principal_id, a.responsible_id, a.action, a.subject,
               lower(a.sys_period) AS at
        FROM identity.action_log a
        ORDER BY a.tenant_id, a.id
    LOOP
        IF cur_tenant IS DISTINCT FROM r.tenant_id THEN
            cur_tenant := r.tenant_id;
            cur_seq := 0;
            cur_hash := decode(repeat('00', 32), 'hex');
        END IF;
        prev := cur_hash;
        cur_seq := cur_seq + 1;
        cur_hash := identity.action_log_hash(
            prev, cur_seq, r.id, r.at, r.principal_id, r.responsible_id, r.action, r.subject);
        UPDATE identity.action_log
        SET seq = cur_seq, prev_hash = prev, hash = cur_hash
        WHERE tenant_id = r.tenant_id AND id = r.id;
    END LOOP;
END;
$$;
-- +goose StatementEnd

ALTER TABLE identity.action_log FORCE ROW LEVEL SECURITY;

ALTER TABLE identity.action_log
    ALTER COLUMN seq SET NOT NULL,
    ALTER COLUMN prev_hash SET NOT NULL,
    ALTER COLUMN hash SET NOT NULL,
    ADD CONSTRAINT action_log_seq CHECK (seq >= 1),
    ADD CONSTRAINT action_log_hashes CHECK (octet_length(prev_hash) = 32 AND octet_length(hash) = 32),
    ADD CONSTRAINT action_log_chain_position UNIQUE (tenant_id, seq);

-- The stamp trigger already names the person responsible. It now also takes the lock of the tenant,
-- reads the head of the chain in a later statement, and writes the time, the position and both hashes. The
-- lock and the read are separate statements on purpose, as in registry.supersession_check (migration
-- 00004): in READ COMMITTED each statement takes a new snapshot, so the read sees an append that committed
-- while this one waited. The trigger is named after action_log_open_sys_period, so it runs after it and its
-- time wins. A collision of the lock key only adds waiting.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION identity.action_log_stamp() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    sponsor   uuid;
    last_seq  bigint;
    last_hash bytea;
BEGIN
    IF current_setting('transaction_isolation') <> 'read committed' THEN
        RAISE EXCEPTION 'an action is logged in a read committed transaction'
            USING ERRCODE = 'feature_not_supported';
    END IF;

    SELECT p.sponsor_id INTO sponsor
    FROM identity.principal p
    WHERE p.tenant_id = NEW.tenant_id
      AND p.id = NEW.principal_id;

    IF NOT FOUND THEN
        RAISE EXCEPTION 'the action names no principal in this tenant'
            USING ERRCODE = 'foreign_key_violation';
    END IF;
    NEW.responsible_id := coalesce(sponsor, NEW.principal_id);

    -- Held until this transaction ends. The read below must stay in a later statement.
    PERFORM pg_advisory_xact_lock(hashtextextended(NEW.tenant_id::text, 68));

    SELECT a.seq, a.hash INTO last_seq, last_hash
    FROM identity.action_log a
    WHERE a.tenant_id = NEW.tenant_id
    ORDER BY a.seq DESC
    LIMIT 1;
    IF NOT FOUND THEN
        last_seq := 0;
        last_hash := decode(repeat('00', 32), 'hex');
    END IF;

    NEW.sys_period := tstzrange(clock_timestamp(), NULL);
    NEW.seq := last_seq + 1;
    NEW.prev_hash := last_hash;
    NEW.hash := identity.action_log_hash(
        last_hash, NEW.seq, NEW.id, lower(NEW.sys_period),
        NEW.principal_id, NEW.responsible_id, NEW.action, NEW.subject);
    RETURN NEW;
END;
$$;
-- +goose StatementEnd

-- +goose StatementBegin
CREATE FUNCTION identity.action_log_refuse() RETURNS trigger
    LANGUAGE plpgsql
    SET search_path = pg_catalog, pg_temp
AS $$
BEGIN
    RAISE EXCEPTION 'the action log is append-only'
        USING ERRCODE = 'insufficient_privilege';
END;
$$;
-- +goose StatementEnd

CREATE TRIGGER action_log_append_only
    BEFORE UPDATE OR DELETE ON identity.action_log
    FOR EACH ROW EXECUTE FUNCTION identity.action_log_refuse();

CREATE TRIGGER action_log_no_truncate
    BEFORE TRUNCATE ON identity.action_log
    FOR EACH STATEMENT EXECUTE FUNCTION identity.action_log_refuse();

-- The head of the chain when the tenant was offboarded, so that a customer holding a copy of the log can
-- show that it is complete and unaltered after the tenant is gone. Both are null when the log was empty
-- and for a tombstone written before this migration.
ALTER TABLE tenancy.offboarding
    ADD COLUMN log_seq  bigint,
    ADD COLUMN log_hash bytea,
    ADD CONSTRAINT offboarding_log_head CHECK (
        (log_seq IS NULL AND log_hash IS NULL)
        OR (log_seq >= 1 AND octet_length(log_hash) = 32));

REVOKE ALL ON FUNCTION identity.action_log_hash(bytea, bigint, uuid, timestamptz, uuid, uuid, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.action_log_stamp() FROM PUBLIC;
REVOKE ALL ON FUNCTION identity.action_log_refuse() FROM PUBLIC;
-- The stamp trigger runs as the caller and calls the hash function, so the caller needs to execute it.
GRANT EXECUTE ON FUNCTION identity.action_log_hash(bytea, bigint, uuid, timestamptz, uuid, uuid, text, text) TO ipso_app;
