-- +goose Up
-- River v0.51.0, riverdriver/riverpgxv5/migration/main:
-- 007_notification_outbox_sqlite_jsonb_and_sql_cleanup.up.sql
-- The schema template is replaced by river. and trailing whitespace is removed. Nothing else
-- differs (IPSO-136, ADR-0097). One goose file for each River version, because River runs each
-- version in its own transaction: 004 adds an enum value that 006 reads. River's version 001 only
-- creates river_migration, which goose replaces as the one ledger (ADR-0050), and River's 005 skips
-- what it renames when river_migration is absent.
--
-- Notification outbox.
--

CREATE TABLE river.river_notification (
    id bigserial PRIMARY KEY,
    created_at timestamptz NOT NULL DEFAULT now(),
    payload text NOT NULL,
    topic text NOT NULL,
    CONSTRAINT topic_length CHECK (length(topic) > 0 AND length(topic) < 128)
);

CREATE INDEX river_notification_created_at_idx ON river.river_notification (created_at);
CREATE INDEX river_notification_topic_id_idx ON river.river_notification (topic, id);

--
-- SQLite JSONB conversion.
--
-- No-op. Postgres already stores River JSON columns as jsonb.

--
-- SQL cleanup.
--

--
-- Drop unused tables `river_client` and `river_client_queue`.
--

DROP TABLE river.river_client_queue;
DROP TABLE river.river_client;

--
-- Adds `DEFAULT 25` to `river_job.max_attempts`.
--

ALTER TABLE river.river_job
    ALTER COLUMN max_attempts SET DEFAULT 25;

--
-- Changes `river_queue.updated_at` to have a default of `CURRENT_TIMESTAMP`.
--

ALTER TABLE river.river_queue
    ALTER COLUMN updated_at SET DEFAULT CURRENT_TIMESTAMP;
