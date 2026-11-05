-- +goose Up
-- River v0.51.0, riverdriver/riverpgxv5/migration/main:
-- 004_pending_and_more.up.sql
-- The schema template is replaced by river. and trailing whitespace is removed. Nothing else
-- differs (IPSO-136, ADR-0097). One goose file for each River version, because River runs each
-- version in its own transaction: 004 adds an enum value that 006 reads. River's version 001 only
-- creates river_migration, which goose replaces as the one ledger (ADR-0050), and River's 005 skips
-- what it renames when river_migration is absent.
-- The args column never had a NOT NULL constraint or default value at the
-- database level, though we tried to ensure one at the application level.
ALTER TABLE river.river_job ALTER COLUMN args SET DEFAULT '{}';
UPDATE river.river_job SET args = '{}' WHERE args IS NULL;
ALTER TABLE river.river_job ALTER COLUMN args SET NOT NULL;
ALTER TABLE river.river_job ALTER COLUMN args DROP DEFAULT;

-- The metadata column never had a NOT NULL constraint or default value at the
-- database level, though we tried to ensure one at the application level.
ALTER TABLE river.river_job ALTER COLUMN metadata SET DEFAULT '{}';
UPDATE river.river_job SET metadata = '{}' WHERE metadata IS NULL;
ALTER TABLE river.river_job ALTER COLUMN metadata SET NOT NULL;

-- The 'pending' job state will be used for upcoming functionality:
ALTER TYPE river.river_job_state ADD VALUE IF NOT EXISTS 'pending' AFTER 'discarded';

ALTER TABLE river.river_job DROP CONSTRAINT finalized_or_finalized_at_null;
ALTER TABLE river.river_job ADD CONSTRAINT finalized_or_finalized_at_null CHECK (
    (finalized_at IS NULL AND state NOT IN ('cancelled', 'completed', 'discarded')) OR
    (finalized_at IS NOT NULL AND state IN ('cancelled', 'completed', 'discarded'))
);

DROP TRIGGER river_notify ON river.river_job;
DROP FUNCTION river.river_job_notify;

--
-- Create table `river_queue`.
--

CREATE TABLE river.river_queue (
    name text PRIMARY KEY NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    metadata jsonb NOT NULL DEFAULT '{}' ::jsonb,
    paused_at timestamptz,
    updated_at timestamptz NOT NULL
);

--
-- Alter `river_leader` to add a default value of 'default` to `name`.
--

ALTER TABLE river.river_leader
    ALTER COLUMN name SET DEFAULT 'default',
    DROP CONSTRAINT name_length,
    ADD CONSTRAINT name_length CHECK (name = 'default');
