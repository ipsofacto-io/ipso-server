-- +goose Up
-- River v0.51.0, riverdriver/riverpgxv5/migration/main:
-- 003_river_job_tags_non_null.up.sql
-- The schema template is replaced by river. and trailing whitespace is removed. Nothing else
-- differs (IPSO-136, ADR-0097). One goose file for each River version, because River runs each
-- version in its own transaction: 004 adds an enum value that 006 reads. River's version 001 only
-- creates river_migration, which goose replaces as the one ledger (ADR-0050), and River's 005 skips
-- what it renames when river_migration is absent.
ALTER TABLE river.river_job ALTER COLUMN tags SET DEFAULT '{}';
UPDATE river.river_job SET tags = '{}' WHERE tags IS NULL;
ALTER TABLE river.river_job ALTER COLUMN tags SET NOT NULL;
