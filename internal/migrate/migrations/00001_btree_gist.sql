-- +goose Up
-- The temporal primary key of registry.decision_version is backed by a GiST index and needs
-- btree_gist for the uuid columns. The extension is trusted, so the database owner creates it.
-- IF NOT EXISTS lets an administrator create it first on a managed service that blocks it for
-- the owner (ADR-0050).
CREATE EXTENSION IF NOT EXISTS btree_gist;
