-- +goose Up
-- What ipso_app needs in schema river, and nothing else (IPSO-136, ADR-0097). The role owns nothing
-- here: ipso_migrate made every relation and keeps the right to change it.
--
-- River's queries on PostgreSQL read and write river_job, river_leader, and river_queue, and draw job
-- ids from river_job_id_seq. They never touch river_notification, which only River's SQLite driver
-- uses, so the role has no privilege on it. The role has no TRUNCATE and does not own the tables, so
-- River's own reindexer, which needs ownership or MAINTAIN, is switched off in the worker. Reindexing
-- river_job is operations work (ADR-0096).
--
-- The function that River's unique insert and the unique-job index call follows the rule of every ipso
-- function: no PUBLIC, and EXECUTE for ipso_app only.
GRANT USAGE ON SCHEMA river TO ipso_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON river.river_job, river.river_leader, river.river_queue TO ipso_app;
GRANT USAGE, SELECT ON SEQUENCE river.river_job_id_seq TO ipso_app;
REVOKE ALL ON FUNCTION river.river_job_state_in_bitmask(bit, river.river_job_state) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION river.river_job_state_in_bitmask(bit, river.river_job_state) TO ipso_app;
