-- +goose Up
-- An index for the uploads of one commit (IPSO-164, ADR-0124).
--
-- Audit question Q3 reads the uploads of a repository and a commit, and the only index of the table is by
-- repository and recency, so the read would scan every upload the repository ever made. The index holds the
-- repository name and the commit that the table already holds, so it adds no data, and it sits under the
-- policies of its table. It adds no column, trigger, route or privilege.
CREATE INDEX upload_repo_sha ON verification.upload (tenant_id, repo, sha);
