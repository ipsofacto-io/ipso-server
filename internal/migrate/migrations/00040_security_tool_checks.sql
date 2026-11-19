-- +goose Up
-- Security tool bindings (IPSO-74, ADR-0136).
--
-- snyk, wiz, sonarqube, and dependabot upload the same report shape as checkov:
-- evidence_sha256 and the verdict counts. The parser already accepts those names.
-- The table constraint still listed the earlier thirteen, so a valid upload failed
-- on insert. This replaces the check with the seventeen names.

ALTER TABLE verification.upload DROP CONSTRAINT upload_check_name;
ALTER TABLE verification.upload
    ADD CONSTRAINT upload_check_name CHECK (check_name IN (
        'plan', 'ci', 'checkov', 'snyk', 'wiz', 'sonarqube', 'dependabot',
        'pulumi', 'cloudformation', 'arm', 'depcruise', 'semgrep',
        'archunit', 'importlinter', 'kyverno', 'gatekeeper', 'eslint'));
