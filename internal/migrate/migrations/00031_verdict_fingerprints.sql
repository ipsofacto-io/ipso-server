-- +goose Up
-- The digests of the violations of one check, from a version 2 verdict report (IPSO-156, ADR-0122).
--
-- The runner computes them under the salt that stays in its repository (ADR-0059), so the server holds
-- digests and never a path, an address or a message. They are what registry.Grandfather compares with the
-- recorded baseline of the decision and repository when a verdict is read (ADR-0052 decision 6). The column
-- is insert-only like the rest of the table, and the application role still cannot update it.
--
-- The column is null when the report sent none: a version 1 report, a check with no baseline on the
-- runner, a waiver, an error, or a violation that has no identity. A list that has no digest is stored as
-- null and never as an empty array. A restore of an archive written before this column reads null.
--
-- A waived verdict holds exactly the digests of its violations, because a local baseline that covers a
-- check covers all of it. A failed verdict holds every digest of the check, covered or not, so it holds at
-- least as many as the violations it counts, which are only the uncovered ones.
ALTER TABLE verification.verdict
    ADD COLUMN fingerprints bytea[],
    ADD CONSTRAINT verdict_fingerprints_bound CHECK (
        fingerprints IS NULL
        OR (cardinality(fingerprints) BETWEEN 1 AND 100000
            AND array_position(fingerprints, NULL) IS NULL)),
    ADD CONSTRAINT verdict_fingerprints_result CHECK (
        fingerprints IS NULL
        OR (result = 'waived' AND cardinality(fingerprints) = violations)
        OR (result = 'fail' AND cardinality(fingerprints) >= violations));

-- The function that guards registry.baseline refuses an entry that is not 32 bytes and a repeated entry.
-- It names the column and nothing else, so it serves this table the same way. The upload parser has
-- refused both before this runs, and the trigger holds when the parser is bypassed.
CREATE TRIGGER verdict_check_fingerprints
    BEFORE INSERT ON verification.verdict
    FOR EACH ROW WHEN (NEW.fingerprints IS NOT NULL)
    EXECUTE FUNCTION registry.baseline_check_fingerprints();
