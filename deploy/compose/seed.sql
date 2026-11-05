-- Single-tenant mode (section 10, ADR-0093): one tenant row, one person, and the login that binds
-- the identity provider's subject for that person to the person. It runs as the application role with
-- ipso.tenant set, so the row-level security policies decide what it may write, and it is safe to
-- run again. Variables come from psql -v.
BEGIN;
SELECT set_config('ipso.tenant', :'tenant', true);
INSERT INTO tenancy.tenant (tenant_id, name)
VALUES (:'tenant', 'local')
ON CONFLICT DO NOTHING;
INSERT INTO identity.principal (tenant_id, id, kind, name)
VALUES (:'tenant', :'person', 'human', 'Local developer')
ON CONFLICT DO NOTHING;
INSERT INTO identity.login (tenant_id, principal_id, issuer, subject)
VALUES (:'tenant', :'person', :'issuer', :'subject')
ON CONFLICT DO NOTHING;
COMMIT;
