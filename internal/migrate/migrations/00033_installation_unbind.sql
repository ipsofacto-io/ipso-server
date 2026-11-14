-- +goose Up
-- The application role removes the binding of an installation that GitHub deleted (IPSO-143, ADR-0125).
--
-- 00025 let the application role read and insert its own tenant's bindings and gave it no DELETE, so only
-- offboarding removed one. The webhooks process runs as the application role, and when GitHub confirms that an
-- installation is gone it removes the binding. It takes the tenant from tenancy.installation_tenant and never
-- from the payload, sets ipso.tenant to it, and deletes the row, so this policy lets it remove that one tenant's
-- binding and nothing else. It is the delete policy every other tenant table that the application role deletes
-- from has. UPDATE stays refused, so a binding still never moves to another tenant, and the delete policy of
-- the migration role keeps no arm for a session with no tenant.
CREATE POLICY app_delete ON tenancy.installation
    FOR DELETE TO ipso_app
    USING (tenant_id = ipso.current_tenant());

GRANT DELETE ON tenancy.installation TO ipso_app;
