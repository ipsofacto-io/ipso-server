-- +goose Up
-- Outbound Slack and Teams digests (IPSO-70, ADR-0138).
--
-- integrations.chat_destination is one sealed webhook URL per connector per tenant.
-- The row is not exported. integrations.chat_delivery records a notice or an open
-- premise reason after the post succeeds, so a restore does not send it again.
-- Neither table stores a message body.

CREATE TABLE integrations.chat_destination (
    id         uuid      NOT NULL DEFAULT uuidv7(),
    tenant_id  uuid      NOT NULL,
    connector  text      NOT NULL,
    url_sealed bytea     NOT NULL,
    sys_period tstzrange NOT NULL DEFAULT tstzrange(clock_timestamp(), NULL),
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT chat_destination_once UNIQUE (tenant_id, connector),
    CONSTRAINT chat_destination_tenant FOREIGN KEY (tenant_id) REFERENCES tenancy.tenant (tenant_id),
    CONSTRAINT chat_destination_connector CHECK (connector IN ('slack', 'teams')),
    CONSTRAINT chat_destination_url CHECK (octet_length(url_sealed) BETWEEN 29 AND 8192),
    CONSTRAINT chat_destination_sys_period_open CHECK (upper(sys_period) IS NULL)
);

CREATE TRIGGER chat_destination_open_sys_period
    BEFORE INSERT ON integrations.chat_destination
    FOR EACH ROW EXECUTE FUNCTION registry.open_sys_period();

CREATE TABLE integrations.chat_delivery (
    tenant_id  uuid      NOT NULL,
    id         uuid      NOT NULL DEFAULT uuidv7(),
    connector  text      NOT NULL,
    kind       text      NOT NULL,
    subject_id uuid      NOT NULL,
    sys_period tstzrange NOT NULL DEFAULT tstzrange(clock_timestamp(), NULL),
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT chat_delivery_once UNIQUE (tenant_id, connector, kind, subject_id),
    CONSTRAINT chat_delivery_tenant FOREIGN KEY (tenant_id) REFERENCES tenancy.tenant (tenant_id),
    CONSTRAINT chat_delivery_connector CHECK (connector IN ('slack', 'teams')),
    CONSTRAINT chat_delivery_kind CHECK (kind IN ('waiver', 'premise')),
    CONSTRAINT chat_delivery_sys_period_open CHECK (upper(sys_period) IS NULL)
);

CREATE TRIGGER chat_delivery_open_sys_period
    BEFORE INSERT ON integrations.chat_delivery
    FOR EACH ROW EXECUTE FUNCTION registry.open_sys_period();

ALTER TABLE integrations.chat_destination ENABLE ROW LEVEL SECURITY;
ALTER TABLE integrations.chat_destination FORCE ROW LEVEL SECURITY;
ALTER TABLE integrations.chat_delivery ENABLE ROW LEVEL SECURITY;
ALTER TABLE integrations.chat_delivery FORCE ROW LEVEL SECURITY;

CREATE POLICY app_select ON integrations.chat_destination FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON integrations.chat_destination FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY app_delete ON integrations.chat_destination FOR DELETE TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_select ON integrations.chat_delivery FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON integrations.chat_delivery FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());

CREATE POLICY migrate_select ON integrations.chat_destination FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON integrations.chat_destination FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_select ON integrations.chat_delivery FOR SELECT TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_insert ON integrations.chat_delivery FOR INSERT TO ipso_migrate
    WITH CHECK (tenant_id = ipso.current_tenant());
CREATE POLICY migrate_delete ON integrations.chat_delivery FOR DELETE TO ipso_migrate
    USING (tenant_id = ipso.current_tenant());

GRANT SELECT, INSERT, DELETE ON integrations.chat_destination TO ipso_app;
GRANT SELECT, INSERT ON integrations.chat_delivery TO ipso_app;
