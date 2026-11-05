-- +goose Up
-- The tenant a process serves and the logins that map a verified token to a principal of that
-- tenant, ADR-0093. A tenant row exists in every deployment, single-tenant or not, so the code paths
-- stay identical (section 10 of the specification). A login binds an issuer and a subject to one
-- principal. It stores no email address: an address can be reassigned, and a token that carried one
-- would then speak for someone else. Both tables are insert-only for the application role, and
-- both carry forced row-level security with the policies of 00013.
CREATE SCHEMA tenancy;

CREATE TABLE tenancy.tenant (
    tenant_id  uuid      NOT NULL,
    name       text      NOT NULL,
    sys_period tstzrange NOT NULL DEFAULT tstzrange(clock_timestamp(), NULL),
    PRIMARY KEY (tenant_id),
    CONSTRAINT tenant_name CHECK (
        char_length(name) BETWEEN 1 AND 200
        AND btrim(name) = name
        AND name !~ '[[:cntrl:]]'),
    CONSTRAINT tenant_sys_period_open CHECK (upper(sys_period) IS NULL)
);

CREATE TRIGGER tenant_open_sys_period
    BEFORE INSERT ON tenancy.tenant
    FOR EACH ROW EXECUTE FUNCTION registry.open_sys_period();

-- One person or agent can sign in through several issuers, and an issuer's subject is unique only
-- within that issuer, so the key is the three together. The foreign key to the principal holds the
-- tenant: a login cannot name a principal of another tenant.
CREATE TABLE identity.login (
    tenant_id    uuid      NOT NULL,
    id           uuid      NOT NULL DEFAULT uuidv7(),
    principal_id uuid      NOT NULL,
    issuer       text      NOT NULL,
    subject      text      NOT NULL,
    sys_period   tstzrange NOT NULL DEFAULT tstzrange(clock_timestamp(), NULL),
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT login_once UNIQUE (tenant_id, issuer, subject),
    CONSTRAINT login_tenant FOREIGN KEY (tenant_id)
        REFERENCES tenancy.tenant (tenant_id),
    CONSTRAINT login_principal FOREIGN KEY (tenant_id, principal_id)
        REFERENCES identity.principal (tenant_id, id),
    CONSTRAINT login_issuer CHECK (
        char_length(issuer) BETWEEN 9 AND 2000
        AND issuer ~ '^https://[^[:space:][:cntrl:]]+$'),
    CONSTRAINT login_subject CHECK (
        char_length(subject) BETWEEN 1 AND 255
        AND btrim(subject) = subject
        AND subject !~ '[[:cntrl:]]'),
    CONSTRAINT login_sys_period_open CHECK (upper(sys_period) IS NULL)
);

CREATE INDEX login_by_principal ON identity.login (tenant_id, principal_id);

CREATE TRIGGER login_open_sys_period
    BEFORE INSERT ON identity.login
    FOR EACH ROW EXECUTE FUNCTION registry.open_sys_period();

ALTER TABLE tenancy.tenant ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenancy.tenant FORCE ROW LEVEL SECURITY;
ALTER TABLE identity.login ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity.login FORCE ROW LEVEL SECURITY;

CREATE POLICY app_select ON tenancy.tenant
    FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON tenancy.tenant
    FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());

CREATE POLICY app_select ON identity.login
    FOR SELECT TO ipso_app
    USING (tenant_id = ipso.current_tenant());
CREATE POLICY app_insert ON identity.login
    FOR INSERT TO ipso_app
    WITH CHECK (tenant_id = ipso.current_tenant());

GRANT USAGE ON SCHEMA tenancy TO ipso_app;
GRANT SELECT, INSERT ON tenancy.tenant TO ipso_app;
GRANT SELECT, INSERT ON identity.login TO ipso_app;
