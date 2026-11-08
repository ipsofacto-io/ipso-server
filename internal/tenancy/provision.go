package tenancy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

var (
	// ErrOffboarded is returned when a tenant id has a tombstone. An id is never provisioned again.
	ErrOffboarded = errors.New("the tenant was offboarded")
	// ErrConflict is returned when a tenant, person or login exists with other attributes than the ones
	// asked for.
	ErrConflict = errors.New("it exists with other attributes")
)

// Person is the first person of a tenant and the login that binds an identity provider's subject to them
// (ADR-0093). The first person is the tenant's admin, so someone can grant the other roles (ADR-0108).
// Later people are bound by IPSO-137.
type Person struct {
	ID      uuid.UUID
	Name    string
	Issuer  string
	Subject string
}

// ProvisionOptions is what a new tenant needs.
type ProvisionOptions struct {
	Tenant uuid.UUID
	Name   string
	// Person is optional. A restore target is provisioned without one.
	Person *Person
	KEK    KEK
}

// ProvisionReport says what a run changed. A run that changes nothing is a repeat.
type ProvisionReport struct {
	Tenant      uuid.UUID `json:"tenant"`
	Created     bool      `json:"created"`
	KeyCreated  bool      `json:"key_created"`
	PersonBound bool      `json:"person_bound"`
}

// Provision creates a tenant: its row, its wrapped data key, and optionally its first person and login.
// It is one transaction as the application role, with ipso.tenant set to the new tenant, so row-level
// security shows it nothing of any other tenant and the same statements work in a deployment that serves
// that tenant. It is safe to run again with the same arguments, and it refuses different ones.
func Provision(ctx context.Context, db *sql.DB, o ProvisionOptions) (ProvisionReport, error) {
	report := ProvisionReport{Tenant: o.Tenant}
	switch {
	case db == nil:
		return report, errors.New("provision: a database is required")
	case o.Tenant == uuid.Nil:
		return report, errors.New("provision: a tenant id is required")
	case o.Name == "":
		return report, errors.New("provision: a tenant name is required")
	case o.KEK.aead == nil:
		return report, errors.New("provision: a key encryption key is required")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return report, reduce("provision: begin", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err := setSession(ctx, tx, o.Tenant, false); err != nil {
		return report, err
	}

	var gone bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM tenancy.offboarding WHERE tenant_id = $1)`, o.Tenant).Scan(&gone); err != nil {
		return report, reduce("provision: read the tombstone", err)
	}
	if gone {
		return report, fmt.Errorf("provision: %s: %w", o.Tenant, ErrOffboarded)
	}

	res, err := tx.ExecContext(ctx, `INSERT INTO tenancy.tenant (tenant_id, name) VALUES ($1, $2) ON CONFLICT DO NOTHING`, o.Tenant, o.Name)
	if err != nil {
		return report, reduce("provision: insert the tenant", err)
	}
	if n, _ := res.RowsAffected(); n == 1 {
		report.Created = true
	} else {
		var name string
		if err := tx.QueryRowContext(ctx, `SELECT name FROM tenancy.tenant WHERE tenant_id = $1`, o.Tenant).Scan(&name); err != nil {
			return report, reduce("provision: read the tenant", err)
		}
		if name != o.Name {
			return report, fmt.Errorf("provision: the tenant name: %w", ErrConflict)
		}
	}

	report.KeyCreated, err = ensureKey(ctx, tx, o)
	if err != nil {
		return report, err
	}
	if o.Person != nil {
		report.PersonBound, err = bindPerson(ctx, tx, o.Tenant, *o.Person)
		if err != nil {
			return report, err
		}
	}
	if err := tx.Commit(); err != nil {
		return report, reduce("provision: commit", err)
	}
	return report, nil
}

// ensureKey wraps a new data key for a tenant that has none. A tenant that has one must be able to open
// it with the key encryption key in use, so a wrong key is found when the tenant is provisioned and not
// when the first secret is sealed.
func ensureKey(ctx context.Context, tx *sql.Tx, o ProvisionOptions) (bool, error) {
	var wrapped []byte
	err := tx.QueryRowContext(ctx, `SELECT wrapped_dek FROM tenancy.tenant_key WHERE tenant_id = $1`, o.Tenant).Scan(&wrapped)
	switch {
	case err == nil:
		dek, err := o.KEK.Unwrap(o.Tenant, wrapped)
		clear(dek)
		if err != nil {
			return false, fmt.Errorf("provision: the stored key: %w", err)
		}
		return false, nil
	case !errors.Is(err, sql.ErrNoRows):
		return false, reduce("provision: read the key", err)
	}
	dek, err := newDataKey()
	if err != nil {
		return false, err
	}
	defer clear(dek)
	wrapped, err = o.KEK.Wrap(o.Tenant, dek)
	if err != nil {
		return false, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO tenancy.tenant_key (tenant_id, wrapped_dek) VALUES ($1, $2)`, o.Tenant, wrapped); err != nil {
		return false, reduce("provision: insert the key", err)
	}
	return true, nil
}

// bindPerson inserts the person, the login and the person's admin binding, and reports whether it wrote
// any of them. The admin binding is written only while the tenant has no admin, so a repeat writes
// nothing, a revoke of this person is kept while another admin exists, and a tenant left with no admin
// gets one again from create, the one way back in until IPSO-147.
func bindPerson(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, p Person) (bool, error) {
	if p.ID == uuid.Nil || p.Name == "" || p.Issuer == "" || p.Subject == "" {
		return false, errors.New("provision: a person needs an id, a name, an issuer and a subject")
	}
	wrote := false
	res, err := tx.ExecContext(ctx,
		`INSERT INTO identity.principal (tenant_id, id, kind, name) VALUES ($1, $2, 'human', $3) ON CONFLICT DO NOTHING`,
		tenant, p.ID, p.Name)
	if err != nil {
		return false, reduce("provision: insert the person", err)
	}
	if n, _ := res.RowsAffected(); n == 1 {
		wrote = true
	} else {
		var kind, name string
		if err := tx.QueryRowContext(ctx, `SELECT kind, name FROM identity.principal WHERE tenant_id = $1 AND id = $2`, tenant, p.ID).Scan(&kind, &name); err != nil {
			return false, reduce("provision: read the person", err)
		}
		if kind != "human" || name != p.Name {
			return false, fmt.Errorf("provision: the person: %w", ErrConflict)
		}
	}

	res, err = tx.ExecContext(ctx,
		`INSERT INTO identity.login (tenant_id, principal_id, issuer, subject) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`,
		tenant, p.ID, p.Issuer, p.Subject)
	if err != nil {
		return false, reduce("provision: insert the login", err)
	}
	if n, _ := res.RowsAffected(); n == 1 {
		wrote = true
	} else {
		var bound uuid.UUID
		if err := tx.QueryRowContext(ctx,
			`SELECT principal_id FROM identity.login WHERE tenant_id = $1 AND issuer = $2 AND subject = $3`,
			tenant, p.Issuer, p.Subject).Scan(&bound); err != nil {
			return false, reduce("provision: read the login", err)
		}
		if bound != p.ID {
			return false, fmt.Errorf("provision: the login: %w", ErrConflict)
		}
	}

	res, err = tx.ExecContext(ctx,
		`INSERT INTO identity.role_binding (tenant_id, principal_id, role)
		 SELECT $1::uuid, $2::uuid, 'admin'
		 WHERE NOT EXISTS (SELECT 1 FROM identity.role_binding WHERE tenant_id = $1::uuid AND role = 'admin')`,
		tenant, p.ID)
	if err != nil {
		return false, reduce("provision: bind the admin role", err)
	}
	if n, _ := res.RowsAffected(); n == 1 {
		wrote = true
	}
	return wrote, nil
}
