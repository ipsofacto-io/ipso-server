//go:build integration

// Package pgtest starts a throwaway PostgreSQL 18 server for the integration tests.
//
// The server has one superuser and four login roles that mirror the install of ADR-0050:
// the migration role that owns each database, the application role, a role with BYPASSRLS
// that the migrate command must refuse, and a role that switches to that BYPASSRLS role at
// connect time. Every password is random for the run. Every row the tests write is synthetic.
package pgtest

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

// image is pinned by tag and digest so a run never picks up a different server build.
const image = "postgres:18.6@sha256:979bccfde35445db618c65107d27d08c6c21339d8dc3ad4c830c6633947be0e4"

// Login role names.
const (
	// Admin is the superuser the container starts with.
	Admin = "postgres"
	// Migrate owns every test database. It has no superuser, BYPASSRLS, or CREATEROLE.
	Migrate = "ipso_migrate"
	// App is the application role. It owns nothing.
	App = "ipso_app"
	// Bypass has BYPASSRLS.
	Bypass = "ipso_bypass"
	// Member is a plain role that is a member of Bypass.
	Member = "ipso_member"
)

// Server is one PostgreSQL container shared by the tests of a package.
type Server struct {
	container *postgres.PostgresContainer
	endpoint  string
	passwords map[string]string
	databases atomic.Int64
}

// Start runs the container and creates the roles.
func Start(ctx context.Context) (*Server, error) {
	passwords := make(map[string]string)
	for _, role := range []string{Admin, Migrate, App, Bypass, Member} {
		password, err := randomPassword()
		if err != nil {
			return nil, err
		}
		passwords[role] = password
	}

	container, err := postgres.Run(ctx, image,
		postgres.WithUsername(Admin),
		postgres.WithPassword(passwords[Admin]),
		postgres.WithDatabase("postgres"),
		postgres.BasicWaitStrategies(),
	)
	if err != nil {
		if container != nil {
			_ = testcontainers.TerminateContainer(container)
		}
		return nil, fmt.Errorf("start postgres: %w", err)
	}
	endpoint, err := container.PortEndpoint(ctx, "5432/tcp", "")
	if err != nil {
		_ = testcontainers.TerminateContainer(container)
		return nil, fmt.Errorf("postgres endpoint: %w", err)
	}

	s := &Server{container: container, endpoint: endpoint, passwords: passwords}
	if err := s.createRoles(ctx); err != nil {
		_ = s.Terminate()
		return nil, err
	}
	return s, nil
}

// Terminate removes the container.
func (s *Server) Terminate() error {
	return testcontainers.TerminateContainer(s.container)
}

func (s *Server) createRoles(ctx context.Context) error {
	admin, err := sql.Open("pgx", s.dsn(Admin, "postgres", ""))
	if err != nil {
		return err
	}
	defer func() { _ = admin.Close() }()

	for _, role := range []string{Migrate, App, Bypass, Member} {
		// The server quotes the identifier and the password, so no SQL is formatted here.
		var statement string
		err := admin.QueryRowContext(ctx,
			`SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', $1::text, $2::text)`,
			role, s.passwords[role]).Scan(&statement)
		if err != nil {
			return fmt.Errorf("format create role %s: %w", role, err)
		}
		if _, err := admin.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("create role %s: %w", role, err)
		}
	}
	for _, statement := range []string{
		`ALTER ROLE ipso_bypass BYPASSRLS`,
		`GRANT ipso_bypass TO ipso_member`,
	} {
		if _, err := admin.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("%s: %w", statement, err)
		}
	}
	return nil
}

// NewDatabase creates an empty database owned by the migration role, which is the state the
// install leaves before the first migrate run. The container is thrown away with the run, so
// the database is not dropped.
func (s *Server) NewDatabase(t testing.TB) *Database {
	t.Helper()
	ctx := t.Context()
	name := fmt.Sprintf("ipso_test_%d", s.databases.Add(1))

	admin, err := sql.Open("pgx", s.dsn(Admin, "postgres", ""))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admin.Close() }()

	var create string
	if err := admin.QueryRowContext(ctx,
		`SELECT format('CREATE DATABASE %I OWNER ipso_migrate', $1::text)`, name).Scan(&create); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.ExecContext(ctx, create); err != nil {
		t.Fatal(err)
	}
	return &Database{server: s, name: name}
}

// Database is one empty database on the shared server.
type Database struct {
	server *Server
	name   string
}

// DSN returns the connection string for a login role.
func (d *Database) DSN(role string) string {
	return d.server.dsn(role, d.name, "")
}

// DSNSwitchingRole returns the connection string for a login role whose session switches to
// another role at connect time, so session_user and current_user differ.
func (d *Database) DSNSwitchingRole(login, switchTo string) string {
	return d.server.dsn(login, d.name, "-c role="+switchTo)
}

// Open returns a connection pool for a login role. It is closed when the test ends.
func (d *Database) Open(t testing.TB, role string) *sql.DB {
	t.Helper()
	db, err := sql.Open("pgx", d.DSN(role))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func (s *Server) dsn(role, database, options string) string {
	query := url.Values{"sslmode": {"disable"}}
	if options != "" {
		query.Set("options", options)
	}
	u := url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(role, s.passwords[role]),
		Host:   s.endpoint,
		Path:   "/" + database,
		// pgx reads a "+" in a URL query as a plus sign, so a space must be %20.
		RawQuery: strings.ReplaceAll(query.Encode(), "+", "%20"),
	}
	return u.String()
}

func randomPassword() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}
