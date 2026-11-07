package controlplane

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/time/rate"

	"github.com/ipsofacto-io/ipso-server/internal/api"
	"github.com/ipsofacto-io/ipso-server/internal/authn"
	"github.com/ipsofacto-io/ipso-server/internal/integrations"
	"github.com/ipsofacto-io/ipso-server/internal/ratelimit"
	"github.com/ipsofacto-io/ipso-server/internal/tenancy"
)

const (
	// repositoryTTL is how long the installation of a repository is kept. Only the GitHub answer is kept.
	// The tenant of an installation is read from the database on every upload, so offboarding takes
	// effect at once.
	repositoryTTL = time.Minute
	// maxKnownRepositories bounds the cache.
	maxKnownRepositories = 4096
	// appCallRate and appCallBurst bound the calls this process makes to GitHub for a repository it has
	// not kept. Anyone can mint a token for any repository with our audience, so those calls must not
	// scale with what a stranger sends.
	appCallRate  = 1
	appCallBurst = 10
)

// Repositories is the GitHub App as the upload route uses it: it checks the App at start and says which
// installation covers a repository.
type Repositories interface {
	Verify(ctx context.Context) error
	RepositoryInstallation(ctx context.Context, owner, name string) (integrations.Installation, error)
}

type repositoryKey struct {
	id   int64
	name string
}

// uploadMapper maps the repository of a verified CI token to the tenant that owns it: GitHub says which
// installation of this App covers the repository (ADR-0101 decision 6), and the database says which tenant
// owns that installation. Nothing the uploader sends is read.
type uploadMapper struct {
	db     *sql.DB
	tenant uuid.UUID
	apps   Repositories
	known  *ttlCache[repositoryKey, integrations.Installation]
	misses *ratelimit.Limiter
	now    func() time.Time
	log    *slog.Logger
}

func newUploadMapper(db *sql.DB, tenant uuid.UUID, apps Repositories, log *slog.Logger) *uploadMapper {
	return &uploadMapper{
		db:     db,
		tenant: tenant,
		apps:   apps,
		known:  newTTLCache[repositoryKey, integrations.Installation](repositoryTTL, maxKnownRepositories),
		misses: ratelimit.New(rate.Limit(appCallRate), appCallBurst),
		now:    time.Now,
		log:    log,
	}
}

// lookup answers which tenant a run belongs to. A repository that no installation of this App covers, an
// installation on another account than the repository's owner, an installation no tenant owns, and one that
// another tenant owns are all MappingUnknown, so a caller learns nothing about who else is bound.
func (m *uploadMapper) lookup(ctx context.Context, run authn.RunClaims) (api.Mapping, api.MappingStatus) {
	now := m.now()
	key := repositoryKey{id: run.RepositoryID, name: strings.ToLower(run.Owner + "/" + run.Name)}
	installation, ok := m.known.get(key, now)
	if !ok {
		// Only a miss costs a call to GitHub, and misses share one budget on this process.
		if _, allowed := m.misses.Allow(uuid.Nil, now); !allowed {
			return api.Mapping{}, api.MappingBusy
		}
		var err error
		installation, err = m.apps.RepositoryInstallation(ctx, run.Owner, run.Name)
		switch {
		case errors.Is(err, integrations.ErrNotFound):
			return api.Mapping{}, api.MappingUnknown
		case err != nil:
			// The error is reduced to a status by integrations. It never holds a token or a body.
			m.log.Warn("GitHub could not say which installation covers a repository", "repository_id", run.RepositoryID, "error", err.Error())
			return api.Mapping{}, api.MappingFailed
		}
		m.known.put(key, installation, now)
	}
	// The installation has to be on the account that owns the repository, as the signed token says.
	if installation.AccountID != run.OwnerID {
		return api.Mapping{}, api.MappingUnknown
	}
	tenant, found, err := tenancy.InstallationTenant(ctx, m.db, installation.ID)
	if err != nil {
		m.log.Warn("the tenant of an installation could not be read", "installation", installation.ID, "error", err.Error())
		return api.Mapping{}, api.MappingFailed
	}
	if !found || tenant != m.tenant {
		return api.Mapping{}, api.MappingUnknown
	}
	return api.Mapping{Tenant: tenant, Installation: installation.ID}, api.MappingFound
}
