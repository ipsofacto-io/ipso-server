// Package eehooks is the registration point the enterprise binary uses to add SAML and SCIM
// without the community binary importing it (ADR-0131). The default gate denies sso.saml.
package eehooks

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync"

	"github.com/google/uuid"
)

// FeatureSAML is the feature key that gates SAML sign-in and SCIM together (ADR-0018).
const FeatureSAML = "sso.saml"

// Gate says whether a feature key is allowed for this process.
type Gate interface {
	Allow(feature string) bool
}

type denyAll struct{}

func (denyAll) Allow(string) bool { return false }

var (
	mu   sync.RWMutex
	gate Gate = denyAll{}
)

// SetGate replaces the process gate. A nil gate denies every key.
func SetGate(g Gate) {
	mu.Lock()
	defer mu.Unlock()
	if g == nil {
		gate = denyAll{}
		return
	}
	gate = g
}

// Allow reports whether the process gate allows feature.
func Allow(feature string) bool {
	mu.RLock()
	defer mu.RUnlock()
	return gate.Allow(feature)
}

// BrowserLogin is one registered sign-in kind. requestID is the id this process put in the
// request, and the callback requires the response to name it.
type BrowserLogin interface {
	RedirectURL(requestID string) string
	Subject(ctx context.Context, body []byte, requestID string) (issuer, subject string, err error)
	Metadata() []byte
	Issuer() string
}

// KindConfig is what a registered kind needs at start. The HTTP client does not follow redirects.
type KindConfig struct {
	ID          string
	MetadataURL string
	ACS         string
	EntityID    string
	Client      *http.Client
}

// KindFactory builds one provider. A failure stops the process, the way OIDC discovery does.
type KindFactory func(ctx context.Context, cfg KindConfig) (BrowserLogin, error)

var kinds = map[string]KindFactory{}

// RegisterKind adds a provider kind. The community binary registers none, so an unknown kind
// still refuses to start.
func RegisterKind(kind string, factory KindFactory) {
	mu.Lock()
	defer mu.Unlock()
	if kind == "" || factory == nil {
		return
	}
	kinds[kind] = factory
}

// UnregisterKind removes a kind. Tests use it to leave the process as they found it.
func UnregisterKind(kind string) {
	mu.Lock()
	defer mu.Unlock()
	delete(kinds, kind)
}

// LookupKind returns the factory for kind.
func LookupKind(kind string) (KindFactory, bool) {
	mu.RLock()
	defer mu.RUnlock()
	factory, ok := kinds[kind]
	return factory, ok
}

// User is one SCIM user. ID is the principal id and the SCIM id.
type User struct {
	ID         uuid.UUID
	ExternalID string
	UserName   string
	Name       string
	Active     bool
}

// GroupRole is one IdP group mapped to a role. ScopeID is uuid.Nil for the whole tenant.
type GroupRole struct {
	ID       uuid.UUID
	GroupRef string
	Role     string
	ScopeID  uuid.UUID
}

// Group is one SCIM group. Ref is the value a group-role row matches.
type Group struct {
	ID  uuid.UUID
	Ref string
}

// Sentinel errors the directory returns. Callers map them to HTTP statuses.
var (
	ErrLastAdmin = errors.New("last admin")
	ErrNotFound  = errors.New("not found")
	ErrInvalid   = errors.New("invalid")
	ErrConflict  = errors.New("conflict")
)

// Directory is the identity operations SCIM and the admin routes call. The server installs one
// bound to the process tenant and the one SAML issuer.
type Directory interface {
	Provision(ctx context.Context, externalID, userName, name string) (User, bool, error)
	SetActive(ctx context.Context, externalID string, active bool) error
	UpdateUserName(ctx context.Context, externalID, userName string) error
	SetName(ctx context.Context, externalID, name string) error
	ReplaceUser(ctx context.Context, externalID, userName, name string, active *bool) error
	UserByID(ctx context.Context, id uuid.UUID) (User, error)
	UserByExternalID(ctx context.Context, externalID string) (User, error)
	UserByUserName(ctx context.Context, userName string) (User, error)
	CreateGroup(ctx context.Context, ref string) (Group, error)
	Group(ctx context.Context, id uuid.UUID) (Group, error)
	GroupByRef(ctx context.Context, ref string) (Group, error)
	ReplaceGroupMembers(ctx context.Context, id uuid.UUID, members []uuid.UUID) error
	Members(ctx context.Context, id uuid.UUID) ([]uuid.UUID, error)
	DeleteGroup(ctx context.Context, id uuid.UUID) error
	PutToken(ctx context.Context, actor uuid.UUID, hash []byte) error
	TokenOK(ctx context.Context, token []byte) (bool, error)
	PutGroupRole(ctx context.Context, actor uuid.UUID, groupRef, role string, scope uuid.UUID) (GroupRole, error)
	ListGroupRoles(ctx context.Context) ([]GroupRole, error)
	DeleteGroupRole(ctx context.Context, actor, id uuid.UUID) error
}

var directory Directory

// SetDirectory installs the directory. A nil directory clears it.
func SetDirectory(d Directory) {
	mu.Lock()
	defer mu.Unlock()
	directory = d
}

// CurrentDirectory returns the installed directory, or nil.
func CurrentDirectory() Directory {
	mu.RLock()
	defer mu.RUnlock()
	return directory
}

// GuardedRoute is one API route mounted only when sso.saml is allowed. The guard asks
// principal.manage before Serve runs. principal is the caller.
type GuardedRoute struct {
	Pattern string
	Op      string
	Serve   func(http.ResponseWriter, *http.Request, uuid.UUID)
}

var guarded []GuardedRoute

// RegisterGuarded appends admin routes. The community binary registers none.
func RegisterGuarded(routes []GuardedRoute) {
	mu.Lock()
	defer mu.Unlock()
	guarded = append(guarded, routes...)
}

// Guarded returns a copy of the admin routes.
func Guarded() []GuardedRoute {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]GuardedRoute, len(guarded))
	copy(out, guarded)
	return out
}

// MountContext is the mux the enterprise binary may attach /scim/v2 to.
type MountContext struct {
	Mux *http.ServeMux
	Log *slog.Logger
}

// MountFunc attaches routes. It runs only when sso.saml is allowed.
type MountFunc func(MountContext)

var mounts []MountFunc

// RegisterMount appends a mount. The community binary registers none.
func RegisterMount(fn MountFunc) {
	mu.Lock()
	defer mu.Unlock()
	if fn != nil {
		mounts = append(mounts, fn)
	}
}

// Mount runs the registered mounts when sso.saml is allowed.
func Mount(ctx MountContext) {
	if !Allow(FeatureSAML) || ctx.Mux == nil || CurrentDirectory() == nil {
		return
	}
	mu.RLock()
	fns := append([]MountFunc(nil), mounts...)
	mu.RUnlock()
	for _, fn := range fns {
		fn(ctx)
	}
}

// ResetForTest clears the gate, kinds, directory, routes, and mounts. A test that changes them
// calls it from t.Cleanup.
func ResetForTest() {
	mu.Lock()
	defer mu.Unlock()
	gate = denyAll{}
	kinds = map[string]KindFactory{}
	directory = nil
	guarded = nil
	mounts = nil
}
