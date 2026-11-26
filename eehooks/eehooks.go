// Package eehooks is the registration point the enterprise binary uses to add SAML, SCIM,
// and paid tracker connectors without the community binary importing them (ADR-0131, ADR-0133).
// The default gate denies every key.
package eehooks

import (
	"context"
	"database/sql"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
)

// FeatureSAML is the feature key that gates SAML sign-in and SCIM together (ADR-0018).
const FeatureSAML = "sso.saml"

// FeatureTrackers is the feature key that gates Jira, Linear, and GitHub Issues (ADR-0133).
const FeatureTrackers = "connectors.trackers"

// FeatureChat is the feature key that gates outbound Slack and Teams digests (ADR-0138).
const FeatureChat = "connectors.chat"

// FeatureDataPlane is the feature key that gates the BYOC data-plane gateway (ADR-0144).
const FeatureDataPlane = "byoc.agent"

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

// CommandFunc runs an enterprise command and returns its exit code. args follow the command name. getenv
// is the environment the process was given, so a command reads nothing else.
type CommandFunc func(ctx context.Context, args []string, getenv func(string) string, stderr io.Writer) int

var commands = map[string]CommandFunc{}

// RegisterCommand adds a command to the process. The community binary registers none. A command whose name
// is one of the process's own is never reached, because those are answered first.
func RegisterCommand(name string, fn CommandFunc) {
	mu.Lock()
	defer mu.Unlock()
	if name == "" || fn == nil {
		return
	}
	commands[name] = fn
}

// Command returns the command registered under name.
func Command(name string) (CommandFunc, bool) {
	mu.RLock()
	defer mu.RUnlock()
	fn, ok := commands[name]
	return fn, ok
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

// GroupOwner is one IdP group mapped to a decision owner team.
type GroupOwner struct {
	ID       uuid.UUID
	GroupRef string
	OwnerRef string
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

// Directory is the identity operations SCIM and the admin routes call for one verified tenant.
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
	PutGroupRole(ctx context.Context, actor uuid.UUID, groupRef, role string, scope uuid.UUID) (GroupRole, error)
	ListGroupRoles(ctx context.Context) ([]GroupRole, error)
	DeleteGroupRole(ctx context.Context, actor, id uuid.UUID) error
	PutGroupOwner(ctx context.Context, actor uuid.UUID, groupRef, ownerRef string) (GroupOwner, error)
	ListGroupOwners(ctx context.Context) ([]GroupOwner, error)
	DeleteGroupOwner(ctx context.Context, actor, id uuid.UUID) error
}

// DirectoryStore authenticates SCIM bearer tokens to their owning tenant and returns a tenant-scoped
// Directory for each verified tenant (ADR-0170).
type DirectoryStore interface {
	Authenticate(ctx context.Context, token []byte) (uuid.UUID, bool, error)
	For(tenant uuid.UUID) Directory
}

var directoryStore DirectoryStore

// SetDirectoryStore installs the directory store. A nil store clears it.
func SetDirectoryStore(d DirectoryStore) {
	mu.Lock()
	defer mu.Unlock()
	directoryStore = d
}

// CurrentDirectoryStore returns the installed directory store, or nil.
func CurrentDirectoryStore() DirectoryStore {
	mu.RLock()
	defer mu.RUnlock()
	return directoryStore
}

// GuardedRoute is one API route mounted only when its enterprise feature is allowed. The guard asks
// principal.manage before Serve runs. tenant and principal are the authenticated caller.
type GuardedRoute struct {
	Pattern string
	Op      string
	Serve   func(http.ResponseWriter, *http.Request, uuid.UUID, uuid.UUID)
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

// MountContext is what an enterprise mount may attach to the control plane.
type MountContext struct {
	Mux         *http.ServeMux
	Log         *slog.Logger
	DB          *sql.DB
	Tenant      uuid.UUID
	MultiTenant bool
	SetTenant   func(context.Context, uuid.UUID)
}

// MountFunc attaches routes. SAML mounts run when sso.saml is allowed.
// Tracker mounts run when connectors.trackers is allowed.
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

// Mount runs the registered mounts. SAML mounts run when sso.saml is allowed and a directory store
// is installed. Tracker mounts run when connectors.trackers is allowed.
func Mount(ctx MountContext) {
	if Allow(FeatureSAML) && ctx.Mux != nil && CurrentDirectoryStore() != nil {
		mu.RLock()
		fns := append([]MountFunc(nil), mounts...)
		mu.RUnlock()
		for _, fn := range fns {
			fn(ctx)
		}
	}
	if Allow(FeatureTrackers) && ctx.Mux != nil {
		mu.RLock()
		fns := append([]MountFunc(nil), trackerMounts...)
		mu.RUnlock()
		for _, fn := range fns {
			fn(ctx)
		}
	}
}

// TrackerAdmin replaces one tracker binding for a tenant. The enterprise route calls it.
type TrackerAdmin interface {
	Put(ctx context.Context, tenant, actor uuid.UUID, connector, account, label, token, webhook string) (uuid.UUID, error)
}

// WaiverTicket is a ticket a tracker created before the waiver row is inserted.
// Abandon comments on the ticket when the waiver is not recorded.
type WaiverTicket struct {
	Connector  string
	ExternalID string
	URL        string
	Key        string
	Abandon    func(context.Context)
}

// OpenWaiverFunc creates the waiver ticket. false means the caller must still require ticket_ref.
type OpenWaiverFunc func(ctx context.Context, db *sql.DB, tenant uuid.UUID, reason string, from, until time.Time) (WaiverTicket, bool, error)

// CloseDueFunc sets done on waiver tickets this server created once the 0-day notice is stored.
type CloseDueFunc func(ctx context.Context, db *sql.DB, tenant uuid.UUID) error

// ChatDestination is one unsealed webhook. URL must not be logged or written to a response.
type ChatDestination struct {
	Connector string
	URL       string
}

// ChatAdmin replaces and lists chat destinations for a tenant. The enterprise routes call it.
type ChatAdmin interface {
	Put(ctx context.Context, tenant, actor uuid.UUID, connector, webhookURL string) (uuid.UUID, error)
	Delete(ctx context.Context, tenant, actor uuid.UUID, connector string) error
	List(ctx context.Context, tenant uuid.UUID) ([]ChatDestination, error)
}

// DeliverChatFunc posts the digests that are due. A denied feature does not call it.
type DeliverChatFunc func(ctx context.Context, db *sql.DB, tenant uuid.UUID) error

// CompleteFunc is one model call for a tenant. text and model are the answer.
type CompleteFunc func(ctx context.Context, tenant uuid.UUID, system, user string, maxTokens int) (text, model string, err error)

var (
	trackerGuarded []GuardedRoute
	trackerMounts  []MountFunc
	trackerAdmin   TrackerAdmin
	connectorKey   []byte
	openWaiver     OpenWaiverFunc
	closeDue       CloseDueFunc
	complete       CompleteFunc
	chatGuarded    []GuardedRoute
	chatAdmin      ChatAdmin
	deliverChat    DeliverChatFunc
)

// RegisterTrackerGuarded appends admin routes mounted only when connectors.trackers is allowed.
func RegisterTrackerGuarded(routes []GuardedRoute) {
	mu.Lock()
	defer mu.Unlock()
	trackerGuarded = append(trackerGuarded, routes...)
}

// TrackerGuarded returns a copy of the tracker admin routes.
func TrackerGuarded() []GuardedRoute {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]GuardedRoute, len(trackerGuarded))
	copy(out, trackerGuarded)
	return out
}

// RegisterTrackerMount appends a mount that runs when connectors.trackers is allowed.
func RegisterTrackerMount(fn MountFunc) {
	mu.Lock()
	defer mu.Unlock()
	if fn != nil {
		trackerMounts = append(trackerMounts, fn)
	}
}

// SetTrackerAdmin installs the binding writer. A nil admin clears it.
func SetTrackerAdmin(admin TrackerAdmin) {
	mu.Lock()
	defer mu.Unlock()
	trackerAdmin = admin
}

// CurrentTrackerAdmin returns the installed admin, or nil.
func CurrentTrackerAdmin() TrackerAdmin {
	mu.RLock()
	defer mu.RUnlock()
	return trackerAdmin
}

// SetConnectorKey installs the process connector key. A nil key clears it. The bytes are not logged.
func SetConnectorKey(key []byte) {
	mu.Lock()
	defer mu.Unlock()
	if len(key) == 0 {
		connectorKey = nil
		return
	}
	connectorKey = append([]byte(nil), key...)
}

// ConnectorKey returns a copy of the process connector key, or nil.
func ConnectorKey() []byte {
	mu.RLock()
	defer mu.RUnlock()
	if len(connectorKey) == 0 {
		return nil
	}
	return append([]byte(nil), connectorKey...)
}

// SetOpenWaiver installs the waiver-ticket opener. A nil opener clears it.
func SetOpenWaiver(fn OpenWaiverFunc) {
	mu.Lock()
	defer mu.Unlock()
	openWaiver = fn
}

// OpenWaiver creates a ticket when the feature is allowed and an opener is installed.
// Otherwise it reports that ticket_ref is still required.
func OpenWaiver(ctx context.Context, db *sql.DB, tenant uuid.UUID, reason string, from, until time.Time) (WaiverTicket, bool, error) {
	if !Allow(FeatureTrackers) {
		return WaiverTicket{}, false, nil
	}
	mu.RLock()
	fn := openWaiver
	mu.RUnlock()
	if fn == nil {
		return WaiverTicket{}, false, nil
	}
	return fn(ctx, db, tenant, reason, from, until)
}

// SetCloseDue installs the closer used when a 0-day notice is stored.
func SetCloseDue(fn CloseDueFunc) {
	mu.Lock()
	defer mu.Unlock()
	closeDue = fn
}

// CloseDue asks the closer to finish waiver tickets. A denied feature or no closer does nothing.
func CloseDue(ctx context.Context, db *sql.DB, tenant uuid.UUID) error {
	if !Allow(FeatureTrackers) {
		return nil
	}
	mu.RLock()
	fn := closeDue
	mu.RUnlock()
	if fn == nil {
		return nil
	}
	return fn(ctx, db, tenant)
}

// SetComplete installs the model call used when a ticket is ingested. A nil call stores no proposal.
func SetComplete(fn CompleteFunc) {
	mu.Lock()
	defer mu.Unlock()
	complete = fn
}

// Complete returns the installed model call, or nil.
func Complete() CompleteFunc {
	mu.RLock()
	defer mu.RUnlock()
	return complete
}

// RegisterChatGuarded appends admin routes mounted only when connectors.chat is allowed.
func RegisterChatGuarded(routes []GuardedRoute) {
	mu.Lock()
	defer mu.Unlock()
	chatGuarded = append(chatGuarded, routes...)
}

// ChatGuarded returns a copy of the chat admin routes.
func ChatGuarded() []GuardedRoute {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]GuardedRoute, len(chatGuarded))
	copy(out, chatGuarded)
	return out
}

// SetChatAdmin installs the destination writer. A nil admin clears it.
func SetChatAdmin(admin ChatAdmin) {
	mu.Lock()
	defer mu.Unlock()
	chatAdmin = admin
}

// CurrentChatAdmin returns the installed admin, or nil.
func CurrentChatAdmin() ChatAdmin {
	mu.RLock()
	defer mu.RUnlock()
	return chatAdmin
}

// SetDeliverChat installs the digest sender. A nil sender clears it.
func SetDeliverChat(fn DeliverChatFunc) {
	mu.Lock()
	defer mu.Unlock()
	deliverChat = fn
}

// DeliverChat posts due digests when the feature is allowed and a sender is installed.
// A denied feature or no sender does nothing.
func DeliverChat(ctx context.Context, db *sql.DB, tenant uuid.UUID) error {
	if !Allow(FeatureChat) {
		return nil
	}
	mu.RLock()
	fn := deliverChat
	mu.RUnlock()
	if fn == nil {
		return nil
	}
	return fn(ctx, db, tenant)
}

// ResetForTest clears the gate, kinds, commands, directory, routes, mounts, and connector hooks. A test that
// changes them calls it from t.Cleanup.
func ResetForTest() {
	mu.Lock()
	defer mu.Unlock()
	gate = denyAll{}
	kinds = map[string]KindFactory{}
	commands = map[string]CommandFunc{}
	directoryStore = nil
	guarded = nil
	mounts = nil
	trackerGuarded = nil
	trackerMounts = nil
	trackerAdmin = nil
	connectorKey = nil
	openWaiver = nil
	closeDue = nil
	complete = nil
	chatGuarded = nil
	chatAdmin = nil
	deliverChat = nil
}
