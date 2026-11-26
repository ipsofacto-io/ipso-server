package controlplane

import (
	"context"
	"database/sql"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/chat"
	"github.com/ipsofacto-io/ipso-server/eehooks"
)

// chatAdmin is the destination writer the API routes call. List copies the unsealed URL into the
// hook type. The HTTP handler must not write that URL back. When fixedTenant is non-nil
// (single-tenant mode), every call refuses any other tenant as defense in depth.
type chatAdmin struct {
	db          *sql.DB
	fixedTenant uuid.UUID
	key         []byte
}

func (a chatAdmin) storeFor(tenant uuid.UUID) (chat.Store, bool) {
	if tenant == uuid.Nil || (a.fixedTenant != uuid.Nil && tenant != a.fixedTenant) {
		return chat.Store{}, false
	}
	return chat.NewStore(a.db, tenant, a.key), true
}

func (a chatAdmin) Put(ctx context.Context, tenant, actor uuid.UUID, connector, webhookURL string) (uuid.UUID, error) {
	store, ok := a.storeFor(tenant)
	if !ok {
		return uuid.Nil, chat.ErrInvalid
	}
	return store.Put(ctx, actor, connector, webhookURL)
}

func (a chatAdmin) Delete(ctx context.Context, tenant, actor uuid.UUID, connector string) error {
	store, ok := a.storeFor(tenant)
	if !ok {
		return chat.ErrInvalid
	}
	return store.Delete(ctx, actor, connector)
}

func (a chatAdmin) List(ctx context.Context, tenant uuid.UUID) ([]eehooks.ChatDestination, error) {
	store, ok := a.storeFor(tenant)
	if !ok {
		return nil, chat.ErrInvalid
	}
	rows, err := store.List(ctx)
	out := make([]eehooks.ChatDestination, 0, len(rows))
	for _, row := range rows {
		out = append(out, eehooks.ChatDestination{Connector: row.Connector, URL: row.URL})
	}
	return out, err
}
