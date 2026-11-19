package controlplane

import (
	"context"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/chat"
	"github.com/ipsofacto-io/ipso-server/eehooks"
)

// chatAdmin is the destination writer the API routes call. List copies the unsealed URL into the
// hook type. The HTTP handler must not write that URL back.
type chatAdmin struct {
	store chat.Store
}

func (a chatAdmin) Put(ctx context.Context, actor uuid.UUID, connector, webhookURL string) (uuid.UUID, error) {
	return a.store.Put(ctx, actor, connector, webhookURL)
}

func (a chatAdmin) Delete(ctx context.Context, actor uuid.UUID, connector string) error {
	return a.store.Delete(ctx, actor, connector)
}

func (a chatAdmin) List(ctx context.Context) ([]eehooks.ChatDestination, error) {
	rows, err := a.store.List(ctx)
	out := make([]eehooks.ChatDestination, 0, len(rows))
	for _, row := range rows {
		out = append(out, eehooks.ChatDestination{Connector: row.Connector, URL: row.URL})
	}
	return out, err
}
