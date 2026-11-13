package proposals

import (
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/registry"
)

// A tenant, a page or a repo that cannot be served is refused before the store is touched: the database is nil,
// so any read would panic.
func TestAcceptedChecksRefusesWhatItCannotServeBeforeItReads(t *testing.T) {
	tenant := uuid.New()
	page := registry.Page{Limit: 10}
	tests := []struct {
		name   string
		tenant uuid.UUID
		repo   string
		page   registry.Page
		want   error
	}{
		{"no tenant", uuid.Nil, "acme/api", page, registry.ErrInvalidQuery},
		{"a page of zero", tenant, "acme/api", registry.Page{}, registry.ErrInvalidQuery},
		{"a page over the bound", tenant, "acme/api", registry.Page{Limit: registry.MaxPage + 1}, registry.ErrInvalidQuery},
		{"no repo", tenant, "", page, registry.ErrInvalidSubject},
		{"an owner only", tenant, "acme", page, registry.ErrInvalidSubject},
		{"a pattern", tenant, "acme/*", page, registry.ErrInvalidSubject},
		{"a dot segment", tenant, "acme/../api", page, registry.ErrInvalidSubject},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := AcceptedChecks(t.Context(), nil, test.tenant, test.repo, time.Now(), test.page)
			if !errors.Is(err, test.want) || got != nil {
				t.Fatalf("AcceptedChecks() = %v, %v, want %v", got, err, test.want)
			}
		})
	}
}
