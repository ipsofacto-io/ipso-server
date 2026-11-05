package tenancy

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestRequireNeedsADatabaseAndATenant(t *testing.T) {
	if err := Require(t.Context(), nil, uuid.New()); !errors.Is(err, ErrUnknownTenant) {
		t.Errorf("no database: %v", err)
	}
}
