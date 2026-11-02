package identity

import (
	"errors"
	"testing"

	"github.com/google/uuid"
)

// A bad argument fails before the database is touched, which is why these pass a nil pool.
func TestInvalidArgumentsTouchNoDatabase(t *testing.T) {
	ctx := t.Context()
	id := uuid.New()
	if _, err := Get(ctx, nil, uuid.Nil, id); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("Get with no tenant: %v", err)
	}
	if _, err := Get(ctx, nil, id, uuid.Nil); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("Get with no principal: %v", err)
	}
	if _, err := RecordAction(ctx, nil, uuid.Nil, id, "a", "b"); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("RecordAction with no tenant: %v", err)
	}
	if _, err := RecordAction(ctx, nil, id, uuid.Nil, "a", "b"); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("RecordAction with no principal: %v", err)
	}
	for _, limit := range []int{0, -1, maxActions + 1} {
		if _, err := Actions(ctx, nil, id, limit); !errors.Is(err, ErrInvalidQuery) {
			t.Errorf("Actions with limit %d: %v", limit, err)
		}
	}
	if _, err := Actions(ctx, nil, uuid.Nil, 1); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("Actions with no tenant: %v", err)
	}
}
