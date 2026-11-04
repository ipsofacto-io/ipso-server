package rls

import (
	"context"
	"errors"
	"testing"
)

func TestCheckRequiresADatabase(t *testing.T) {
	err := Check(context.Background(), nil)
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("Check(nil) = %v, want the start refusal", err)
	}
}
