package registry

import (
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestGrandfatherRefusesBadArgumentsBeforeTouchingTheDatabase(t *testing.T) {
	// A nil database proves the checks run first: a call that reached it would panic.
	var db *sql.DB
	now := time.Now()
	tenant := uuid.MustParse("00000000-0000-4000-8000-00000000000a")
	decision := uuid.MustParse("00000000-0000-4000-8000-0000000000d1")
	one := Fingerprint{1}

	if _, err := Grandfather(t.Context(), db, uuid.Nil, decision, "acme/x", []Fingerprint{one}, now, now); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("nil tenant: err = %v, want ErrInvalidQuery", err)
	}
	if _, err := Grandfather(t.Context(), db, tenant, uuid.Nil, "acme/x", []Fingerprint{one}, now, now); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("nil decision: err = %v, want ErrInvalidQuery", err)
	}
	if _, err := Grandfather(t.Context(), db, tenant, decision, "acme/x", []Fingerprint{one}, time.Time{}, now); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("zero valid time: err = %v, want ErrInvalidQuery", err)
	}
	if _, err := Grandfather(t.Context(), db, tenant, decision, "acme/x", []Fingerprint{one}, now, time.Time{}); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("zero transaction time: err = %v, want ErrInvalidQuery", err)
	}
	if _, err := Grandfather(t.Context(), db, tenant, decision, "not a repo", []Fingerprint{one}, now, now); !errors.Is(err, ErrInvalidSubject) {
		t.Errorf("bad repo: err = %v, want ErrInvalidSubject", err)
	}
	if _, err := Grandfather(t.Context(), db, tenant, decision, "acme/x", []Fingerprint{one, one}, now, now); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("repeated fingerprint: err = %v, want ErrInvalidQuery", err)
	}
	got, err := Grandfather(t.Context(), db, tenant, decision, "acme/x", nil, now, now)
	if err != nil || got != nil {
		t.Errorf("no violations: got %v, err %v, want nil, nil", got, err)
	}
}

func TestResultWords(t *testing.T) {
	if Fail.String() != "fail" || WaivedBaseline.String() != "waived(baseline)" {
		t.Errorf("words = %q and %q", Fail.String(), WaivedBaseline.String())
	}
}
