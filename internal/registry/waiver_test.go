package registry

import (
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestApplyRefusesBadArgumentsBeforeTouchingTheDatabase(t *testing.T) {
	// A nil database proves the checks run first: a call that reached it would panic.
	var db *sql.DB
	now := time.Now()
	tenant := uuid.MustParse("00000000-0000-4000-8000-00000000000a")
	decision := uuid.MustParse("00000000-0000-4000-8000-0000000000d1")
	subject := Subject{Repo: "acme/payments"}

	if _, err := Apply(t.Context(), db, uuid.Nil, decision, subject, OutcomeFail, now, now); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("nil tenant: err = %v, want ErrInvalidQuery", err)
	}
	if _, err := Apply(t.Context(), db, tenant, uuid.Nil, subject, OutcomeFail, now, now); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("nil decision: err = %v, want ErrInvalidQuery", err)
	}
	if _, err := Apply(t.Context(), db, tenant, decision, subject, OutcomeFail, time.Time{}, now); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("zero valid time: err = %v, want ErrInvalidQuery", err)
	}
	if _, err := Apply(t.Context(), db, tenant, decision, subject, OutcomeFail, now, time.Time{}); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("zero transaction time: err = %v, want ErrInvalidQuery", err)
	}
	if _, err := Apply(t.Context(), db, tenant, decision, subject, Outcome(9), now, now); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("unknown outcome: err = %v, want ErrInvalidQuery", err)
	}
	if _, err := Apply(t.Context(), db, tenant, decision, Subject{Repo: "nope"}, OutcomeFail, now, now); !errors.Is(err, ErrInvalidSubject) {
		t.Errorf("bad subject: err = %v, want ErrInvalidSubject", err)
	}
	for _, outcome := range []Outcome{OutcomePass, OutcomeWaived, OutcomeError} {
		got, err := Apply(t.Context(), db, tenant, decision, subject, outcome, now, now)
		if err != nil || got != outcome {
			t.Errorf("%s: got %v, %v, want the same outcome and no error", outcome, got, err)
		}
	}
}

func TestNotifyRefusesANilTenantBeforeTouchingTheDatabase(t *testing.T) {
	var db *sql.DB
	if _, err := Notify(t.Context(), db, uuid.Nil); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("err = %v, want ErrInvalidQuery", err)
	}
}

func TestOutcomeString(t *testing.T) {
	if got := OutcomeFail.String(); got != "fail" {
		t.Errorf("OutcomeFail = %q, want fail", got)
	}
	if got := OutcomePass.String(); got != "pass" {
		t.Errorf("OutcomePass = %q, want pass", got)
	}
	if got := OutcomeWaived.String(); got != "waived" {
		t.Errorf("OutcomeWaived = %q, want waived", got)
	}
	if got := OutcomeError.String(); got != "error" {
		t.Errorf("OutcomeError = %q, want error", got)
	}
	if got := Outcome(9).String(); got != "outcome(9)" {
		t.Errorf("unknown = %q, want outcome(9)", got)
	}
}
