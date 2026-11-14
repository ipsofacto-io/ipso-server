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

func TestWaiverEachRefusesBadArgumentsBeforeTouchingTheDatabase(t *testing.T) {
	// A nil database proves the checks run first: a call that reached it would panic.
	var db *sql.DB
	now := time.Now()
	tenant := uuid.MustParse("00000000-0000-4000-8000-00000000000a")
	decision := uuid.MustParse("00000000-0000-4000-8000-0000000000d1")
	read := WaiverRead{Decision: decision, Repo: "acme/payments", Env: "prod", ValidAt: now}

	if _, err := WaiverEach(t.Context(), db, uuid.Nil, []WaiverRead{read}, now); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("nil tenant: err = %v, want ErrInvalidQuery", err)
	}
	if _, err := WaiverEach(t.Context(), db, tenant, []WaiverRead{read}, time.Time{}); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("zero transaction time: err = %v, want ErrInvalidQuery", err)
	}
	noDecision := read
	noDecision.Decision = uuid.Nil
	if _, err := WaiverEach(t.Context(), db, tenant, []WaiverRead{noDecision}, now); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("nil decision: err = %v, want ErrInvalidQuery", err)
	}
	noTime := read
	noTime.ValidAt = time.Time{}
	if _, err := WaiverEach(t.Context(), db, tenant, []WaiverRead{noTime}, now); !errors.Is(err, ErrInvalidQuery) {
		t.Errorf("zero valid time: err = %v, want ErrInvalidQuery", err)
	}
	for _, repo := range []string{"", "nope", "acme/*", "acme/pay ments", "ACMÉ/payments"} {
		bad := read
		bad.Repo = repo
		if _, err := WaiverEach(t.Context(), db, tenant, []WaiverRead{read, bad}, now); !errors.Is(err, ErrInvalidSubject) {
			t.Errorf("repo %q: err = %v, want ErrInvalidSubject", repo, err)
		}
	}
	got, err := WaiverEach(t.Context(), db, tenant, nil, now)
	if err != nil || len(got) != 0 {
		t.Errorf("no reads: got %v, %v, want none and no error", got, err)
	}
}

func TestAWholeSubjectReadsAnEnvThatIsNotANameAsNone(t *testing.T) {
	for env, want := range map[string]string{"prod": "prod", "PROD": "prod", "": "", "pro d": "", "prod\n": "", "prod-é": "", "-prod": ""} {
		got, err := newWholeSubject("Acme/Payments", env)
		if err != nil {
			t.Fatalf("env %q: %v", env, err)
		}
		if got.env != want || !got.whole || got.hasPath || got.repoString() != "acme/payments" {
			t.Errorf("env %q: got env %q whole %v path %v repo %q, want env %q whole, no path, acme/payments", env, got.env, got.whole, got.hasPath, got.repoString(), want)
		}
	}
}

func TestAWholeSubjectIsNeverWidenedByAMissingPathOrEnv(t *testing.T) {
	str := func(s string) sql.NullString { return sql.NullString{String: s, Valid: true} }
	whole, err := newWholeSubject("acme/payments", "prod")
	if err != nil {
		t.Fatal(err)
	}
	wholeNoEnv, err := newWholeSubject("acme/payments", "")
	if err != nil {
		t.Fatal(err)
	}
	widening, err := newSubject(Subject{Repo: "acme/payments"})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		c    candidate
		s    subject
		want bool
	}{
		{"a repo node", candidate{repo: str("acme/payments")}, whole, true},
		{"an org node", candidate{}, whole, true},
		{"a path node", candidate{repo: str("acme/payments"), path: str("infra/**")}, whole, false},
		{"a path node that names every path", candidate{repo: str("acme/payments"), path: str("**")}, whole, false},
		{"the same env node", candidate{repo: str("acme/payments"), env: str("prod")}, whole, true},
		{"another env node", candidate{repo: str("acme/payments"), env: str("staging")}, whole, false},
		{"an env node when the verdict has no env", candidate{repo: str("acme/payments"), env: str("prod")}, wholeNoEnv, false},
		{"another repo", candidate{repo: str("acme/billing")}, whole, false},
		{"a path node under a widening subject", candidate{repo: str("acme/payments"), path: str("infra/**")}, widening, true},
		{"an env node under a widening subject", candidate{repo: str("acme/payments"), env: str("prod")}, widening, true},
	} {
		got, err := tc.s.selects(tc.c)
		if err != nil || got != tc.want {
			t.Errorf("%s: got %v, %v, want %v", tc.name, got, err, tc.want)
		}
	}
	// A damaged path selector is never parsed for a whole subject, which no path node covers, and is still an error for a
	// subject that has a path.
	if got, err := whole.selects(candidate{path: str("a b")}); err != nil || got {
		t.Errorf("a damaged path selector under a whole subject: got %v, %v, want not covered and no error", got, err)
	}
	if _, err := widening.selects(candidate{path: str("a b")}); !errors.Is(err, ErrInvalidSelector) {
		t.Errorf("a damaged path selector under a widening subject: err = %v, want ErrInvalidSelector", err)
	}
}
