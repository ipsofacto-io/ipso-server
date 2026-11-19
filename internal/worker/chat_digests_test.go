package worker

import (
	"context"
	"database/sql"
	"errors"
	"log/slog"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/ipsofacto-io/ipso-server/eehooks"
)

type allowChat struct{}

func (allowChat) Allow(feature string) bool { return feature == eehooks.FeatureChat }

func chatJob(tenant uuid.UUID) *river.Job[ChatDigestsArgs] {
	return &river.Job[ChatDigestsArgs]{JobRow: &rivertype.JobRow{ID: 9}, Args: ChatDigestsArgs{Tenant: tenant}}
}

func TestAChatJobForAnotherTenantIsCancelledBeforeDelivery(t *testing.T) {
	t.Cleanup(eehooks.ResetForTest)
	eehooks.SetGate(allowChat{})
	eehooks.SetDeliverChat(func(context.Context, *sql.DB, uuid.UUID) error {
		t.Error("delivery ran for a job that names another tenant")
		return nil
	})
	w := &chatDigests{tenant: tenantA, log: slog.New(slog.DiscardHandler)}
	err := w.Work(t.Context(), chatJob(tenantB))
	var cancelled *river.JobCancelError
	if !errors.As(err, &cancelled) {
		t.Fatalf("err = %v, want a cancellation", err)
	}
	if strings.Contains(err.Error(), tenantB.String()) {
		t.Errorf("err = %q names a tenant", err)
	}
}

func TestADeniedChatFeatureMakesNoRequest(t *testing.T) {
	t.Cleanup(eehooks.ResetForTest)
	eehooks.SetDeliverChat(func(context.Context, *sql.DB, uuid.UUID) error {
		t.Error("delivery ran while the feature is denied")
		return nil
	})
	w := &chatDigests{tenant: tenantA, log: slog.New(slog.DiscardHandler)}
	if err := w.Work(t.Context(), chatJob(tenantA)); err != nil {
		t.Fatal(err)
	}
}

func TestAChatFailureDoesNotKeepTheWebhookURL(t *testing.T) {
	t.Cleanup(eehooks.ResetForTest)
	eehooks.SetGate(allowChat{})
	const secret = "https://hooks.slack.com/services/T000/B000/SECRET"
	eehooks.SetDeliverChat(func(context.Context, *sql.DB, uuid.UUID) error {
		return errors.New("post " + secret + " failed")
	})
	w := &chatDigests{tenant: tenantA, log: slog.New(slog.DiscardHandler)}
	err := w.Work(t.Context(), chatJob(tenantA))
	if err == nil || strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), "hooks.slack.com") {
		t.Fatalf("err = %v", err)
	}
}

func TestTheChatJobIsUniqueWhileItWaits(t *testing.T) {
	opts := ChatDigestsArgs{Tenant: tenantA}.InsertOpts()
	if !opts.UniqueOpts.ByArgs || opts.Queue != chatDigestsQueue || opts.MaxAttempts != chatDigestsAttempts {
		t.Fatalf("opts = %+v", opts)
	}
	for _, done := range []rivertype.JobState{rivertype.JobStateCompleted, rivertype.JobStateDiscarded, rivertype.JobStateCancelled} {
		if slices.Contains(opts.UniqueOpts.ByState, done) {
			t.Errorf("state %q holds the next tick back", done)
		}
	}
	typ := reflect.TypeFor[ChatDigestsArgs]()
	if typ.NumField() != 1 || typ.Field(0).Name != "Tenant" || (ChatDigestsArgs{}).Kind() != chatDigestsKind {
		t.Fatalf("arguments = %s", typ)
	}
}
