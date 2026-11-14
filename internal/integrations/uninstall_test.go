package integrations

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

// unbinder answers the removal of a binding from a table, the way the database does, and records what it was
// asked to remove.
type unbinder struct {
	mu       sync.Mutex
	owners   map[int64]uuid.UUID
	asked    []int64
	err      error
	deadline time.Duration
}

func (u *unbinder) unbind(ctx context.Context, installation int64) (uuid.UUID, bool, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.asked = append(u.asked, installation)
	if deadline, ok := ctx.Deadline(); ok {
		u.deadline = time.Until(deadline)
	}
	if u.err != nil {
		return uuid.Nil, false, u.err
	}
	tenant, ok := u.owners[installation]
	delete(u.owners, installation)
	return tenant, ok, nil
}

// uninstallService is a service whose installation 42 belongs to testTenant and that GitHub says is gone.
func uninstallService(t *testing.T, logs io.Writer) (*fakeGitHub, *Service, *unbinder) {
	t.Helper()
	fake, app := newFakeGitHub(t)
	fake.statusFor["/app/installations/42"] = http.StatusNotFound
	s := newTestService(t, app, logs, nil)
	// An uninstall takes its tenant from the removal itself and never asks the lookup of a delivery.
	s.cfg.Tenants = neverCalled(t)
	u := &unbinder{owners: map[int64]uuid.UUID{42: testTenant}}
	s.cfg.Unbind = u.unbind
	return fake, s, u
}

func uninstallEvent(action string, installation any) map[string]any {
	return map[string]any{
		"action":       action,
		"installation": map[string]any{"id": installation, "app_id": 12345, "account": map[string]any{"login": "Acme-Corp"}},
	}
}

func TestUninstallRemovesTheBindingOnceGitHubConfirms(t *testing.T) {
	var logs strings.Builder
	fake, s, u := uninstallService(t, &logs)
	if code := deliver(t, s, "installation", "d-1", uninstallEvent("deleted", 42)); code != http.StatusAccepted {
		t.Fatalf("status %d, want 202", code)
	}
	if !slices.Equal(u.asked, []int64{42}) || len(u.owners) != 0 {
		t.Fatalf("asked %v, bindings left %v; want 42 removed", u.asked, u.owners)
	}
	if !slices.Equal(fake.requests, []string{"GET /app/installations/42"}) {
		t.Fatalf("requests %v, want one check of the installation as the App", fake.requests)
	}
	if u.deadline <= 0 || u.deadline > unbindTimeout {
		t.Errorf("the removal ran with %v left, want a bound of at most %v", u.deadline, unbindTimeout)
	}
	if len(s.queue)+len(s.merged) != 0 {
		t.Errorf("an uninstall queued a job")
	}
	if !strings.Contains(logs.String(), testTenant.String()) {
		t.Errorf("the log does not name the tenant that lost the binding: %s", logs.String())
	}

	// A redelivery finds nothing left to remove and is still done.
	if code := deliver(t, s, "installation", "d-1", uninstallEvent("deleted", 42)); code != http.StatusAccepted {
		t.Fatalf("redelivery: status %d, want 202", code)
	}
	if len(u.asked) != 2 {
		t.Fatalf("asked %v, want the redelivery to ask again", u.asked)
	}
}

func TestUninstallOfAnUnboundInstallationChangesNothing(t *testing.T) {
	fake, s, u := uninstallService(t, nil)
	fake.statusFor["/app/installations/77"] = http.StatusNotFound
	if code := deliver(t, s, "installation", "d-1", uninstallEvent("deleted", 77)); code != http.StatusAccepted {
		t.Fatalf("status %d, want 202", code)
	}
	if !slices.Equal(u.asked, []int64{77}) || u.owners[42] != testTenant {
		t.Fatalf("asked %v, bindings %v; want 77 asked and 42 kept", u.asked, u.owners)
	}
}

func TestUninstallThatGitHubDoesNotConfirmRemovesNothing(t *testing.T) {
	for name, tc := range map[string]struct {
		status int
		log    string
	}{
		"still installed": {0, "still has it"},
		"github fails":    {http.StatusBadGateway, "check failed"},
	} {
		t.Run(name, func(t *testing.T) {
			var logs strings.Builder
			fake, s, u := uninstallService(t, &logs)
			delete(fake.statusFor, "/app/installations/42")
			if tc.status != 0 {
				fake.statusFor["/app/installations/42"] = tc.status
			}
			if code := deliver(t, s, "installation", "d-1", uninstallEvent("deleted", 42)); code != http.StatusServiceUnavailable {
				t.Fatalf("status %d, want 503", code)
			}
			if len(u.asked) != 0 || u.owners[42] != testTenant {
				t.Fatalf("asked %v, bindings %v; want nothing removed", u.asked, u.owners)
			}
			if !strings.Contains(logs.String(), tc.log) {
				t.Errorf("the log does not say why: %s", logs.String())
			}
		})
	}
}

func TestUninstallRemovalFailureAsksForRedeliveryAndLeaksNothing(t *testing.T) {
	var logs strings.Builder
	_, s, u := uninstallService(t, &logs)
	u.err = errors.New("marker-database-error")
	if code := deliver(t, s, "installation", "d-1", uninstallEvent("deleted", 42)); code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", code)
	}
	if strings.Contains(logs.String(), "marker-database-error") {
		t.Fatalf("the log quotes the database error: %s", logs.String())
	}
	u.err = nil
	if code := deliver(t, s, "installation", "d-1", uninstallEvent("deleted", 42)); code != http.StatusAccepted {
		t.Fatalf("redelivery: status %d, want 202", code)
	}
	if len(u.owners) != 0 {
		t.Fatalf("bindings %v, want the redelivery to remove 42", u.owners)
	}
}

func TestOtherInstallationEventsDoNoWork(t *testing.T) {
	for name, delivery := range map[string]struct {
		event   string
		payload any
	}{
		"created":                  {"installation", uninstallEvent("created", 42)},
		"suspend":                  {"installation", uninstallEvent("suspend", 42)},
		"unsuspend":                {"installation", uninstallEvent("unsuspend", 42)},
		"new permissions accepted": {"installation", uninstallEvent("new_permissions_accepted", 42)},
		"repositories removed":     {"installation_repositories", uninstallEvent("removed", 42)},
	} {
		t.Run(name, func(t *testing.T) {
			fake, s, u := uninstallService(t, nil)
			if code := deliver(t, s, delivery.event, "d-1", delivery.payload); code != http.StatusAccepted {
				t.Fatalf("status %d, want 202", code)
			}
			drain(s)
			if len(fake.requests) != 0 || len(u.asked) != 0 {
				t.Fatalf("requests %v, removals asked %v; want none", fake.requests, u.asked)
			}
		})
	}
}

func TestMalformedUninstallIsRefused(t *testing.T) {
	noInstallation := uninstallEvent("deleted", 42)
	delete(noInstallation, "installation")
	for name, payload := range map[string]any{
		"not an object":   "deleted",
		"id not a number": uninstallEvent("deleted", "42"),
		"zero id":         uninstallEvent("deleted", 0),
		"negative id":     uninstallEvent("deleted", -42),
		"no installation": noInstallation,
	} {
		t.Run(name, func(t *testing.T) {
			fake, s, u := uninstallService(t, nil)
			if code := deliver(t, s, "installation", "d-1", payload); code != http.StatusBadRequest {
				t.Fatalf("status %d, want 400", code)
			}
			if len(fake.requests) != 0 || len(u.asked) != 0 {
				t.Fatalf("requests %v, removals asked %v; want none", fake.requests, u.asked)
			}
		})
	}
}

func TestUnsignedUninstallRemovesNothing(t *testing.T) {
	fake, s, u := uninstallService(t, nil)
	request := httptest.NewRequest(http.MethodPost, webhookPath, strings.NewReader(`{"action":"deleted","installation":{"id":42}}`))
	request.Header.Set("X-Hub-Signature-256", "sha256="+strings.Repeat("0", 64))
	request.Header.Set("X-GitHub-Event", "installation")
	request.Header.Set("X-GitHub-Delivery", "d-1")
	recorder := httptest.NewRecorder()
	s.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", recorder.Code)
	}
	if len(fake.requests) != 0 || len(u.asked) != 0 {
		t.Fatalf("requests %v, removals asked %v; want none", fake.requests, u.asked)
	}
}

func TestServiceThatCannotUnbindRefusesAnUninstall(t *testing.T) {
	fake, s, _ := uninstallService(t, nil)
	s.cfg.Unbind = nil
	if code := deliver(t, s, "installation", "d-1", uninstallEvent("deleted", 42)); code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", code)
	}
	if len(fake.requests) != 0 {
		t.Fatalf("requests %v, want none", fake.requests)
	}
}

func TestServeRefusesAServiceThatCannotUnbind(t *testing.T) {
	fake, app := newFakeGitHub(t)
	listener, err := (&testListener{}).listen(t)
	if err != nil {
		t.Fatal(err)
	}
	err = Serve(context.Background(), listener, Config{App: app, WebhookSecret: []byte(testSecret), Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Tenants: ownedBy(nil)})
	if err == nil || !strings.Contains(err.Error(), "binding") {
		t.Fatalf("Serve = %v, want a refusal that names the binding", err)
	}
	if len(fake.requests) != 0 {
		t.Fatalf("a refused service called GitHub: %v", fake.requests)
	}
}
