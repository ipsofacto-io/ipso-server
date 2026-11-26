package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/eehooks"
	"github.com/ipsofacto-io/ipso-server/internal/authn"
	"github.com/ipsofacto-io/ipso-server/internal/telemetry/telemetrytest"
	"github.com/ipsofacto-io/ipso-server/internal/verification"
)

type mapVerifier map[string]authn.Claims

func (m mapVerifier) Verify(_ context.Context, raw string) (authn.Claims, error) {
	claims, ok := m[raw]
	if !ok {
		return authn.Claims{}, errors.New("unknown token")
	}
	return claims, nil
}

func TestMultiTenantAPITelemetryAndPerTenantRateLimit(t *testing.T) {
	db, err := sql.Open("pgx", unreachable)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	personA := uuid.MustParse("00000000-0000-4000-8000-0000000000a1")
	personB := uuid.MustParse("00000000-0000-4000-8000-0000000000b1")

	tel, rec := telemetrytest.New(t)
	h, err := New(Config{
		DB: db,
		Verifier: mapVerifier{
			"tok-a": {Issuer: "https://idp.example.test", Subject: "sub-a"},
			"tok-b": {Issuer: "https://idp.example.test", Subject: "sub-b"},
		},
		Callers: func(_ context.Context, c authn.Claims) (Caller, bool) {
			if c.Subject == "sub-a" {
				return Caller{Tenant: tenantA, Principal: personA}, true
			}
			return Caller{Tenant: tenantB, Principal: personB}, true
		},
		Policy: testPolicy(t),
		Limits: Limits{Rate: 0.001, Burst: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	root := http.NewServeMux()
	root.Handle("/v1/", h)
	observed := tel.Handler(uuid.Nil, root)

	// Tenant A consumes its burst of 1 (reaches DB -> 500 because unreachable DB, NOT 429).
	resA1 := call(t, observed, http.MethodGet, "/v1/scopes", "Bearer tok-a")
	if resA1.Code == http.StatusTooManyRequests || resA1.Code == http.StatusUnauthorized {
		t.Fatalf("tenant A first call = %d, want past guard rate limit", resA1.Code)
	}
	// Tenant A second call is rate limited with 429.
	if resA2 := call(t, observed, http.MethodGet, "/v1/scopes", "Bearer tok-a"); resA2.Code != http.StatusTooManyRequests {
		t.Fatalf("tenant A second call = %d, want 429", resA2.Code)
	}
	// Tenant B has its own bucket and is NOT rate limited.
	resB := call(t, observed, http.MethodGet, "/v1/scopes", "Bearer tok-b")
	if resB.Code == http.StatusTooManyRequests || resB.Code == http.StatusUnauthorized {
		t.Fatalf("tenant B call = %d, want past guard rate limit", resB.Code)
	}

	// Telemetry spans received the verified tenant id for both tenants.
	var tenants []string
	for _, s := range rec.Spans() {
		tenants = append(tenants, telemetrytest.Attrs(s.Attributes)["ipso.tenant.id"])
	}
	if len(tenants) != 3 || tenants[0] != tenantA.String() || tenants[1] != tenantA.String() || tenants[2] != tenantB.String() {
		t.Fatalf("span tenants = %v, want [%s %s %s]", tenants, tenantA, tenantA, tenantB)
	}
}

func TestGuardedRouteReceivesCallerTenantAndActor(t *testing.T) {
	eehooks.ResetForTest()
	t.Cleanup(eehooks.ResetForTest)
	eehooks.SetGate(allowChat{})
	eehooks.SetChatAdmin(stubChatAdmin{})

	var gotTenant, gotActor uuid.UUID
	eehooks.RegisterChatGuarded([]eehooks.GuardedRoute{{
		Pattern: "GET /v1/chat/ping",
		Op:      "chat_ping",
		Serve: func(w http.ResponseWriter, _ *http.Request, tenant, actor uuid.UUID) {
			gotTenant, gotActor = tenant, actor
			w.WriteHeader(http.StatusNoContent)
		},
	}})

	var matched *route
	for _, rt := range routes(nil, time.Now, nil, "") {
		if rt.pattern == "GET /v1/chat/ping" {
			rCopy := rt
			matched = &rCopy
			break
		}
	}
	if matched == nil {
		t.Fatal("guarded route not mounted")
	}
	req := httptest.NewRequest(http.MethodGet, "/v1/chat/ping", nil)
	ctx := context.WithValue(req.Context(), callerKey{}, Caller{Tenant: tenantB, Principal: someone})
	rec := httptest.NewRecorder()
	matched.handler.ServeHTTP(rec, req.WithContext(ctx))
	if rec.Code != http.StatusNoContent || gotTenant != tenantB || gotActor != someone {
		t.Fatalf("code=%d tenant=%v actor=%v, want 204 %v %v", rec.Code, gotTenant, gotActor, tenantB, someone)
	}
}

func TestLiveUploadTagsTelemetryTenantOnlyAfterSignatureVerification(t *testing.T) {
	db, err := sql.Open("pgx", unreachable)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(spki)
	pinHex := hex.EncodeToString(sum[:])

	tel, rec := telemetrytest.New(t)
	h, err := New(Config{
		DB:       db,
		Verifier: fakeVerifier{},
		Callers:  func(context.Context, authn.Claims) (Caller, bool) { return Caller{}, false },
		LiveUploads: &LiveUploads{
			LookupPin: func(_ context.Context, gotHex string) (verification.AgentPin, SessionStatus) {
				if gotHex != pinHex {
					return verification.AgentPin{}, SessionUnknown
				}
				return verification.AgentPin{ID: uuid.New(), Tenant: tenantB, Repo: "acme/api", Env: "prod", PublicKeyDER: spki}, SessionFound
			},
		},
		Policy: testPolicy(t),
		Limits: Limits{Rate: 100, Burst: 100},
	})
	if err != nil {
		t.Fatal(err)
	}
	root := http.NewServeMux()
	root.Handle("/v1/", h)
	observed := tel.Handler(uuid.Nil, root)

	body := []byte(`{"bad":"payload"}`)
	ts := time.Now().UTC().Format(time.RFC3339)

	// Invalid signature must NOT tag tenantB on telemetry span.
	badReq := httptest.NewRequest(http.MethodPost, "/v1/verdicts/live", bytes.NewReader(body))
	badReq.Header.Set("Content-Type", "application/json")
	badReq.Header.Set("X-Ipso-Agent-Pin", pinHex)
	badReq.Header.Set("X-Ipso-Timestamp", ts)
	badReq.Header.Set("X-Ipso-Signature", base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize)))
	badRec := httptest.NewRecorder()
	observed.ServeHTTP(badRec, badReq)
	if badRec.Code != http.StatusUnauthorized {
		t.Fatalf("bad sig status = %d, want 401", badRec.Code)
	}

	// Valid signature tags tenantB (even if body fails schema validation as 400).
	sig := ed25519.Sign(priv, verification.LiveMessage(ts, body))
	goodReq := httptest.NewRequest(http.MethodPost, "/v1/verdicts/live", bytes.NewReader(body))
	goodReq.Header.Set("Content-Type", "application/json")
	goodReq.Header.Set("X-Ipso-Agent-Pin", pinHex)
	goodReq.Header.Set("X-Ipso-Timestamp", ts)
	goodReq.Header.Set("X-Ipso-Signature", base64.StdEncoding.EncodeToString(sig))
	goodRec := httptest.NewRecorder()
	observed.ServeHTTP(goodRec, goodReq)
	if goodRec.Code == http.StatusUnauthorized {
		t.Fatalf("valid sig status = 401: %s", goodRec.Body)
	}

	spans := rec.Spans()
	if len(spans) != 2 {
		t.Fatalf("spans = %d, want 2", len(spans))
	}
	if _, has := telemetrytest.Attrs(spans[0].Attributes)["ipso.tenant.id"]; has {
		t.Errorf("failed signature leaked tenant on telemetry span: %v", telemetrytest.Attrs(spans[0].Attributes))
	}
	if got := telemetrytest.Attrs(spans[1].Attributes)["ipso.tenant.id"]; got != tenantB.String() {
		t.Errorf("verified live upload span tenant = %q, want %s", got, tenantB)
	}
}
