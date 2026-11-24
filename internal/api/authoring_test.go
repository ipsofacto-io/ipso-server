package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/ipsofacto-io/ipso-server/internal/identity"
	"github.com/ipsofacto-io/ipso-server/internal/verification"
	"github.com/ipsofacto-io/ipso/pkg/mcptools"
)

func sha256HexBytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestCLISessionBearerAuthAndVerifiability(t *testing.T) {
	db, err := sql.Open("pgx", unreachable)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	now := time.Date(2026, 11, 24, 15, 0, 0, 0, time.UTC)
	principalID := uuid.MustParse("01960000-0000-7000-8000-000000000077")
	cliCalled := false
	g, _, err := newGuard(Config{
		DB:       db,
		Verifier: fakeVerifier{},
		Callers:  callerOf(tenantA),
		Sessions: &Sessions{
			Origin: "https://ipso.example.com",
			Lookup: func(context.Context, []byte) (Caller, SessionStatus) {
				return Caller{}, SessionUnknown
			},
			LookupCLI: func(_ context.Context, raw string) (Caller, SessionStatus) {
				if raw == "ipsocli_valid_token" {
					cliCalled = true
					return Caller{Tenant: tenantA, Principal: principalID}, SessionFound
				}
				return Caller{}, SessionUnknown
			},
		},
		Policy: testPolicy(t),
		Now:    func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	g.principals = func(context.Context, uuid.UUID, uuid.UUID) (identity.Principal, error) {
		return holder(identity.RoleContributor, uuid.Nil), nil
	}

	mux, table := mount(routesWith(db, func() time.Time { return now }, nil, "", testPolicy(t), nil), nil, nil)
	h := g.serve(mux, table)

	w := callBody(t, h, http.MethodPost, "/v1/verifiability", "Bearer ipsocli_valid_token",
		`{"title":"Use TLS where appropriate","statement":"Services should use TLS where appropriate."}`)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", w.Code, w.Body.String())
	}
	if !cliCalled {
		t.Fatal("expected Sessions.LookupCLI to be called for ipsocli_ token")
	}
	var diag mcptools.VerifiabilityOutput
	if err := json.Unmarshal(w.Body.Bytes(), &diag); err != nil {
		t.Fatalf("unmarshal diagnosis: %v", err)
	}
	if diag.Classification != "ambiguous" {
		t.Fatalf("classification = %q, want ambiguous", diag.Classification)
	}

	wBad := callBody(t, h, http.MethodPost, "/v1/verifiability", "Bearer ipsocli_revoked",
		`{"title":"Deny egress","statement":"Deny 0.0.0.0/0 egress"}`)
	if wBad.Code != http.StatusUnauthorized {
		t.Fatalf("revoked cli token status = %d, want 401", wBad.Code)
	}
}

func TestLiveUploadGuardVerifiesAgentPinSignature(t *testing.T) {
	db, err := sql.Open("pgx", unreachable)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	pinSha := sha256HexBytes(der)
	now := time.Date(2026, 11, 24, 15, 0, 0, 0, time.UTC)

	g, _, err := newGuard(Config{
		DB:       db,
		Verifier: fakeVerifier{},
		Callers:  callerOf(tenantA),
		LiveUploads: &LiveUploads{
			LookupPin: func(_ context.Context, gotSha string) (verification.AgentPin, SessionStatus) {
				if gotSha != pinSha {
					return verification.AgentPin{}, SessionUnknown
				}
				return verification.AgentPin{
					ID:           uuid.MustParse("01960000-0000-7000-8000-000000000099"),
					Tenant:       tenantA,
					Name:         "prod-agent",
					Repo:         "acme/firewall",
					Env:          "prod",
					PinSHA256:    pinSha,
					PublicKeyDER: der,
				}, SessionFound
			},
		},
		Policy: testPolicy(t),
		Now:    func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}

	var gotAgent verifiedLiveAgent
	var gotBody string
	live := []route{{
		pattern: "POST /v1/verdicts/live",
		op:      "upload_live_verdicts",
		handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			agent, ok := liveAgentOf(r)
			if !ok {
				t.Error("missing verifiedLiveAgent in context")
			}
			gotAgent = agent
			raw, _ := io.ReadAll(r.Body)
			gotBody = string(raw)
			writeJSON(w, http.StatusCreated, map[string]any{"id": uuid.NewString(), "verdicts": 0})
		}),
	}}
	mux, table := mount(routes(db, func() time.Time { return now }, nil, ""), nil, live)
	h := g.serve(mux, table)

	tsHeader := now.Format(time.RFC3339)
	payload := `{"check":"plan","report":{"report_version":3,"ipso_version":"0.1.0","evaluated_at":"2026-11-24T15:00:00Z","env":"prod","live":true,"build_sha256":"` + strings.Repeat("a", 64) + `","plan_sha256":"` + strings.Repeat("b", 64) + `","verdicts":[]}}`
	sig, err := verification.SignLivePayload(priv, tsHeader, []byte(payload))
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/verdicts/live", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Ipso-Agent-Pin", pinSha)
	req.Header.Set("X-Ipso-Timestamp", tsHeader)
	req.Header.Set("X-Ipso-Signature", sig)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("valid live upload status = %d, body = %s", w.Code, w.Body.String())
	}
	if gotAgent.Pin.Repo != "acme/firewall" || gotAgent.Pin.Env != "prod" {
		t.Fatalf("unexpected principal pin = %+v", gotAgent.Pin)
	}
	if gotBody != payload {
		t.Fatalf("handler body mismatch")
	}

	// Tampered body must be rejected 401.
	reqTampered := httptest.NewRequest(http.MethodPost, "/v1/verdicts/live", strings.NewReader(payload+" "))
	reqTampered.Header.Set("Content-Type", "application/json")
	reqTampered.Header.Set("X-Ipso-Agent-Pin", pinSha)
	reqTampered.Header.Set("X-Ipso-Timestamp", tsHeader)
	reqTampered.Header.Set("X-Ipso-Signature", sig)
	wTampered := httptest.NewRecorder()
	h.ServeHTTP(wTampered, reqTampered)
	if wTampered.Code != http.StatusUnauthorized {
		t.Fatalf("tampered live upload status = %d, want 401", wTampered.Code)
	}

	// Stale timestamp (> 5m skew) must be rejected 401.
	staleTS := now.Add(-10 * time.Minute).Format(time.RFC3339)
	staleSig, err := verification.SignLivePayload(priv, staleTS, []byte(payload))
	if err != nil {
		t.Fatal(err)
	}
	reqStale := httptest.NewRequest(http.MethodPost, "/v1/verdicts/live", strings.NewReader(payload))
	reqStale.Header.Set("Content-Type", "application/json")
	reqStale.Header.Set("X-Ipso-Agent-Pin", pinSha)
	reqStale.Header.Set("X-Ipso-Timestamp", staleTS)
	reqStale.Header.Set("X-Ipso-Signature", staleSig)
	wStale := httptest.NewRecorder()
	h.ServeHTTP(wStale, reqStale)
	if wStale.Code != http.StatusUnauthorized {
		t.Fatalf("stale live upload status = %d, want 401", wStale.Code)
	}
}
